# Copyright (C) 2016 Huang MaChi at Chongqing University
# of Posts and Telecommunications, Chongqing, China.
# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.ofp_event import EventOFPStateChange
from ryu.lib.dpid import str_to_dpid
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import igmplib

import network_awareness
import network_monitor
import setting

CONF = cfg.CONF


class ShortestForwarding(app_manager.RyuApp):
    """
        ShortestForwarding is a Ryu app for forwarding packets on shortest path.
        This App does not defined the path computation method.
        To get shortest path, this module depends on network awareness,
        network monitor and network delay detecttor modules.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "network_awareness": network_awareness.NetworkAwareness,
        "network_monitor": network_monitor.NetworkMonitor,
        "igmplib": igmplib.IgmpLib}

    WEIGHT_MODEL = {'hop': 'weight', 'bw': 'bw'}

    def __init__(self, *args, **kwargs):
        super(ShortestForwarding, self).__init__(*args, **kwargs)
        self.name = "shortest_forwarding"
        self.awareness = kwargs["network_awareness"]
        self.monitor = kwargs["network_monitor"]
        self._snoop = kwargs["igmplib"]
        self._snoop.set_querier_mode(dpid=str_to_dpid('0000000000000001'), server_port=2)
        self.datapaths = {}
        """
        | Multicast address: {path_dict}|
        """
        self.mcast_paths = {}
        self.weight = self.WEIGHT_MODEL[CONF.weight]

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _ofp_state_change_handler(self, ev):
        """
            Collect datapath information.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            In packet_in handler, we need to learn access_table by ARP and IP packets.
        '''
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            if len(pkt.get_protocols(ethernet.ethernet)):
                eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                if not self._isMCastAddr(dst_ip):
                    self.shortest_forwarding(msg, eth_type, src_ip, dst_ip)
                else:
                    self.shortest_forwarding_mcast(msg, eth_type, src_ip, dst_ip)

    def add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
            Send a flow entry to datapath.
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port of dst host.
            access_table = {(sw,port):(ip, mac),}
        """
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:  # Use the IP address only, not the MAC address. (hmc)
                        dst_port = key[1]
                        return dst_port
        return None

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
            link_to_port = {(src_dpid,dst_dpid):(src_port,dst_port),}
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("Link from dpid:%s to dpid:%s is not in links" %
                             (src_dpid, dst_dpid))
            return None

    def flood(self, msg):
        """
            Flood packet to the access ports which have no record of host.
            access_ports = {dpid:set(port_num,),}
            access_table = {(sw,port):(ip, mac),}
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto

        for dpid in self.awareness.access_ports:
            for port in self.awareness.access_ports[dpid]:
                if (dpid, port) not in self.awareness.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug("Flooding packet to access port")

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """
            Send ARP packet to the destination host if the dst host record
            is existed, else flow it to the unknow access port.
            result = (datapath, port)
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto

        result = self.awareness.get_host_location(dst_ip)
        if result:
            # Host has been recorded in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Deliver ARP packet to knew host")
        else:
            # Flood is not good.
            self.flood(msg)

    def get_path(self, src, dst, weight):
        """
            Get shortest path from network_awareness module.
            generator (nx.shortest_simple_paths( )) produces
            lists of simple paths, in order from shortest to longest.
        """
        shortest_paths = self.awareness.shortest_paths
        # Create bandwidth-sensitive datapath graph.
        graph = self.awareness.graph

        if weight == self.WEIGHT_MODEL['hop']:
            return shortest_paths.get(src).get(dst)[0]
        elif weight == self.WEIGHT_MODEL['bw']:
            # Because all paths will be calculated when we call self.monitor.get_best_path_by_bw,
            # so we just need to call it once in a period, and then, we can get path directly.
            # If path is existed just return it, else calculate and return it.
            try:
                path = self.monitor.best_paths.get(src).get(dst)
                return path
            except:
                result = self.monitor.get_best_path_by_bw(graph, shortest_paths)
                # result = (capabilities, best_paths)
                paths = result[1]
                best_path = paths.get(src).get(dst)
                return best_path
        else:
            pass

    def get_path_mcast(self, src, mcast_addr, dsts):
        # Prune the path cannot reach `dsts`
        def dfs(path_dict, cur, dsts):
            cur_sw_list = path_dict.get(cur)
            if not cur_sw_list:
                if not dsts.contains(cur):
                    return False
                else:
                    return True
            else:
                for next_sw in cur_sw_list:
                    good_path = dfs(path_dict, next_sw, dsts)
                    if not good_path:
                        path_dict.get(cur).remove(next_sw)
                if not path_dict.get(cur):
                    return False
                else:
                    return True
        if not self.mcast_paths.has_key(mcast_addr):
            bfs_dict = self.awareness.get_bfs_successor(src)
            dfs(bfs_dict, src, dsts)
            self.mcast_paths[mcast_addr] = bfs_dict
        else:
            bfs_dict = self.mcast_paths.get(mcast_addr)
        return bfs_dict

    def install_mcast_flows(self, datapaths, link_to_port, path_dict, src_sw, flow_info):
        """
            Install flow entries for datapaths.
            path=[dpid1, dpid2, ...]
            flow_info = (eth_type, src_ip, mcast_ip, in_port)
            or
            flow_info = (eth_type, src_ip, mcast_ip, in_port, ip_proto, Flag, L4_port)
        """
        # Generate flow rules for each switches on the path
        if not path_dict:
            self.logger.info("Path error!")
            return
        in_port = flow_info[3]
        first_dp = datapaths[src_sw]
        def dfs_path_dict(last_dpid, cur_dpid):
            next_dpid_list = path_dict.get(cur_dpid)
            port_pair = self.get_port_pair_from_link(link_to_port, last_dpid, cur_dpid)
            port_pairs_next = [self.get_port_pair_from_link(link_to_port, cur_dpid, next_dpid) for next_dpid in
                          next_dpid_list]
            src_port = port_pair[1]
            ports = [pair[0] for pair in port_pairs_next]
            if src_port and ports:
                group_id = int("".join(sorted(ports)))
                datapath = datapaths[cur_dpid]
                self.send_flow_mod(datapath, flow_info, src_port, group_id, isGroupId=True)
            for next_dpid in next_dpid_list:
                dfs_path_dict(cur_dpid, next_dpid)

        # install flow for the src_sw
        first_port_pairs_next = []
        for next_dpid in path_dict.get(src_sw):
            dfs_path_dict(src_sw, next_dpid)
            first_port_pairs_next.append(self.get_port_pair_from_link(link_to_port, src_sw, next_dpid))

        first_ports = [first_port_pairs_next[0] for pair in first_port_pairs_next]
        if in_port and first_ports:
            group_id = int("".join(sorted(first_ports)))
            self.send_flow_mod(first_dp, flow_info, in_port, group_id, isGroupId=True)


    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None
        src_location = self.awareness.get_host_location(src)  # src_location = (dpid, port)
        if in_port in self.awareness.access_ports[dpid]:
            if (dpid, in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None
        dst_location = self.awareness.get_host_location(dst)  # dst_location = (dpid, port)
        if dst_location:
            dst_sw = dst_location[0]
        if src_sw and dst_sw:
            return src_sw, dst_sw
        else:
            return None

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port, isGroupId = False):
        """
            Build flow entry, and send it to datapath.
            flow_info = (eth_type, src_ip, dst_ip, in_port)
            or
            flow_info = (eth_type, src_ip, dst_ip, in_port, ip_proto, Flag, L4_port)
        """
        parser = datapath.ofproto_parser
        actions = []
        if not isGroupId:
            actions.append(parser.OFPActionOutput(dst_port))
        else:
            actions.append(parser.OFPActionGroup(dst_port))
        if len(flow_info) == 7:
            if flow_info[-3] == 6:
                if flow_info[-2] == 'src':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=6, tcp_src=flow_info[-1])
                elif flow_info[-2] == 'dst':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=6, tcp_dst=flow_info[-1])
                else:
                    pass
            elif flow_info[-3] == 17:
                if flow_info[-2] == 'src':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=17, udp_src=flow_info[-1])
                elif flow_info[-2] == 'dst':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=17, udp_dst=flow_info[-1])
                else:
                    pass
        elif len(flow_info) == 4:
            match = parser.OFPMatch(
                in_port=src_port, eth_type=flow_info[0],
                ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
        else:
            pass

        self.add_flow(datapath, 30, match, actions,
                      idle_timeout=5, hard_timeout=10)

    def install_flow(self, datapaths, link_to_port, path, flow_info, buffer_id, data=None):
        '''
            Install flow entries for datapaths.
            path=[dpid1, dpid2, ...]
            flow_info = (eth_type, src_ip, dst_ip, in_port)
            or
            flow_info = (eth_type, src_ip, dst_ip, in_port, ip_proto, Flag, L4_port)
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        # Install flow entry for intermediate datapaths.
        for i in xrange(1, int((len(path) - 1) / 2)):
            port = self.get_port_pair_from_link(link_to_port, path[i - 1], path[i])
            port_next = self.get_port_pair_from_link(link_to_port, path[i], path[i + 1])
            if port and port_next:
                src_port, dst_port = port[1], port_next[0]
                datapath = datapaths[path[i]]
                self.send_flow_mod(datapath, flow_info, src_port, dst_port)

        #  Install flow entry for the first datapath.
        port_pair = self.get_port_pair_from_link(link_to_port, path[0], path[1])
        if port_pair is None:
            self.logger.info("Port not found in first hop.")
            return
        out_port = port_pair[0]
        self.send_flow_mod(first_dp, flow_info, in_port, out_port)

    def get_L4_info(self, tcp_pkt, udp_pkt, ip_proto, L4_port, Flag):
        """
            Get ip_proto and L4 port number.
        """
        if tcp_pkt:
            ip_proto = 6
            if tcp_pkt.src_port:
                L4_port = tcp_pkt.src_port
                Flag = 'src'
            elif tcp_pkt.dst_port:
                L4_port = tcp_pkt.dst_port
                Flag = 'dst'
            else:
                pass
        elif udp_pkt:
            ip_proto = 17
            if udp_pkt.src_port:
                L4_port = udp_pkt.src_port
                Flag = 'src'
            elif udp_pkt.dst_port:
                L4_port = udp_pkt.dst_port
                Flag = 'dst'
            else:
                pass
        else:
            pass
        return (ip_proto, L4_port, Flag)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            Calculate shortest forwarding path and Install them into datapaths.
            flow_info = (eth_type, src_ip, dst_ip, in_port)
            or
            flow_info = (eth_type, ip_src, ip_dst, in_port, ip_proto, Flag, L4_port)
        """
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        ip_proto = None
        L4_port = None
        Flag = None
        # Get ip_proto and L4 port number.
        ip_proto, L4_port, Flag = self.get_L4_info(tcp_pkt, udp_pkt, ip_proto, L4_port, Flag)
        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)  # result = (src_sw, dst_sw)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                # Path has already been calculated, just get it.
                path = self.get_path(src_sw, dst_sw, weight=self.weight)
                if ip_proto and L4_port and Flag:
                    if ip_proto == 6:
                        L4_Proto = 'TCP'
                    elif ip_proto == 17:
                        L4_Proto = 'UDP'
                    else:
                        pass
                    self.logger.info("[PATH]%s<-->%s(%s Port:%d): %s" % (ip_src, ip_dst, L4_Proto, L4_port, path))
                    flow_info = (eth_type, ip_src, ip_dst, in_port, ip_proto, Flag, L4_port)
                else:
                    self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                    flow_info = (eth_type, ip_src, ip_dst, in_port)
                # Install flow entries to datapaths along the path.
                self.install_flow(self.datapaths,
                                  self.awareness.link_to_port,
                                  path, flow_info, msg.buffer_id, msg.data)
        else:
            # Flood is not good.
            self.flood(msg)

    def _isMCastAddr(self, ip_addr):
        ip2Int = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
        return (ip2Int(ip_addr) & 0xF0000000) == 0xE0000000

    def shortest_forwarding_mcast(self, msg, eth_type, ip_src, mcast_ip):
        """
             Calculate shortest forwarding path and Install them into datapaths.
             flow_info = (eth_type, src_ip, dst_ip, in_port)
             or
             flow_info = (eth_type, ip_src, ip_dst, in_port, ip_proto, Flag, L4_port)
        """
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        ip_proto = None
        L4_port = None
        Flag = None
        # Get ip_proto and L4 port number.
        ip_proto, L4_port, Flag = self.get_L4_info(tcp_pkt, udp_pkt, ip_proto, L4_port, Flag)
        host_ips = self._mcastAddr2HostIPs(mcast_ip)
        results = [self.get_sw(datapath.id, in_port, ip_src, host_ip) for host_ip in host_ips]

        if results:
            dsts = [result[1] for result in results]
            src = results[0][0]
            path_dict = self.get_path_mcast(src, mcast_ip, dsts)
            dpid_port_to_hosts = [self.awareness.get_host_location(host_ip) for host_ip in host_ips]
            dpid2port_dict = {}
            for dpid_port in dpid_port_to_hosts:
                dpid2port_dict.setdefault(dpid_port[0], [])
                dpid2port_dict[dpid_port[0]].append(dpid_port[1])
            # Find the in port for each edge dpid
            edge_dpid2in_port = {}
            edge_dpids = dpid2port_dict.keys()
            for (dpid, next_dpid_list) in path_dict:
                for next_dpid in next_dpid_list:
                    if next_dpid in edge_dpids:
                        src_port = self.get_port_pair_from_link(self.awareness.link_to_port, dpid, next_dpid)[1]
                        edge_dpid2in_port[next_dpid] = src_port

            if ip_proto and L4_port and Flag:
                if ip_proto == 6:
                    L4_Proto = 'TCP'
                elif ip_proto == 17:
                    L4_Proto = 'UDP'
                else:
                    pass
                self.logger.info("[PATH]%s<-->%s(%s Port:%d): %s" % (ip_src, mcast_ip, L4_Proto, L4_port, path_dict))
                flow_info = (eth_type, ip_src, mcast_ip, in_port, ip_proto, Flag, L4_port)
            else:
                self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, mcast_ip, path_dict))
                flow_info = (eth_type, ip_src, mcast_ip, in_port)
            self.install_mcast_flows(self.datapaths, self.awareness.link_to_port, path_dict, src, flow_info)
            # Flow rules for edge switch
            for (dpid, ports) in dpid2port_dict:
                if len(ports) > 1:
                    group_id = "".join(sorted(ports))
                    self.send_flow_mod(self.datapaths[dpid], flow_info, edge_dpid2in_port[dpid],
                                       int(group_id), isGroupId=True)
                else:
                    out_port = ports[0]
                    self.send_flow_mod(self.datapaths[dpid], flow_info, edge_dpid2in_port[dpid], out_port)
        else:
            self.flood(msg)

    def _mcastAddr2HostIPs(self, mcast_addr):
        dst_ips = []
        return dst_ips
