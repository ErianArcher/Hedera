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
import json

from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_3

import network_awareness
import network_monitor

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
        "network_monitor": network_monitor.NetworkMonitor}

    WEIGHT_MODEL = {'hop': 'weight', 'bw': 'bw'}

    def __init__(self, *args, **kwargs):
        super(ShortestForwarding, self).__init__(*args, **kwargs)
        self.name = "shortest_forwarding"
        self.awareness = kwargs["network_awareness"]
        self.monitor = kwargs["network_monitor"]
        self.datapaths = {}
        """
        | {dpid: {Multicast address: [{path_dict},],},}|
        """
        self.mcast_paths = {}
        """
        | Multicast address infos {group_addr: hosts_list(No)}
        """
        self.maddr_hosts = self._read_json("maddr_hosts.json")
        """
        | Host ip infos {host No: ip}
        """
        self.host_ip = self._read_json("host_ip.json")
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
                if not is_multicast_addr(dst_ip):
                    self.shortest_forwarding(msg, eth_type, src_ip, dst_ip)
                else:
                    self.shortest_forwarding_mcast(msg, eth_type, src_ip, dst_ip)

    def _read_json(self, json_fname):
        with open(json_fname) as json_file:
            data = json.load(json_file)
        return data

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
        """
        The original strategy can be used to calculate the multicast path from core switch to destination switches.
        Cautions:
        1. The core switches should be the switches that connects to one of the next switches of src_sw by BFS but do not connect to the others.
        2. Find if there is any switch that is the target one in the next switches by BFS of the chosen one of the next switches of src_sw by BFS.
        Main steps
        1. Judge if there is any of destination switches in the same pod of the source switch.
        2. If the set of destination switches in the same pod of the source switch is not empty,
        3. For each partial path, calculate the remaining part from the core switch to destination switches.
        4. Use network_monitor to find the best path with abundant bandwidth.
        :param src: The source switch
        :param mcast_addr: The multicast address
        :param dsts: The destination switches
        :return: List of paths
        """
        self.logger.debug("DEBUG (get_path_mcast): src(%s), mcast_addr(%s), dsts(%s)" % (src, mcast_addr, dsts))
        # k_port = len(self.awareness.switch_port_table.values()[0])

        # Make sure that there is path dict key
        if not self.mcast_paths.has_key(src):
            self.mcast_paths[src] = {}
        if not self.mcast_paths[src].has_key(mcast_addr):
            self.mcast_paths[src][mcast_addr] = []

        if not self.mcast_paths[src][mcast_addr]:
            # Calculate all possible paths
            self.calculate_multicast_paths(src, mcast_addr, dsts)

        # Choose the path with least cost.
        path_dicts = self.mcast_paths[src][mcast_addr]
        if self.weight == self.WEIGHT_MODEL['hop']:
            # TODO: Random select one path.
            best_path_dict = path_dicts[0]
        elif self.weight == self.WEIGHT_MODEL['bw']:
            # Because all paths will be calculated when we call self.monitor.get_best_path_by_bw,
            # so we just need to call it once in a period, and then, we can get path directly.
            # If path is existed just return it, else calculate and return it.
            try:
                best_path_dict = self.monitor.best_mcast_paths.get(src).get(mcast_addr)
            except:
                result = self.monitor.get_best_mcast_path_by_bw(self.awareness.graph, self.mcast_paths)
                # result = (capabilities, best_mcast_path_dicts)
                path_dicts = result[1]
                best_path_dict = path_dicts.get(src).get(mcast_addr)
        else:
            empty_dict = {src: []}
            best_path_dict = empty_dict
        self.logger.debug("Multicast path for %s: %s, the best is: %s",
                         mcast_addr, self.mcast_paths[src][mcast_addr], best_path_dict)
        return best_path_dict

    def calculate_multicast_paths(self, src, mcast_addr, dsts):
        # Prune the path cannot reach `dsts`
        def dfs(path_dict, cur, dsts_dfs):
            cur_sw_list = path_dict.get(cur, [])
            if not cur_sw_list:
                # This means that the switch is the end of the path
                if cur not in dsts_dfs:
                    return False
                else:
                    return True
            else:
                item_to_remove = []
                for next_sw in cur_sw_list:
                    good_path = dfs(path_dict, next_sw, dsts_dfs)
                    if not good_path:
                        item_to_remove.append(next_sw)
                # Remove the item needed to be removed
                for item in item_to_remove:
                    path_dict.get(cur).remove(item)
                if not path_dict.get(cur, []):
                    # Bug fixed
                    path_dict.pop(cur)
                    # Bug fixed: When the destination is the leaf node, it cannot recognize the path.
                    if cur in dsts_dfs:
                        return True
                    else:
                        return False
                else:
                    return True

        # Get all possible paths
        aggr_sws = self.awareness.neighbors(src)
        # Locate all the core switches
        self.awareness.register_core_switch(src)

        self.logger.debug("Aggregate switches: %s", aggr_sws)
        for aggr_sw in aggr_sws:
            # New paths
            core_sws = []
            intrapod_dst_sws = []
            next_sws = self.awareness.neighbors(aggr_sw, exclusive=src)
            for next_sw in next_sws:
                if next_sw in dsts:
                    # Should be added to the path.
                    intrapod_dst_sws.append(next_sw)
                elif self.awareness.is_core_switch(next_sw, aggr_sw, aggr_sws):
                    # Should be added to th                                                                                                      e path.
                    core_sws.append(next_sw)
                else:
                    # Should be the intra-pod switch but not destination.
                    pass
            # Begin to calculate paths
            self.logger.debug("Core switches: %s", core_sws)
            for core_sw in core_sws:
                half = self.awareness.bfs_tree(core_sw, exclusive_neighbor=aggr_sw, wo_core_switch=True)
                self.logger.debug("[Debug] BFS tree of (%s): %s", core_sw, half)
                dfs(half, core_sw, dsts)
                self.logger.debug("[Debug] BFS tree after dfs of (%s): %s", core_sw, half)
                # Merge the first half to the path dict
                half[src] = [aggr_sw]
                aggr_sw_path_dict = [core_sw]
                aggr_sw_path_dict.extend(intrapod_dst_sws)
                half[aggr_sw] = aggr_sw_path_dict
                self.mcast_paths[src][mcast_addr].append(half)

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

        def dfs_path_dict(last_dpid, cur_dpid):
            """
            Function for installing flow on the switches in the path.
            :param last_dpid: The data path's id for the last switch
            :param cur_dpid: The data path's id for the current switch
            """
            if path_dict.has_key(cur_dpid):
                next_dpid_list = path_dict.get(cur_dpid)
                port_pair = self.get_port_pair_from_link(link_to_port, last_dpid, cur_dpid)
                port_pairs_next = [self.get_port_pair_from_link(link_to_port, cur_dpid, next_dpid_tmp) for next_dpid_tmp
                                   in next_dpid_list]
                src_port = port_pair[1]
                ports = [_pair[0] for _pair in port_pairs_next]
                if src_port and ports:
                    # Bug fixed: leak the case of single port to forward
                    datapath = datapaths[cur_dpid]
                    self._install_port_list(datapath, flow_info, src_port, ports)
                for next_dpid in next_dpid_list:
                    dfs_path_dict(cur_dpid, next_dpid)

        # For edge switch
        mcast_ip = flow_info[2]
        host_ips = self._maddr2host_ips(mcast_ip)
        dpid_port_to_hosts = [self.awareness.get_host_location(host_ip) for host_ip in host_ips]
        dpid2port_dict = {}
        for dpid_port in dpid_port_to_hosts:
            dpid2port_dict.setdefault(dpid_port[0], [])
            dpid2port_dict[dpid_port[0]].append(dpid_port[1])
        # Find the in port for each edge dpid
        edge_dpid2in_port = {}
        edge_dpids = dpid2port_dict.keys()
        for dpid, next_dpid_list in path_dict.iteritems():
            for next_dpid in next_dpid_list:
                if next_dpid in edge_dpids:
                    src_port = self.get_port_pair_from_link(self.awareness.link_to_port, dpid, next_dpid)[1]
                    edge_dpid2in_port[next_dpid] = src_port
        # Origin
        in_port = flow_info[3]
        first_dp = datapaths[src_sw]

        # install flow for the src_sw
        first_port_pairs_next = []
        for next_dpid in path_dict.get(src_sw):
            dfs_path_dict(src_sw, next_dpid)
            first_port_pairs_next.append(self.get_port_pair_from_link(link_to_port, src_sw, next_dpid))

        # Bug fixed: leak the case of single port to forward
        # Bug fixed: Same dst cannot have two different flow action.
        first_ports = [pair[0] for pair in first_port_pairs_next]
        if in_port and first_ports:
            ports = dpid2port_dict.get(src_sw, []) # Get or else empty list (!flag1)
            ports.extend(first_ports)
            self._install_port_list(first_dp, flow_info, in_port, ports)

        # Flow rules for edge switch
        for dpid, ports in dpid2port_dict.iteritems():
            self.logger.debug(
                "DEBUG: dpid2port_dict(%s), edge_dpid2in_port(%s)" % (dpid2port_dict, edge_dpid2in_port))
            # Case of neighbors
            if dpid == src_sw:
                # Bug fixed: When the host ip is not the neighbor of sender,
                # the flow table of src_sw cannot be installed
                # Solution: Move code to (flag1)
                pass
            else:
                self._install_port_list(self.datapaths[dpid], flow_info, edge_dpid2in_port[dpid], ports)

    def _install_port_list(self, datapath, flow_info, in_port, out_ports):
        self.logger.debug("[Debug] Data path(%s) is installed: out ports(%s)", datapath, out_ports)
        if len(out_ports) > 1:
            group_id = self._to_group_id(out_ports)
            self.send_flow_mod(datapath, flow_info, in_port, group_id, isGroupId=True)
        else:
            out_port = out_ports[0]
            self.send_flow_mod(datapath, flow_info, in_port, out_port)

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

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port, isGroupId=False):
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
                    self.logger.debug("[PATH]%s<-->%s(%s Port:%d): %s" % (ip_src, ip_dst, L4_Proto, L4_port, path))
                    flow_info = (eth_type, ip_src, ip_dst, in_port, ip_proto, Flag, L4_port)
                else:
                    self.logger.debug("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                    flow_info = (eth_type, ip_src, ip_dst, in_port)
                # Install flow entries to datapaths along the path.
                self.install_flow(self.datapaths,
                                  self.awareness.link_to_port,
                                  path, flow_info, msg.buffer_id, msg.data)
        else:
            # Flood is not good.
            self.flood(msg)

    def _to_group_id(self, ports_to_forward):
        reversed_ordered_port_list = sorted(ports_to_forward, reverse=True)
        sum = 0
        for i in range(0, len(reversed_ordered_port_list)):
            sum += reversed_ordered_port_list[i] * (10 ** i)
        return sum

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
        host_ips = self._maddr2host_ips(mcast_ip)
        results = [self.get_sw(datapath.id, in_port, ip_src, host_ip) for host_ip in host_ips]

        if results:
            """
            self.logger.info("DEBUG: nodes(%s) edges(%s)" %
                             (self.awareness.graph.nodes(), self.awareness.graph.edges()))
            self.logger.info("DEBUG: link_to_port(%s) access_ports(%s)" %
                             (self.awareness.link_to_port, self.awareness.access_ports))
            """
            self.logger.debug("DEBUG: results(%s)" % results)
            dsts = [result[1] for result in results]
            src = results[0][0]
            path_dict = self.get_path_mcast(src, mcast_ip, dsts)
            self.logger.debug("DEBUG: path_dict(%s)" % path_dict)

            if ip_proto and L4_port and Flag:
                if ip_proto == 6:
                    L4_Proto = 'TCP'
                elif ip_proto == 17:
                    L4_Proto = 'UDP'
                else:
                    pass
                self.logger.debug("[PATH]%s<-->%s(%s Port:%d): %s" % (ip_src, mcast_ip, L4_Proto, L4_port, path_dict))
                flow_info = (eth_type, ip_src, mcast_ip, in_port, ip_proto, Flag, L4_port)
            else:
                self.logger.debug("[PATH]%s<-->%s: %s" % (ip_src, mcast_ip, path_dict))
                flow_info = (eth_type, ip_src, mcast_ip, in_port)
            self.install_mcast_flows(self.datapaths, self.awareness.link_to_port, path_dict, src, flow_info)
        else:
            self.flood(msg)

    def _maddr2host_ips(self, mcast_addr):
        dst_ips = []
        # self.logger.info("DEBUG: maddr2host_ips (%s)" % mcast_addr)
        for hostNo in self.maddr_hosts.get(mcast_addr, []):
            if self.host_ip.has_key(hostNo):
                dst_ips.append(self.host_ip[hostNo])
        # self.logger.info("DEBUG: maddr2host_ips dsts(%s)" % dst_ips)
        # self.logger.info("DEBUG: maddr2host_ips host_ip(%s)" % self.host_ip)
        # self.logger.info("DEBUG: maddr2host_ips hosts(%s)" % self.maddr_hosts.get(mcast_addr, []))
        return dst_ips


def is_multicast_addr(ip_addr):
    ip2Int = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
    return (ip2Int(ip_addr) & 0xF0000000) == 0xE0000000
