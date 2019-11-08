import logging
from subprocess import Popen, PIPE, STDOUT, call
import os
import argparse

parser = argparse.ArgumentParser("Lab starter")
parser.add_argument('--hostnum', dest='hostnum', type=int, required=True,
                    help='The amount of hosts')
parser.add_argument('-P', '--lab_program', dest='addition_filename', required=True,
                    help='The name of lab program')
args = parser.parse_args()

scheduler_container_name = "scheduler"
image = 'ubuntu-exp'
startString = "/bin/bash"
dargs = "-di"
docker_bridge = "control-net"


def get_host_container_name(hostNO):
    prefix = "mininet-"
    if hostNO < 10:
        return prefix+"h00"+str(hostNO)
    elif hostNO < 100:
        return prefix+"h0"+str(hostNO)
    else:
        return prefix + "h" + str(hostNO)


def copy_required_files(container_name, addition_file=None):
    files = ['maddr_hosts.json', 'host_ip.json', 'lab_config.json']
    copy_cmd = ['docker', 'cp', 'filename', container_name + ':/']
    if addition_file:
        files.append(addition_file)
    for file_name in files:
        copy_cmd[2] = file_name
        print copy_cmd
        pidp = Popen(copy_cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=False)


def run_lab_program(container_name, lab_program, *args):
    run_cmd = ["docker exec -dt " + container_name + " scala -J-Xmx3072m -J-Xms1536m /" + lab_program + " " + " ".join(args)]
    print run_cmd
    pidp = call(run_cmd, shell=True)
    psef = call(["docker exec -it " + container_name + " ps -ef"], shell=True)


if __name__ == '__main__':
    if os.getuid() != 0:
        logging.debug("You are NOT root")
    elif os.getuid() == 0:
        hostNum = args.hostnum
        lab_program = args.addition_filename

        # Remove any old host still running
        call(["docker stop " + scheduler_container_name], shell=True)
        call(["docker rm " + scheduler_container_name], shell=True)
        # Start a scheduler that connect to other hosts via docker bridge
        cmd = ["docker", "run", "--privileged", "-h", scheduler_container_name, "--name=" + scheduler_container_name]
        cmd.extend([dargs])
        cmd.extend(["--network=%s" % docker_bridge, image, startString])
        # print cmd
        pidp = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=False)

        for hostNO in range(1, hostNum+1):
            host_container_name = get_host_container_name(hostNO)
            copy_required_files(host_container_name, addition_file=lab_program)
        # Copy files to the scheduler
        copy_required_files(scheduler_container_name, addition_file=lab_program)

        # Start the lab program
        run_lab_program(scheduler_container_name, lab_program, 'controller')
        for hostNO in range(1, hostNum+1):
            host_container_name = get_host_container_name(hostNO)
            run_lab_program(host_container_name, lab_program, 'host', str(hostNO))
