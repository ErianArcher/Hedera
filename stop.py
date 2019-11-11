from subprocess import Popen, PIPE, call
import argparse
import os
import logging

stopper_parser = argparse.ArgumentParser("Lab stopper")
stopper_parser.add_argument('--hostnum', dest='hostnum', type=int, required=True,
                            help='The amount of hosts')

stopper_args = stopper_parser.parse_args()
scheduler_container_name = "scheduler"
akka_log_fname = "akka_log.log"

def get_host_container_name(hostNO):
    prefix = "mininet-"
    if hostNO < 10:
        return prefix+"h00"+str(hostNO)
    elif hostNO < 100:
        return prefix+"h0"+str(hostNO)
    else:
        return prefix + "h" + str(hostNO)

def stop_scala_program(container_name):
    # Fetch the pid of scala programs
    p = Popen(["docker exec -it " + container_name + " ps -ef | grep 'scala\|java' | awk '{print $2}'"], shell=True, stdout=PIPE)
    out, err = p.communicate()
    for line in out.splitlines():
        call(["docker exec -it " + container_name + " kill -9 " + line], shell=True)
    psef = call(["docker exec -it " + container_name + " ps -ef"], shell=True)

def cp_log(container_name):
    log_folder = "logs"
    log_file_name_in_local = container_name + "_log.log"
    call(["docker cp " + container_name + ":/" + akka_log_fname + " " +
          os.path.join(log_folder,log_file_name_in_local)], shell=True)

if __name__ == '__main__':
    if os.getuid() != 0:
        logging.debug("You are NOT root")
    elif os.getuid() == 0:
        hostNum = stopper_args.hostnum

        for hostNO in range(1, hostNum+1):
            host_container_name = get_host_container_name(hostNO)
            stop_scala_program(host_container_name)
            cp_log(host_container_name)
        stop_scala_program(scheduler_container_name)
        cp_log(scheduler_container_name)