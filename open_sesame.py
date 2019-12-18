#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys
import re

from requests import get
from subprocess import call, Popen, PIPE

mypath = None
myname = None
node_types_external = ["management", "eloader", "grafana"]
node_types_internal = ["storage-node", "replication-agent"]
node_types = node_types_external + node_types_internal
logger = None


def init_log(log_file='result.log', console_log_level=logging.INFO,
             file_log_level=logging.DEBUG):

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Global debug level

    # Console logging settings
    console_log_fmt = logging.Formatter(
        "%(asctime)s %(levelname)s: %(message)s",
        datefmt="%Y/%m/%d %H:%M:%S")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_log_level)
    console_handler.setFormatter(console_log_fmt)
    logger.addHandler(console_handler)

    # File logging settings
    file_log_fmt = logging.Formatter(
        "%(asctime)s [%(filename)s/%(funcName)s] %(levelname)s: %(message)s",
        datefmt='%Y/%m/%d %H:%M:%S')
    file_handler = logging.FileHandler(log_file, mode='w')  # Overwrite the file
    file_handler.setLevel(file_log_level)
    file_handler.setFormatter(file_log_fmt)
    logger.addHandler(file_handler)

    logger.info('Log initialized - logging to %s', log_file)

    return logger


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Allow Tesla to connect to the specified cluster")
    parser.add_argument(dest='cluster_id',
                        help="Cluster id, i.e. PROJECT_ID for single-cluster "
                             "projects or PROJECT_ID:LABEL for multi-cluster "
                             "projects")
    args, unhandled_args = parser.parse_known_args()
    return args, unhandled_args


# gcloud compute --project elastifile-gce-lab-c934 instances list
# --filter=labels=5ee6b527 --format json
def get_instances_by_label(project_id: str, cluster_label: str = None) -> list:
    cmd = ["gcloud", "compute"]
    cmd.extend(["--project", project_id])
    cmd.extend(["instances", "list"])
    if cluster_label:
        cmd.append("--filter=labels={}".format(cluster_label))
    cmd.append("--format=json")

    stdout = None
    stderr = None
    try:
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
    except Exception as ex:
        logger.error("Command failed: {}".format(ex))
        exit(1)

    if stderr:
        logger.warning("stderr: {}".format(stderr))

    instances = json.loads(stdout)
    if len(instances) == 0:
        logger.error("There are no instances in project {} label {} to "
                     "connect to".format(project_id, cluster_label))
        exit(1)

    hashes = cluster_hashes(instances)

    if not hashes:
        logger.error("There are instances in project {}, but label {} "
                     "is not found. Possible labels: {}".format(
                        project_id, cluster_label, hashes))
        exit(1)

    if len(hashes) > 1:
        # TODO: Nice to have - only return instances with one label if only one
        #  has the requested node_type and node_id
        logger.error("There's more than one cluster hash available in "
                     "project {}. Please specify the one you're interested in. "
                     "Available labels: {}".format(project_id, hashes))
        exit(1)

    return instances


def cluster_hashes(instances: list) -> list:
    hashes = dict()
    for inst in instances:
        try:
            cluster_hash = inst["labels"]["cluster-hash"]
            hashes[cluster_hash] = 1
        except KeyError:
            logger.warning("Ignoring instance {}".format(inst["name"]))
            continue
    return [uniq_hash for uniq_hash in hashes.keys()]


def get_cluster(project_id: str, cluster_label: str) -> dict:
    instances = get_instances_by_label(project_id, cluster_label)
    cluster = dict()
    for node_type in node_types:
        cluster[node_type] = list()

    for inst in instances:
        if "ecfs-instance-type" in inst["labels"]:
            cluster[inst["labels"]["ecfs-instance-type"]].append(inst)
        elif "grafana" in inst["tags"]["items"]:
            cluster["grafana"].append(inst)
        elif "eloader" in inst["tags"]["items"]:
            cluster["eloader"].append(inst)
        else:
            logger.warning("Failed to detect instance type for {}".format(
                inst["name"]))
    logger.debug("Detected instances: {}".format(cluster))
    return cluster


def get_instance_zone(inst: dict) -> str:
    zone = inst["zone"].split("/")[-1]
    logger.debug("Instance {} zone: {}".format(inst["name"], zone))
    return zone


def get_instance_networks(inst: dict) -> list:
    networks = [interface["network"].split("/")[-1] for
                interface in inst["networkInterfaces"]]
    logger.debug("Instance {} networks: {}".format(inst["name"], networks))
    return networks


def get_public_address() -> str:
    address = get("https://api.ipify.org").text
    logger.debug("Detected public IP address {}".format(address))
    return address


# gcloud compute firewall-rules create --network=NETWORK default-allow-ssh
# --allow=tcp:22
def gcloud_configure_firewall(project_id: str, inst: dict, prefix: str = "ssh"):

    tesla_ports = {
        "ssh": "tcp:22",
        "debugger": "tcp:2345",
        "docker": "tcp:2375",
        "web": "tcp:80,tcp:443",
        "grafana": "tcp:3000,tcp:9090",
        "dns": "tcp:53",
        "icmp": "icmp",
    }

    address = get_public_address()
    if not address:
        raise Exception("Failed to detect public address")

    networks = get_instance_networks(inst)
    network = networks.pop()

    address_adapted = re.sub(r'\.', r'-', address)
    name = "{}-{}-{}".format(prefix, address_adapted, network)

    allow = ""
    for rule in tesla_ports.values():
        if allow:
            allow += ","
        allow += rule
    allow = "--allow=" + allow

    cmd = ["gcloud", "compute", "firewall-rules", "create",
           "--project", project_id, "--network", network,
           name, allow, "--source-ranges={}/32".format(address)]

    logger.info("Running command: {}".format(" ".join(cmd)))
    process = Popen(cmd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    if process.returncode:
        if b"exists" in stderr:
            logger.info("Firewall rule {} already exists".format(name))
        else:
            logger.warning("Failed to create firewall rule. SSH might hang.")
            logger.warning("return code: {}. stderr: {}".format(
                process.returncode, stderr))


# gcloud compute ssh --project elastifile-gce-lab-c934 --zone us-east1-a
# centos@c-5ee6b527-eloader-1
def gcloud_connect_to_instance(project_id: str, user: str, inst: dict,
                               remote_cmd: list, jump_host_inst: dict = None):
    zone = get_instance_zone(inst)

    cmd = ["gcloud", "compute", "ssh"]
    cmd.extend(["--project", project_id])
    cmd.extend(["--zone", zone])
    if jump_host_inst:
        cmd.extend(["{}@{}".format(user, jump_host_inst["name"])])
    else:
        cmd.extend(["{}@{}".format(user, inst["name"])])
    cmd.extend(["--", "-t"])
    if jump_host_inst:
        cmd.append("sudo ssh -o StrictHostKeyChecking=no {}".format(
            inst["name"]))
    if remote_cmd:
        cmd.extend(remote_cmd)

    logger.info("Running command: {}".format(" ".join(cmd)))
    call(cmd)


def expand_project_template(project_id: str, match=r'^(\d{3})$',
                            template=r'elastifile-gce-lab-c\1') -> str:
    project_id = re.sub(match, template, project_id)
    return project_id


def alphanumeric_sort_list_of_dict_by_key(nodes: list, key: str) -> list:
    convert = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda node: [convert(c) for c
                                 in re.split('([0-9]+)', node[key])]
    return sorted(nodes, key=alphanum_key)


def process_user_request():
    global logger

    # Handle command line parameters
    args, command = parse_arguments()

    cluster_id = args.cluster_id
    log_name = os.path.splitext(myname)[0] + '.log'
    console_log_level = logging.INFO
    logger = init_log(os.path.join(mypath, log_name), console_log_level)

    project_id = cluster_id
    cluster_label = None
    if ":" in cluster_id:
        project_id, cluster_label = cluster_id.split(":")
    project_id = expand_project_template(project_id)

    # Fetch cluster data
    cluster = get_cluster(project_id, cluster_label)

    # Get the first instance with an external address
    instance = None
    node_type = node_types_external[0]
    try:
        instance = cluster[node_type][0]
    except KeyError:
        logger.error("Node type {} not found in cluster. Found values: {}".
                     format(node_type, [n for n in cluster]))
        exit(1)
    except IndexError:
        logger.error("No {} nodes found".format(node_type))
        exit(1)

    # Configure the firewall
    gcloud_configure_firewall(project_id, instance, "tesla-client")


if __name__ == '__main__':
    mypath = os.path.dirname(sys.argv[0])
    myname = os.path.basename(sys.argv[0])
    process_user_request()
