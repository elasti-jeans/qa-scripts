#!/usr/bin/env python

import os
import sys
import ssh
import time
import json
import random
import string
import logging
import argparse
import subprocess

from subprocess import call

mypath = os.path.dirname(sys.argv[0])
myname = os.path.basename(sys.argv[0])
cache_dir = "/tmp/ssh2cache"

ssh_script = os.path.join(mypath, 'ssh.py')
remote_identity_file = None
node_types = ['emanage', 'vheads', 'replication_agents', 'loaders']


def init_log(log_file='result.log', debug_level=logging.DEBUG):
    log_formatter = logging.Formatter(
        '%(asctime)s [%(filename)s/%(funcName)s] %(levelname)s: %(message)s',
        datefmt='%Y/%m/%d %H:%M:%S')

    logger = logging.getLogger()
    logger.setLevel(debug_level)  # Global debug level

    log_ch = logging.StreamHandler(sys.stdout)
    log_ch.setLevel(logging.INFO)  # Console debug level
    log_ch.setFormatter(log_formatter)

    log_fh = logging.FileHandler(log_file, mode='w')  # Overwrite the log file
    log_fh.setFormatter(log_formatter)

    logger.addHandler(log_ch)
    logger.addHandler(log_fh)

    logger.info('Log initialized - logging to %s', log_file)

    return logger


class StoreNodeTypeId(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, 'node_type', self.dest)
        values = 0 if values is None else values
        setattr(namespace, 'node_id', values)


def get_cluster(project):
    """Download cluster details via cloudctl"""
    image = 'registry.gcp.elastifile.com/tools/cloud_tools'
    tag = 'latest'

    # On cloudtop, may need to run
    # newgrp docker
    cloudctl_cmd = ['docker', 'run', '--rm', '--privileged', '-v', '/tmp:/tmp', image+':'+tag,
                    'gcp', 'list_ips', '--project-id', project, '--json']

    logger.info("Running command: {}".format(" ".join(cloudctl_cmd)))
    json_as_text = subprocess.check_output(cloudctl_cmd)

    try:
        data = json.loads(json_as_text)
    except ValueError as ex:
        raise Exception("Bad JSON: {} === {}".format(ex, json_as_text))

    if data is None:
        raise Exception("Malformed JSON: {}".format(json_as_text))
    elif not data['data']:
        raise Exception("Unexpected json format - 'data' not found: {}".format(json_as_text))

    return data


logger = init_log(os.path.join(mypath, os.path.splitext(myname)[0] + '.log'))

# Define command line arguments
parser = argparse.ArgumentParser(description="Connect to a test setup's node or to one node specified by type [and id]")
machine_type = parser.add_mutually_exclusive_group()
machine_type.add_argument('-l', '--loader', dest='loaders', type=int,
                          default=0, nargs='?', action=StoreNodeTypeId,
                          metavar='LOADER_ID', help="Loader id")
machine_type.add_argument('-e', '--emanage', dest='emanage', type=int,
                          default=0, nargs='?', action=StoreNodeTypeId,
                          metavar='EMANAGE_ID', help="eManage id")
machine_type.add_argument('-v', '--vhead', dest='vheads', type=int,
                          default=0, nargs='?', action=StoreNodeTypeId,
                          metavar='VHEAD_ID', help="vHead id")
machine_type.add_argument('-r', '--replication_agents', dest='replication_agents', type=int,
                          default=0, nargs='?', action=StoreNodeTypeId,
                          metavar='REPLICATION_AGENT_ID', help="Replication agent id")
machine_type.add_argument('-f', '--floating_ip', dest='node_type',
                          action='store_const', const='emanage_vip',
                          help="eManage VIP")
parser.add_argument('-u', '--user', dest='user_name', help="Node user name", default="centos")
parser.add_argument('-p', '--password', dest='password', default='123456', help="Node user's password")
parser.add_argument('-i', '--identity_file', dest='public_key',
                    help="Identity (public key) file")
parser.add_argument('-c', '--cache', dest='cache_ttl', type=int, help="Cache TTL in seconds", default="600")
parser.add_argument('-x', '--execute', dest='cmd', type=str, action='store',
                    metavar='CMD', help="Command to be executed (doesn't echo the result at the moment)")
parser.add_argument(dest='setup_id', help="Numeric test setup id")
args = parser.parse_args()

setup_id = args.setup_id
node_type = args.node_type if args.node_type else 'all'
identity_file_override = args.public_key
node_id = 0
if args.node_type in node_types:
    node_id = args.node_id
user_name = args.user_name
password = args.password
remote_cmd = args.cmd
cache_ttl = args.cache_ttl

cache_file = os.path.join(cache_dir, setup_id)


def get_cluster_from_cache(setup_id):
    if not cache_ttl:
        logger.debug("Cache disabled")
        return None

    if not os.path.isfile(cache_file):
        logger.debug("Cached cluster {} not found".format(setup_id))
        return None

    cache_update_time = os.path.getmtime(cache_file)
    current_time = int(time.time())
    if current_time - cache_update_time > cache_ttl:
        logger.debug("Cluster cache expired - current time: {} cache mtime: {} TTL: {}, delta: {}s".
            format(current_time, cache_update_time, cache_ttl, current_time - cache_update_time))
        return None

    logger.info("Using cached config {}".format(cache_file))
    with open(cache_file) as f:
        try:
            return json.load(f)
        except Exception as ex:
            logger.warning("Failed loading cluster config from cache {} - {}".format(cache_file, ex))
            return None

def update_cluster_cache(cluster_id, cluster_data):
    if not os.path.isdir(cache_dir):
        logger.debug("Missing cache dir - creating {}".format(cache_dir))
        os.makedirs(cache_dir)

    with open(cache_file, "w") as f:
        logger.debug("Updating cluster cache - {}".format(cache_file))
        json.dump(cluster_data, f)


if not os.path.isfile(ssh_script):
    raise Exception("SSH script {} not found".format(ssh_script))

# Fetch cluster data
testenv = get_cluster_from_cache(setup_id)
if not testenv:
    testenv = get_cluster(setup_id)
    update_cluster_cache(setup_id, testenv)

# Identity (key) file
identity_file = os.path.expanduser('~/.ssh/elastifile.pem')  # Default value
if identity_file_override:
    identity_file = identity_file_override

if node_type in node_types:
    try:
        ip_addr = testenv['data'][node_type][node_id]['ip_address']
    except KeyError:  # replication_agents don't have ip_address field
        ip_addr = testenv['data'][node_type][node_id]['external_ip_address']
    except IndexError:
        raise Exception("Setup doesn't have enough {} (requested zero-based id {}, total {})".
                        format(node_type, node_id, len(testenv['data'][node_type])))
elif node_type == 'emanage_vip':
    ip_addr = testenv['data'][node_type]
else:
    raise Exception("Unsupported node type {}".format(node_type))

key_arg = ""
if identity_file:
    key_arg = "-k {}".format(identity_file)

assert ip_addr is not None,\
    "IP address for the requested node ({} {}) is not specified in cloudctl. "\
    "Try refreshing the cache (-c 0) and contact IT if that fails.".\
    format(node_type, node_id)
logger.info("Connecting to {} as {}/{}".format(ip_addr, user_name, password))

cmd = [os.path.abspath(ssh_script)]
if remote_cmd:
    cmd.extend(['--', remote_cmd])
if key_arg:
    cmd.append(key_arg)
cmd.extend(['-l', user_name, '-p', password])
if node_type in ('emanage', 'emanage_vip'):
    if user_name != "root":  # Fix elfs_admin access rights
        chmod_cmd = list(cmd)
        chmod_cmd.extend(['-e', 'sudo chmod a+X ~root', ip_addr])
        call(chmod_cmd)
    cmd.extend(['-i', '-e', "bash --rcfile <(echo '. ~root/elfs_admin; . ~/.bashrc')", ip_addr])
elif node_type in ('vheads', 'replication_agents'):
    emanage_ip = testenv['data']['emanage'][0]['ip_address']
    cmd.extend(['-e', 'sudo ssh -o StrictHostKeyChecking=no ' + ip_addr, emanage_ip])
else:  # Regular VM, e.g. loader
    cmd.append(ip_addr)

call(cmd)

