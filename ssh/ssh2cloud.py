#!/usr/bin/env python

import os
import subprocess
import sys
import ssh
import json
import random
import string
import logging
import argparse

from subprocess import call

mypath = os.path.dirname(sys.argv[0])
myname = os.path.basename(sys.argv[0])

copy_id_bin = '/usr/bin/ssh-copy-id'
ssh_script = os.path.join(mypath, 'ssh.py')
remote_identity_file = None
copy_id_hack = True  # Disable once emanage runs openssh >= 7.3p1
node_types = ['emanage', 'vheads', 'replication_agents', 'loaders']


def init_log(log_file='result.log', debug_level=logging.INFO):
    log_formatter = logging.Formatter(
        '%(asctime)s [%(filename)s/%(funcName)s] %(levelname)s: %(message)s',
        datefmt='%Y/%m/%d %H:%M:%S')

    logger = logging.getLogger()
    logger.setLevel(debug_level)  # Global debug level

    log_ch = logging.StreamHandler(sys.stdout)
    log_ch.setLevel(logging.INFO)  # Console debug level
    log_ch.setFormatter(log_formatter)

    log_fh = logging.FileHandler(log_file, mode='w')  # Overwrite the log file
    log_fh.setLevel(logging.DEBUG)  # File debug level
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
    json_as_text = subprocess.check_output(['docker', 'run', '--rm', '--privileged', '-v', '/tmp:/tmp', image+':'+tag,
                                            'gcp', 'list_ips', '--project-id', project, '--json'])

    data = json.loads(json_as_text)
    if data is None:
        raise Exception("Malformed JSON: {}".format(json_as_text))
    elif not data['data']:
        raise Exception("Unexpected json format - 'data' not found: {}".format(json_as_text))

    return data


def random_str(len=8, chars=string.ascii_letters+string.digits):
    """
    Return random string
    """
    return "".join(random.choice(chars) for _ in xrange(len))


def add_public_key(identity_file, emanage_vip, vhead_ip, emanage_user='root',
                   emanage_pass='123456', vhead_user='root'):
    """
    Add public key to a vHead
    :param identity_file: Identity file (key)
    :param emanage_vip: eManage virtual IP address
    :param vhead_ip: vHead's IP address
    :param emanage_user: eManage username
    :param emanage_pass: eManage user's password
    :param vhead_user: vHead's user
    """
    authorized_keys = '~/.ssh/authorized_keys'
    logger.info("Adding public key to vhead {}".format(vhead_ip))

    sess = ssh.SshSession(emanage_user, emanage_vip, password=emanage_pass)

    if copy_id_hack:
        # openssh requires the private key to be present to be able to copy id
        # https://bugzilla.mindrot.org/show_bug.cgi?id=2110
        copy_id_bin = os.path.join('/tmp', 'copy-id')
        local_copy_id_bin = os.path.join(mypath, 'copy-id')

    global remote_identity_file
    if remote_identity_file is None:  # Only done once per run
        remote_identity_file = '/tmp/{}.key.pub'.format(random_str(6))
        assert os.path.isfile(os.path.expanduser(identity_file)), \
            "Public key not found: ({})".format(identity_file)
        sess.scp(os.path.expanduser(identity_file), remote_identity_file)
        if copy_id_hack:
            assert os.path.isfile(os.path.expanduser(local_copy_id_bin)), \
                "File not found: ({})".format(local_copy_id_bin)
            sess.scp(os.path.expanduser(local_copy_id_bin), copy_id_bin)

    sess.ssh('ssh -o \'StrictHostKeyChecking no\' {}@{} \"echo \'\' '
             '\\\>\\\> {}\"'.format(vhead_user, vhead_ip, authorized_keys))
    sess.ssh("{} -f -o 'StrictHostKeyChecking no' -i {} {}@{}".
             format(copy_id_bin, remote_identity_file, vhead_user, vhead_ip))


def update_prompt(host, user, password, node_type=None):
    """Customize node's prompt"""
    remote_path = '/etc/profile.d'
    fname = 'vheads-prompt.sh' if node_type == 'vheads' else 'qa-prompt.sh'
    assert os.path.isfile(os.path.expanduser(fname)),\
        "Prompt file not found: ({})".format(fname)
    logger.info("Updating prompt on {}".format(host))
    sess = ssh.SshSession(user, host, password)
    sess.scp(os.path.expanduser(fname), os.path.join(remote_path, fname))


logger = init_log(os.path.join(mypath, myname + '.log'))

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
parser.add_argument('-k', '--add_key', dest='add_key', action='store_true',
                    default=False, help="Add your public key to all vHeads")
parser.add_argument('-i', '--identity_file', dest='public_key',
                    help="Identity (public key) file")
parser.add_argument('-P', '--customize_prompt', dest='customize_prompt',
                    action='store_true', default=False,
                    help="Customize prompt on remote hosts")
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
add_key = args.add_key
remote_cmd = args.cmd
customize_prompt = args.customize_prompt


if not os.path.isfile(ssh_script):
    raise Exception("SSH script {} not found".format(ssh_script))

# Fetch cluster data
testenv = get_cluster(setup_id)

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
elif node_type == 'all':
    pass
else:
    raise Exception("Unsupported node type {}".format(node_type))

# Add public key to vHeads
if add_key:
    emanage_vip_addr = testenv['data']['emanage_vip']
    for i in xrange(len(testenv['data']['vheads'])):
        vhead_ip_addr = testenv['data']['vheads'][i]['ip_address']
        logger.info("Adding your public key to {} ({})".format(
            vhead_ip_addr, testenv['data']['vheads'][i]['hostname']))
        add_public_key(identity_file, emanage_vip_addr, vhead_ip_addr)

key_arg = ""
if identity_file:
    key_arg = "-k {}".format(identity_file)

assert ip_addr is not None,\
    "Requested IP address for the requested node ({} {}) is not specified "\
    "in eLab. Try refreshing the cache (-c) and contact IT if that fails.".\
    format(node_type, node_id)
logger.info("Connecting to {} as {}/{}".format(ip_addr, user_name, password))

if customize_prompt:
    update_prompt(ip_addr, user_name, password, node_type)

cmd = [os.path.abspath(ssh_script)]
if remote_cmd:
    cmd.extend(['-e', remote_cmd])
if key_arg:
    cmd.append(key_arg)
cmd.extend(['-l', user_name, '-p', password])
if node_type in ('emanage', 'emanage_vip'):
    if user_name != "root":  # Fix elfs_admin access rights
        chmod_cmd = list(cmd)
        chmod_cmd.extend(['-e', 'sudo chmod a+X ~root', ip_addr])
        call(chmod_cmd)
    cmd.extend(['-i', '-e', "bash --rcfile <(echo '. ~root/elfs_admin; . ~/.bashrc')", ip_addr])
else:  # Regular VM, e.g. loader
    cmd.append(ip_addr)
call(cmd)
