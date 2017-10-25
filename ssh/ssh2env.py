#!/usr/bin/env python

import os
import re
import sys
import json
import argparse

from platform import system
from subprocess import call, Popen


class StoreNodeTypeId(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        print "NODE TYPE: {}".format(self.dest)
        print "NODE ID VALUES: {}".format(values)
        setattr(namespace, 'node_type', self.dest)
        setattr(namespace, 'node_id', values)


def get_public_key(public_key_file):
    k_file = os.path.expanduser(public_key_file)  # Support ~ in the path
    with open(k_file) as k:
        public_key = k.readline()
    return public_key.rstrip()


def add_public_key(key_file, emanage_vip, vhead_ip, emanage_user='root',
                   emanage_pass='123456', vhead_user='root'):
    print "Adding public key to vhead {}".format(vhead_ip)
    authorized_keys_file = '~/.ssh/authorized_keys'
    public_key = get_public_key(key_file)

    cmd = "ssh {0}@{1} \"echo \'{2}\' \\\\>\\\\> {3}\"".\
          format(vhead_user, vhead_ip, public_key, authorized_keys_file)

    # Shell - works
    # ssh.py -e "ssh root@10.11.147.87 grep 'AAA' /tmp/a || ssh root@10.11.147.87 \"echo 'BBB BBB' \\\>\\\> /tmp/pkey\"" -l root -p 123456 10.11.209.208

    # Works, but keeps adding more entries to authorized_keys
    # cmd = "ssh {0}@{1} \"grep -Fq \'{2}\' {3}\" \\\\|\\\\| " \
    #       "ssh {0}@{1} \"echo \'{2}\' \\\\>\\\\> {3}\"".\
    #       format(vhead_user, vhead_ip, public_key, authorized_keys_file)

    call([ssh_script, '-l', emanage_user, '-p', emanage_pass, '-e', cmd,
          emanage_vip])


# Define command line arguments
parser = argparse.ArgumentParser(description='Connect to a test setup node '
                                             'specified by type [and id]')
# Only one argument in the group is accepted, and that arg is required
machine_type = parser.add_mutually_exclusive_group(required=True)
machine_type.add_argument('-l', '--loader', dest='loaders', type=int,
                          action=StoreNodeTypeId, help="Loader id")
machine_type.add_argument('-e', '--emanage', dest='emanage', type=int,
                          nargs='?', action=StoreNodeTypeId, help="eManage id")
machine_type.add_argument('-v', '--vip', dest='node_type', action='store_const',
                          const='emanage_vip', help="eManage VIP")
machine_type.add_argument('-a', '--all', dest='node_type', action='store_const',
                          const='all', help="Connect to all nodes")
parser.add_argument('-u', '--user', dest='user_name', default='root',
                    help="User name")
parser.add_argument('-p', '--password', dest='password', default='123456',
                    help="User password")
parser.add_argument('-k', '--public_key', dest='public_key',
                    default='~/.ssh/id_rsa.pub', help="Public key file")
parser.add_argument('-A', '--add_key', dest='add_key', action='store_true',
                    default=False, help="Add keys to vHeads")


parser.add_argument(dest='conf_file', help="JSON configuration file")
args = parser.parse_args()

ssh_script = os.path.join(os.path.dirname(sys.argv[0]), 'ssh.py')
json_file = args.conf_file
node_type = args.node_type
key_file = args.public_key
if args.node_type in ('loaders', 'emanage'):
    node_id = args.node_id
user_name = args.user_name
password = args.password
add_key = args.add_key

# Read json
with open(json_file) as f:
    testenv = json.load(f)

if testenv is None:
    raise Exception("ERROR - failed to load data from {}".format(json_file))

if not os.path.isfile(ssh_script):
    print "ERROR - {} not found".format(ssh_script)
    raise

if node_type in ('loaders', 'emanage'):
    try:
        ip_addr = testenv['data'][node_type][node_id]['ip_address']
    except IndexError:
        print "ERROR - setup doesn't have enough {} (total {})".format(
            node_type, len(testenv['data'][node_type]))
        raise
elif node_type == 'emanage_vip':
    ip_addr = testenv['data'][node_type]
elif node_type == 'all':
    pass
else:
    print "ERROR - unsupported node type {}".format(node_type)

os_name = system()

# Add public key to vheads
if add_key:
    emanage_vip_addr = testenv['data']['emanage_vip']
    for i in xrange(len(testenv['data']['vheads'])):
        add_public_key(key_file, emanage_vip_addr,
                       testenv['data']['vheads'][i]['ip_address'])

if node_type != 'all':
    print "Connecting to {} as {}/{}".format(ip_addr, user_name, password)
    call([ssh_script, '-l', user_name, '-p', password, ip_addr])
else:  # Open sessions for all setup nodes
    tabs = []
    for t in ('emanage', 'vheads', 'loaders'):
        for i in xrange(len(testenv['data'][t])):
            ip_addr = testenv['data'][t][i]['ip_address']
            print "Connecting to {} {} ({} {}/{})".format(
                t, i, ip_addr, user_name, password)

            if os_name == 'Linux':
                tabs.append([ssh_script, '-l', user_name, '-p', password,
                             ip_addr])
                # Might be needed to open a bunch of separate shells on Mac OSX
                # Popen(['xterm', '-e', ssh_script, '-l', user_name, '-p',
                #        password, ip_addr])
            elif os_name == 'Darwin':
                # TODO: Launch Terminal.app / itern2
                print "ERROR - Mac OS X is not yet supported"
                # Useful links
                # https://stackoverflow.com/questions/7171725/open-new-terminal-tab-from-command-line-mac-os-x
                
            else:
                print "ERROR - Unsupported OS: {}".format(os_name)

    if os_name == 'Linux':
        cmd = ["gnome-terminal"]
        for tab in tabs:
            cmd.extend(['--tab', '-e', " ".join(tab)])
        print "Executing cmd: {}".format(cmd)
        call(cmd)
