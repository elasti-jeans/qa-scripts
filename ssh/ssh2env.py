#!/usr/bin/env python

import os
import sys
import ssh
import json
import random
import string
import argparse

from platform import system
from subprocess import call, Popen

copy_id_hack = True  # Remove once emanage runs openssh >= 7.3p1
copy_id_bin = '/usr/bin/ssh-copy-id'
mydir = os.path.dirname(sys.argv[0])


class StoreNodeTypeId(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, 'node_type', self.dest)
        setattr(namespace, 'node_id', values)


def random_str(len=8, chars=string.ascii_letters+string.digits):
    return "".join(random.choice(chars) for _ in xrange(len))


def get_public_key(public_key_file):
    k_file = os.path.expanduser(public_key_file)  # Support ~ in the path
    with open(k_file) as k:
        public_key = k.readline()
    return public_key.rstrip()


def add_public_key(key_file, emanage_vip, vhead_ip, emanage_user='root',
                   emanage_pass='123456', vhead_user='root'):
    print "Adding public key to vhead {}".format(vhead_ip)
    public_key = get_public_key(key_file)
    # authorized_keys_file = '~/.ssh/authorized_keys'

    # # TODO: emanage should have the vhead in known_hosts
    # cmd = "ssh {0}@{1} \"echo -e \'\\\n{2}\' \\\\>\\\\> {3}\"".\
    #       format(vhead_user, vhead_ip, public_key, authorized_keys_file)

    # Shell - works
    # ssh.py -e "ssh root@10.11.147.87 grep 'AAA' /tmp/a || ssh root@10.11.147.87 \"echo 'BBB BBB' \\\>\\\> /tmp/pkey\"" -l root -p 123456 10.11.209.208

    # Works, but keeps adding more entries to authorized_keys
    # cmd = "ssh {0}@{1} \"grep -Fq \'{2}\' {3}\" \\\\|\\\\| " \
    #       "ssh {0}@{1} \"echo \'{2}\' \\\\>\\\\> {3}\"".\
    #       format(vhead_user, vhead_ip, public_key, authorized_keys_file)

    # call([ssh_script, '-l', emanage_user, '-p', emanage_pass, '-e', cmd,
    #       emanage_vip])
    # sess.ssh(command=cmd, handle_known_hosts=True)
    session_id = random_str(6)
    tmp_key_file = '/tmp/{}.key.pub'.format(session_id)
    sess = ssh.SshSession(emanage_user, emanage_vip, password=emanage_pass)
    sess.scp(os.path.expanduser(key_file), tmp_key_file)

    if copy_id_hack:
        # openssh requires the private key to be present to be able to copy id
        # https://bugzilla.mindrot.org/show_bug.cgi?id=2110
        copy_id_bin = os.path.join('/tmp', 'copy-id')
        local_copy_id_bin = os.path.join(mydir, 'copy-id')
        sess.scp(os.path.expanduser(local_copy_id_bin), copy_id_bin)
    sess.ssh("{} -f -o 'StrictHostKeyChecking no' -i {} {}@{}".
             format(copy_id_bin, tmp_key_file, vhead_user, vhead_ip))
    # Cleanup
    # sess.ssh("rm -f {}".format(tmp_key_file))


# Define command line arguments
parser = argparse.ArgumentParser(description='Connect to a test setup node '
                                             'specified by type [and id]')
# Only one argument in the group is accepted, and that arg is required
machine_type = parser.add_mutually_exclusive_group(required=True)
machine_type.add_argument('-l', '--loader', dest='loaders', type=int,
                          action=StoreNodeTypeId, help="Loader id")
machine_type.add_argument('-e', '--emanage', dest='emanage', type=int,
                          nargs='?', action=StoreNodeTypeId, help="eManage id")
machine_type.add_argument('-v', '--vhead', dest='vheads', type=int,
                          action=StoreNodeTypeId, help="vHead id")
machine_type.add_argument('-f', '--floating_ip', dest='node_type', action='store_const',
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

ssh_script = os.path.join(mydir, 'ssh.py')
json_file = args.conf_file
node_type = args.node_type
key_file = args.public_key
if args.node_type in ('emanage', 'vheads', 'loaders'):
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

if node_type in ('emanage', 'vheads', 'loaders'):
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
    # Build ssh commands
    tabs = []
    for t in ('emanage', 'vheads', 'loaders'):
        for i in xrange(len(testenv['data'][t])):
            ip_addr = testenv['data'][t][i]['ip_address']
            print "Connecting to {} {} ({} {}/{})".format(
                t, i, ip_addr, user_name, password)

            tabs.append([ssh_script, '-l', user_name, '-p', password,
                         ip_addr])

    # Open OS-specific terminal emulators
    if os_name == 'Linux':
        cmd = ["gnome-terminal"]
        for tab in tabs:
            cmd.extend(['--tab', '-e', " ".join(tab)])
        print "Executing cmd: {}".format(cmd)
        call(cmd)
    elif os_name == 'Darwin':
        for i, tab in enumerate(tabs):
            osascr = []
            osascr.append('tell application \"Terminal\"\n')
            osascr.append('tell application \"System Events\" to keystroke \"t\" using command down\n')
            osascr.append('do script \"' + " ".join(tab) + '\" in front window\n')
            osascr.append('end tell\n')
            osa_file = '/tmp/tab-{}'.format(i)
            with open(osa_file, 'w') as f:
                f.writelines(osascr)
            cmd = ['osascript', osa_file]
            print "Running cmd: {}".format(" ".join(cmd))
            call(cmd)
            # TODO: Clean up the tmp files? Could be useful to re-open the tabs manually
    else:
        print "ERROR - Unsupported OS: {}".format(os_name)
        sys.exit(30)
