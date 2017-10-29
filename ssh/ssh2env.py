#!/usr/bin/env python

import os
import sys
import ssh
import json
import random
import string
import argparse

from platform import system
from subprocess import call

mydir = os.path.dirname(sys.argv[0])
copy_id_bin = '/usr/bin/ssh-copy-id'
ssh_script = os.path.join(mydir, 'ssh.py')
remote_public_key = None
copy_id_hack = True  # Remove once emanage runs openssh >= 7.3p1


class StoreNodeTypeId(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, 'node_type', self.dest)
        setattr(namespace, 'node_id', values)


def read_testenv(json_file):
    """
    Read tesenv json
    """
    with open(json_file) as f:
        testenv = json.load(f)

    if testenv is None:
        raise Exception("ERROR - failed to load data from {}".format(json_file))

    return testenv


def random_str(len=8, chars=string.ascii_letters+string.digits):
    """
    Return random string
    """
    return "".join(random.choice(chars) for _ in xrange(len))


def add_public_key(key_file, emanage_vip, vhead_ip, emanage_user='root',
                   emanage_pass='123456', vhead_user='root'):
    """
    Add public key to a vHead
    :param key_file: Public key
    :param emanage_vip: eManage virtual IP address
    :param vhead_ip: vHead's IP address
    :param emanage_user: eManage username
    :param emanage_pass: eManage user's password
    :param vhead_user: vHead's user
    """
    print "Adding public key to vhead {}".format(vhead_ip)

    sess = ssh.SshSession(emanage_user, emanage_vip, password=emanage_pass)

    if copy_id_hack:
        # openssh requires the private key to be present to be able to copy id
        # https://bugzilla.mindrot.org/show_bug.cgi?id=2110
        copy_id_bin = os.path.join('/tmp', 'copy-id')
        local_copy_id_bin = os.path.join(mydir, 'copy-id')

    global remote_public_key
    if remote_public_key is None:  # Only done once per run
        remote_public_key = '/tmp/{}.key.pub'.format(random_str(6))
        assert os.path.isfile(os.path.expanduser(key_file)), \
            "Public key not found: ({})".format(key_file)
        sess.scp(os.path.expanduser(key_file), remote_public_key)
        if copy_id_hack:
            assert os.path.isfile(os.path.expanduser(local_copy_id_bin)), \
                "File not found: ({})".format(local_copy_id_bin)
            sess.scp(os.path.expanduser(local_copy_id_bin), copy_id_bin)

    sess.ssh("{} -f -o 'StrictHostKeyChecking no' -i {} {}@{}".
             format(copy_id_bin, remote_public_key, vhead_user, vhead_ip))


def connect_gnome_term(cmds):
    """Connect to gnoe-terminal on Linux"""
    cmd = ["gnome-terminal"]
    for tab_cmd in cmds:
        cmd.extend(['--tab', '-e', " ".join(tab_cmd)])
    print "Executing cmd: {}".format(cmd)
    call(cmd)


def connect_iterm(cmds):
    """Connect to iTerm on OS X"""
    osa_iterm = """
tell application "iTerm"
  create window with default profile
  tell application "iTerm"
    tell current window
      set cmds to {{{}}}
      repeat with a from 1 to length of cmds
        set cmd to item a of cmds
        create tab with default profile command cmd
      end repeat
    end tell
  end tell
end tell
"""
    osa_file = '/tmp/iterm.osa'
    acmds = ['"{}"'.format(" ".join(s)) for s in cmds]  # Format commands for Apple Script
    with open(osa_file, 'w') as f:
        f.write(osa_iterm.format(", ".join(acmds)))
    cmd = ['osascript', osa_file]
    print "Running cmd: {}".format(" ".join(cmd))
    call(cmd)


def connect_terminal(cmds):
    """Connect to Terminal app on OS X"""
    osa_terminal = """
tell application \"Terminal\"
    tell application \"System Events\" to keystroke \"t\" using command down
    do script \"{}\" in front window
end tell
"""
    for i, tab in enumerate(cmds):
        osa_file = '/tmp/tab-{}'.format(i)
        with open(osa_file, 'w') as f:
            f.writelines(osa_terminal.format(" ".join(tab)))
        cmd = ['osascript', osa_file]
        print "Running cmd {}: {}".format(i, " ".join(cmd))
        call(cmd)


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
parser.add_argument('-m', '--mac_term', dest='mac_term', action='store',
                    default="Terminal", help="Mac Os X Terminal emulator")


parser.add_argument(dest='conf_file', help="JSON configuration file")
args = parser.parse_args()

json_file = args.conf_file
node_type = args.node_type
key_file = args.public_key
if args.node_type in ('emanage', 'vheads', 'loaders'):
    node_id = args.node_id
user_name = args.user_name
password = args.password
add_key = args.add_key
mac_term = args.mac_term

testenv = read_testenv(json_file)

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

# Add public key to vHeads
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
    cmds = []
    for t in ('emanage', 'vheads', 'loaders'):
        for i in xrange(len(testenv['data'][t])):
            ip_addr = testenv['data'][t][i]['ip_address']
            print "Connecting to {} {} ({} {}/{})".format(
                t, i, ip_addr, user_name, password)

            cmds.append([os.path.abspath(ssh_script), '-l', user_name,
                         '-p', password, ip_addr])

    # Open OS-specific terminal emulators
    if os_name == 'Linux':
        connect_gnome_term(cmds)
    elif os_name == 'Darwin':
        # TODO: Check if iTerm2 is installed, and use that one by default
        if mac_term == "iTerm":
            connect_iterm(cmds)
        elif mac_term == "Terminal":
            connect_terminal(cmds)
        else:
            raise Exception("Usupported Mac terminal: {}".format(mac_term))
    else:
        raise Exception("ERROR - Unsupported OS: {}".format(os_name))
