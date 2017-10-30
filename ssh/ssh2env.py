#!/usr/bin/env python

import os
import sys
import ssh
import json
import urllib
import random
import string
import logging
import argparse

from time import sleep
from platform import system
from subprocess import call

mydir = os.path.dirname(sys.argv[0])
elab_url = 'http://elab.il.elastifile.com'
elab_cluster_url = '{}/api/v1/system/cluster/'.format(elab_url)
copy_id_bin = '/usr/bin/ssh-copy-id'
ssh_script = os.path.join(mydir, 'ssh.py')
remote_public_key = None
copy_id_hack = True  # Remove once emanage runs openssh >= 7.3p1


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


def download_testenv(cid, force=False):
    """Download json from eLab by setup id"""
    dest = os.path.join(mydir, cid)
    if force or not os.path.isfile(dest):
        logger.info("Downloading json for setup {} from eLab (force: {})".
                    format(cid, force))
        try:
            urllib.urlretrieve(elab_cluster_url+cid, cid)
        except IOError as ex:
            sleep(2)
            logger.warning("Failed to download json from eLab. {}: {} "
                           "-- retrying".format(ex.errno, ex.strerror))
            try:
                urllib.urlretrieve(elab_cluster_url+cid, cid)
            except IOError as ex:
                raise Exception("Final attempt to download json from eLab "
                                "failed. {}: {}".format(ex.errno, ex.strerror))
    return dest


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
    logger.info("Adding public key to vhead {}".format(vhead_ip))

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

    sess.ssh("echo '' >> ~/.ssh/authorized_keys")
    sess.ssh("{} -f -o 'StrictHostKeyChecking no' -i {} {}@{}".
             format(copy_id_bin, remote_public_key, vhead_user, vhead_ip))


def connect_gnome_term(cmds):
    """Connect to gnoe-terminal on Linux"""
    cmd = ["gnome-terminal"]
    for tab_cmd in cmds:
        cmd.extend(['--tab', '-e', " ".join(tab_cmd)])
    logger.info("Executing cmd: {}".format(cmd))
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
    # Format commands for Apple Script
    acmds = ['"{}"'.format(" ".join(s)) for s in cmds]
    with open(osa_file, 'w') as f:
        f.write(osa_iterm.format(", ".join(acmds)))
    cmd = ['osascript', osa_file]
    logger.info("Running cmd: {}".format(" ".join(cmd)))
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
        logger.info("Running cmd {}: {}".format(i, " ".join(cmd)))
        call(cmd)


logger = init_log(os.path.join(mydir, 'ssh2env.log'))

# Define command line arguments
parser = argparse.ArgumentParser(description='Connect to a test setup node '
                                             'specified by type [and id]')
# Only one argument in the group is accepted, and that arg is required
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
machine_type.add_argument('-f', '--floating_ip', dest='node_type',
                          action='store_const', const='emanage_vip',
                          help="eManage VIP")
machine_type.add_argument('-a', '--all', dest='node_type', action='store_const',
                          const='all', help="Connect to all nodes")
parser.add_argument('-u', '--user', dest='user_name', default='root',
                    help="User name")
parser.add_argument('-p', '--password', dest='password', default='123456',
                    help="User password")
parser.add_argument('-i', '--identity_file', dest='public_key',
                    default='~/.ssh/id_rsa.pub',
                    help="Identity (public key) file")
parser.add_argument('-k', '--add_key', dest='add_key', action='store_true',
                    default=False, help="Add key to vHeads")
parser.add_argument('-m', '--mac_term', dest='mac_term', action='store',
                    default="Terminal", help="Mac Os X Terminal emulator")
parser.add_argument('-c', '--clear_cache', dest='clear_cache',
                    action='store_true', default=False,
                    help="Clear cached json for the specified setup id")


parser.add_argument(dest='setup_id', help="JSON configuration file")
args = parser.parse_args()

setup_id = args.setup_id
node_type = args.node_type
key_file = args.public_key
if args.node_type in ('emanage', 'vheads', 'loaders'):
    node_id = args.node_id
user_name = args.user_name
password = args.password
add_key = args.add_key
mac_term = args.mac_term
clear_cache = args.clear_cache

json_file = download_testenv(setup_id, force=clear_cache)
testenv = read_testenv(json_file)

if not os.path.isfile(ssh_script):
    raise Exception("SSH script {} not found".format(ssh_script))

if node_type in ('emanage', 'vheads', 'loaders'):
    try:
        ip_addr = testenv['data'][node_type][node_id]['ip_address']
    except IndexError:
        raise Exception("Setup doesn't have enough {} (total {})".
            format(node_type, len(testenv['data'][node_type])))
elif node_type == 'emanage_vip':
    ip_addr = testenv['data'][node_type]
elif node_type == 'all':
    pass
else:
    raise Exception("Unsupported node type {}".format(node_type))

os_name = system()

# Add public key to vHeads
if add_key:
    emanage_vip_addr = testenv['data']['emanage_vip']
    for i in xrange(len(testenv['data']['vheads'])):
        vhead_ip_addr = testenv['data']['vheads'][i]['ip_address']
        logger.info("Adding your public key to {} ({})".format(
            vhead_ip_addr, testenv['data']['vheads'][i]['hostname']))
        add_public_key(key_file, emanage_vip_addr, vhead_ip_addr)

if node_type != 'all':
    logger.info("Connecting to {} as {}/{}".format(ip_addr, user_name,
                                                   password))
    call([ssh_script, '-l', user_name, '-p', password, ip_addr])
else:  # Open sessions for all setup nodes
    # Build ssh commands
    cmds = []
    for t in ('emanage', 'vheads', 'loaders'):
        for i in xrange(len(testenv['data'][t])):
            ip_addr = testenv['data'][t][i]['ip_address']
            logger.info("Connecting to {} ({} {}/{})".format(
                testenv['data'][t][i]['hostname'], ip_addr, user_name,
                password))
            if ip_addr is None:
                logger.error("Skipping {}, since eLab reports its IP as null".
                             format(testenv['data'][t][i]['hostname']))
            else:
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
            raise Exception("Unsupported Mac terminal: {}".format(mac_term))
    else:
        raise Exception("Unsupported OS: {}".format(os_name))
