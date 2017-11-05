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

from platform import system
from subprocess import call

mydir = os.path.dirname(sys.argv[0])
elab_url = 'http://elab.il.elastifile.com'
elab_cluster_url = '{}/api/v1/system/cluster/'.format(elab_url)
copy_id_bin = '/usr/bin/ssh-copy-id'
ssh_script = os.path.join(mydir, 'ssh.py')
remote_public_key = None
copy_id_hack = True  # Disable once emanage runs openssh >= 7.3p1
node_types = ['emanage', 'vheads', 'loaders']


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


def fetch_file(url, dest, attempts=1):
    """Download a file by URL"""
    attempt = 0

    while attempt < attempts:
        attempt += 1
        try:
            urllib.urlretrieve(url, dest)
        except IOError as ex:
            logger.warning("Attempt {}/{} to fetch file {} failed "
                           "(errno {}: {})".format(attempt, attempts, url,
                                                   ex.errno, ex.strerror))
        else:
            logger.info("Downloaded {} from {}".format(dest, url))
            break
    else:
        raise Exception("Gave up the download of {} after {} attempts".
                        format(url, attempts))


def download_testenv(cid, force=False):
    """Download json from eLab by setup id"""
    dest = os.path.join(mydir, cid)
    if force or not os.path.isfile(dest):
        logger.info("Downloading json for setup {} from eLab (force: {})".
                    format(cid, force))
        fetch_file(elab_cluster_url+cid, dest, attempts=3)
    else:
        logger.info("Using cached json: {}".format(dest))
    return dest


def read_testenv(json_file):
    """
    Read testenv json
    """
    with open(json_file) as f:
        testenv = json.load(f)

    if testenv is None:
        raise Exception("Failed to load data from {}".format(json_file))
    elif not testenv['data']:
        raise Exception("Bad test setup json in {} - are you sure the setup id "
                        "is correct?".format(json_file))

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
    authorized_keys = '~/.ssh/authorized_keys'
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

    sess.ssh('ssh -o \'StrictHostKeyChecking no\' {}@{} \"echo \'\' '
             '\\\>\\\> {}\"'.format(vhead_user, vhead_ip, authorized_keys))
    sess.ssh("{} -f -o 'StrictHostKeyChecking no' -i {} {}@{}".
             format(copy_id_bin, remote_public_key, vhead_user, vhead_ip))


def update_prompt(host, user, password, node_type=None):
    """Customize node's prompt"""
    remote_path = '/etc/profile.d'
    fname = 'vheads-prompt.sh' if node_type == 'vheads' else 'qa-prompt.sh'
    assert os.path.isfile(os.path.expanduser(fname)),\
        "Prompt file not found: ({})".format(fname)
    logger.info("Updating prompt on {}".format(host))
    sess = ssh.SshSession(user, host, password)
    sess.scp(os.path.expanduser(fname), os.path.join(remote_path, fname))


def connect_gnome_term(cmds):
    """Connect to gnoe-terminal on Linux"""
    cmd = ["gnome-terminal"]
    for tab_cmd in cmds:
        cmd.extend(['--tab', '-e', " ".join(tab_cmd)])
    logger.info("Executing cmd: {}".format(cmd))
    call(cmd)


def connect_iterm(setup_id, cmds_by_type, split="true", messages=[]):
    """Connect to iTerm on OS X"""
    osa_iterm = """
set split_by_node_type to {0}
tell application "iTerm"
    create window with default profile
    activate
    set w to current window
    if w is equal to missing value then
        log "Creating new window"
        set w to (create window with default profile)
    else
        log "Reusing existing window"
    end if

    #set emanage_hostnames to ...
    #set emanage_cmds to ...
    #set vheads_hostnames to ...
    #set vheads_cmds to ...
    #set loaders_hostnames to ...
    #set loaders_cmds to ...
    {1}

    set node_hostnames to {{emanage_hostnames, vheads_hostnames, loaders_hostnames}}
    set node_groups to {{emanage_cmds, vheads_cmds, loaders_cmds}}

    tell w
        repeat with gi from 1 to length of node_groups
            set node_type_cmds to item gi of node_groups
            set node_type_hostnames to item gi of node_hostnames
            
            if split_by_node_type then
                # Create new tab for each node group, except the 1st one
                if gi is not equal to 1 then
                    log "Creating new tab"
                    set t to (create tab with default profile)
                    select t
                end if
            end if

            repeat with ni from 1 to length of node_type_cmds
                # Actual ssh.py command
                set cmd to item ni of node_type_cmds
                set hostname to item ni of node_type_hostnames

                log "Executing " & cmd

                if split_by_node_type then
                    tell current session of w
                        # Create new session for each node, except the 1st one in each group
                        if ni is equal to 1 then
                            log "... in existing session"
                        else
                            log "... in new (split) session"
                            set s to (split horizontally with same profile)
                            select s
                        end if
                    end tell
                else
                    # Create new tab for each node, except the 1st one
                    if gi is equal to 1 and ni is equal to 1 then
                        log "Skipping new tab"
                        tell current session of w
                            write text cmd
                        end tell
                    else
                        log "Creating new tab"
                        set t to (create tab with default profile)
                    end if
                end if

                tell current session
                    write text cmd
                    delay 0.8
                    set sess_name to "{2} " & hostname
                    set name to sess_name
                end tell
            end repeat
        end repeat
    end tell
end tell

{3}
"""
    osa_file = '/tmp/iterm2.osa'
    list_defs = ""
    for t in node_types:
        hostnames = list()
        cmds = list()
        for n in cmds_by_type[t]:
            hostnames.append(n['hostname'])
            cmds.append(" ".join(n['cmd']))
        list_defs += 'set {}_hostnames to {{"{}"}}\n'.format(t, '", "'.
                                                             join(hostnames))
        list_defs += 'set {}_cmds to {{"{}"}}\n'.format(t, '", "'.join(cmds))

    say = []
    if voice:
        say = ['say "Connected to test setup {}"'.format(setup_id)]
        if messages:
            say.extend(['say "{}"'.format(m) for m in messages])
    with open(osa_file, 'w') as f:
        f.write(osa_iterm.format(split, list_defs, setup_id, "\n".join(say)))
    cmd = ['osascript', osa_file]
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


def osx_is_installed(app_name):
    cmd = ["osascript", "-e", 'exists application \"{}\"'.format(app_name)]
    logger.info("Executing {}".format(cmd))
    success = call(cmd) == 0
    logger.info("App '{}' installed: {}".format(app_name, success))
    return success


logger = init_log(os.path.join(mydir, 'ssh2env.log'))

# Define command line arguments
parser = argparse.ArgumentParser(
    description="Connect to all test setup's nodes or to one node "
                "specified by type [and id]")
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
                    help="Node user name")
parser.add_argument('-p', '--password', dest='password', default='123456',
                    help="Node user's password")
parser.add_argument('-k', '--add_key', dest='add_key', action='store_true',
                    default=False, help="Add your public key to all vHeads")
parser.add_argument('-i', '--identity_file', dest='public_key',
                    default='~/.ssh/id_rsa.pub',
                    help="Identity (public key) file")
parser.add_argument('-m', '--mac_term', dest='mac_term', action='store',
                    default="", help="Override OS X Terminal emulator "
                                     "detection (iTerm/Terminal)")
parser.add_argument('-S', '--iterm_no_split', dest='iterm_split',
                    action='store_const', const='false', default='true',
                    help="(iTerm only) Don't split sessions by node type")
parser.add_argument('--voice', dest='voice', action='store_true',
                    default=False, help="Issue sound alerts")
parser.add_argument('-P', '--customize_prompt', dest='customize_prompt',
                    action='store_true', default=False,
                    help="Customize prompt on remote hosts")
parser.add_argument('-c', '--clear_cache', dest='clear_cache',
                    action='store_true', default=False,
                    help="Clear cached json for the specified setup id")
parser.add_argument(dest='setup_id', help="Numeric test setup id")
args = parser.parse_args()

setup_id = args.setup_id
node_type = args.node_type if args.node_type else 'all'
key_file = args.public_key
if args.node_type in node_types:
    node_id = args.node_id
user_name = args.user_name
password = args.password
add_key = args.add_key
mac_term = args.mac_term
clear_cache = args.clear_cache
iterm_split = args.iterm_split
voice = args.voice
customize_prompt = args.customize_prompt

json_file = download_testenv(setup_id, force=clear_cache)
testenv = read_testenv(json_file)

if not os.path.isfile(ssh_script):
    raise Exception("SSH script {} not found".format(ssh_script))

if node_type in node_types:
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
    assert ip_addr is not None,\
        "Requested IP address for the requested node ({} {}) is not specified "\
        "in eLab. Try refreshing the cache (-c) and contact IT if that fails.".\
        format(node_type, node_id)
    logger.info("Connecting to {} as {}/{}".format(ip_addr, user_name,
                                                   password))
    if customize_prompt:
        update_prompt(ip_addr, user_name, password, node_type)

    call([ssh_script, '-l', user_name, '-p', password, ip_addr])
else:  # Open sessions for all setup nodes
    # Build ssh commands
    cmds = []
    problems = []
    node_groups = {}
    for t in node_types:
        node_groups[t] = []
        for i in xrange(len(testenv['data'][t])):
            ip_addr = testenv['data'][t][i]['ip_address']
            node_hostname = testenv['data'][t][i]['hostname']

            if customize_prompt:
                update_prompt(ip_addr, user_name, password, t)

            logger.info("Connecting to {} ({} {}/{})".format(
                node_hostname, ip_addr, user_name, password))
            if ip_addr is None:
                logger.error("Skipping {}, since eLab reports its IP as null".
                             format(testenv['data'][t][i]['hostname']))
                problems.append("Skipped {} {} due to missing IP address".
                                format(t, i))
            else:
                cmd = [os.path.abspath(ssh_script), '-l', user_name, '-p',
                       password, ip_addr]
                node_groups[t].append({'hostname': node_hostname, 'cmd': cmd})
                cmds.append(cmd)

    # Open OS-specific terminal emulators
    if os_name == 'Linux':
        connect_gnome_term(cmds)
    elif os_name == 'Darwin':
        if not mac_term:
            mac_term = "iTerm" if osx_is_installed("iTerm") else "Terminal"

        if mac_term == "iTerm":
            connect_iterm(setup_id, node_groups, split=iterm_split,
                          messages=problems)
        elif mac_term == "Terminal":
            connect_terminal(cmds)
        else:
            raise Exception("Unsupported Mac terminal: {}".format(mac_term))
    else:
        raise Exception("Unsupported OS: {}".format(os_name))
