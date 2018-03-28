#!/usr/bin/env python

"""
 ----/-- - Author: Eric S. Raymond
 2003/04 - Greatly modified by Nigel W. Moriarty
 2013/08 - Modified by Jean Spector

PEXPECT LICENSE

    This license is approved by the OSI and FSF as GPL-compatible.
        http://opensource.org/licenses/isc-license.txt

    Copyright (c) 2012, Noah Spurrier <noah@noah.org>
    PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE FOR ANY
    PURPOSE WITH OR WITHOUT FEE IS HEREBY GRANTED, PROVIDED THAT THE ABOVE
    COPYRIGHT NOTICE AND THIS PERMISSION NOTICE APPEAR IN ALL COPIES.
    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""

from pexpect import *
import re
import os
import sys
import time
import fcntl
import string
import getopt
import shutil
import struct
import signal
import getpass
import termios

myname = os.path.basename(__file__)
keyfile = None
host = None
user = 'root'
password = None
rcmd = None
verbose = False
force_interact = None


class SshSession:

    """Session with extra state including the password to be used."""

    def __init__(self, user, host, password=None, verbose=False):
        self.user = user
        self.host = host
        self.verbose = verbose
        self.password = password
        self.keys = [
            'authenticity',
            'assword:',
            '@@@@@@@@@@@@',
            'Offending key for IP in',
            ']#',
            ']$',
            '~# ',
            'Command not found.',  # Errors should come last
            'Name or service not known',
            'No route to host',
            EOF,
            ]

        self.f = open('ssh.out', 'w')

    def __repr__(self):
        outl = 'class :'+self.__class__.__name__
        for attr in self.__dict__:
            if attr == 'password':
                outl += '\n\t'+attr+' : '+'*'*len(self.password)
            else:
                outl += '\n\t'+attr+' : '+str(getattr(self, attr))
        return outl

    def sigwinch_passthrough(self, sig, data):
        self.resize_term()

    def resize_term(self):
        s = struct.pack("HHHH", 0, 0, 0, 0)
        a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(),
                                              termios.TIOCGWINSZ, s))
        self.child.setwinsize(a[0], a[1])
        # print 'NEW WINSIZE: ', self.child.getwinsize()

    # ssh stopped storing the ip in known_hosts, and provides an easier way to clean up the offending entries
    def new_style_cleanup(self, lines):
        remove_command_identifier = "ssh-keygen"
        for line in lines:
            if remove_command_identifier in line:
                remove_cmd = line.strip()
                print "Executing %s " % remove_cmd
                res = os.system(remove_cmd)
                if res == 0:
                    return True
                else:
                    print "Previous command failed with exit code: %s" % res
        return false

    def __exec(self, command, handle_known_hosts=False, interactive=False):
        """Execute a command on the remote host. Return the output."""

        print "Executing %s " % command
        self.child = spawn(command)

        if self.verbose:
            sys.stderr.write("-> " + command + "\n")

        seen = self.child.expect_exact(self.keys)
        try:
            self.f.write(str(self.child.before) + str(self.child.after)+'\n')
        except Exception:
            pass

        if seen == 2:  # Bad known_hosts entry
            print "Handling known_hosts..."
            lines = self.child.readlines()
            for line in lines:
                self.f.write(line)
            if handle_known_hosts:
                if not self.new_style_cleanup(lines):
                    self.remove_known_hosts_entry(self.host)
                # Connect again after known_hosts were cleaned up
                print "Executing %s " % command
                self.child = spawn(command)
                seen = self.child.expect_exact(self.keys)

        if seen == 3:  # Bad key in known_hosts (conflict)
            lines = self.child.before
            if type(lines) is not list:  # Force list
                lines = lines,

            ip_addr = None
            for line in lines:
                self.f.write(line)
                match = re.search("differs from the key for the IP address '(.+)'", line)
                if match:
                    ip_addr = match.group(1)

            if ip_addr is None:
                print 'Bad address format'
                sys.exit(1)

            if handle_known_hosts:
                self.remove_known_hosts_entry(ip_addr)
                print "Executing %s " % command
                self.child = spawn(command)
                seen = self.child.expect_exact(self.keys)

        if seen == 0:  # 'yes' is required
            self.child.sendline('yes')
            seen = self.child.expect_exact(self.keys)

        if seen == 1:  # Password is expected
            if not self.password:
                self.password = getpass.getpass('Remote password: ')

            self.child.sendline(self.password)

            if not interactive:
                self.child.readline()
                time.sleep(5)
                # Added to allow the background running of remote process
                if not self.child.isalive():
                    seen = self.child.expect_exact(self.keys)

        elif seen > 6:  # Errors
            if seen != 10 or interactive:  # non-interactive + EOF is ok
                print "FATAL ERROR ({}). Please review the output:".format(seen)
                print self.child.before, self.child.after

        if self.verbose:
            sys.stderr.write("<- " + self.child.before + "|\n")

        try:
            self.f.write(str(self.child.before) + str(self.child.after)+'\n')
        except Exception:
            pass

        self.f.close()
        return self.child

    def ssh(self, command=None, handle_known_hosts=False, force_interact=None):
        if force_interact is not None:
            interactive = force_interact
        elif command is None:  # We're looking for a shell
            interactive = True
        else:  # Assume we want to run the command and quit
            interactive = False

        key_arg = ""
        if keyfile:
            key_arg = "-i %s" % keyfile
        sshcmd = "ssh %s -t -l %s %s" % (key_arg, self.user, self.host)
        if command is not None:
            sshcmd = "%s \"%s\"" % (sshcmd, command)

        self.child = self.__exec(sshcmd, handle_known_hosts=handle_known_hosts,
                                 interactive=interactive)

        if interactive:
            signal.signal(signal.SIGWINCH, self.sigwinch_passthrough)
            self.resize_term()
            self.child.interact()

        return self.child.after

    def scp(self, src, dst, handle_known_hosts=False):
        key_arg = ""
        if keyfile:
            key_arg = "-i %s" % keyfile

        return self.__exec("scp {} {} {}@{}:{}".format(
            key_arg, src, self.user, self.host, dst), handle_known_hosts)

    def copy_id(self, identity_file, handle_known_hosts=False):
        return self.__exec("ssh-copy-id -i {} {}@{}" % (
            identity_file, self.user, self.host), handle_known_hosts)

    def exists(self, file):
        """Retrieve file permissions of specified remote file."""
        seen = self.ssh("/bin/ls -ld %s" % file)
        if string.find(seen, "No such file") > -1:
            return None  # File doesn't exist
        else:
            return seen.split()[0]  # Return permission field of listing.

    def remove_known_hosts_entry(
            self, host, known_hosts_file='~/.ssh/known_hosts', tmpfile=None):
        known_hosts_file = os.path.expanduser(known_hosts_file)
        print "Removing bad host entry (%s) from %s" % (host, known_hosts_file)
        if tmpfile is None:
            tmpfile = '/tmp/ssh_known_hosts-'+str(os.getpid())
        dstfd = open(tmpfile, "w")
        srcfd = open(known_hosts_file, "r")
        for line in srcfd:
            # TODO: fix X.X.X.1 matching X.X.X.1nn
            match = re.search(host, line)
            if (match is None):
                dstfd.write(line)
            else:
                print "REMOVING LINE: %s" % line
        dstfd.close()
        srcfd.close()
        shutil.move(tmpfile, known_hosts_file)


def testssh(user, host, password):
    s = SshSession(user, host, password=password)
    s.ssh(handle_known_hosts=True)


def usage(msg='', errno=0):
    print msg + """
Usage:
    """ + myname + """ [-l <user>] [-p <password>] [-e <cmd>] [-v] [-i] [user@]<host>

Where:
    Mandatory parameters:
    host - remote host to connect to

    Optional parameters:
    -l - user to Login with (default: """ + user + """)
    -p|--password - Password to specify
    -e - Execute command
    -i - force Interactive mode, useful in combination with -e
    -k - public Key
    -v - Verbose
    -h - print this Help message
"""

    sys.exit(errno)


def parse_params():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hil:p:e:k:v", ["password="])
    except getopt.GetoptError as err:
        print str(err)  # will print something like "option -a not recognized"
        usage(errno=2)

    if len(sys.argv) < 2:
        usage(msg="Missing parameters", errno=2)

    global keyfile
    global host
    global user
    global password
    global rcmd
    global verbose
    global force_interact
    for o, a in opts:
        if o == "-h":
            usage(msg="%s specified" % o)
        elif o in ("-i"):
            force_interact = True
        elif o in ("-k"):
            keyfile = a
        elif o in ("-l"):
            user = a
        elif o in ("-p", "--password"):
            password = a
        elif o in ("-e"):
            rcmd = a
        elif o in ("-v"):
            verbose = True

    host = args[0]
    if host is None:
        usage(msg="Mandatory parameter 'host' not specified", errno=2)

    if re.search('@', host):
        user, host = host.split('@')


if __name__ == "__main__":
    parse_params()
    s = SshSession(user, host, password=password, verbose=verbose)
    s.ssh(command=rcmd, handle_known_hosts=True, force_interact=force_interact)
