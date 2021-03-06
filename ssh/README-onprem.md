== Description ==
Connect to a setup node (or all nodes) by cluster id on eLab
You can either connect to a single node by specifying its type and, optionally, id.
Alternatively, you can open connections to all the nodes using a single command.
On Linux, gnome-terminal is used.
On OSX, iTerm is used if available, and Terminal if not.

IMPORTANT:
You won't be able to connect to vHeads w/o placing your public key there.
This operation is only needed once per setup, and is performed by passing -k.

NOTE:
You can set a custom prompt with date and exit code by passing -P.
This can take a few moments, and is only needed once per setup.

== Requirements ==

- Install pexpect
sudo easy_install pexpect

- Make sure you have a key ready to be used, e.g. ~/.ssh/id_rsa.pub
# If you don't, run ssh-keygen to create one

== Usage ==

    Examples:
        # Classic first connection - will fetch the configuration from eLab, place your key on vheads, update the prompt, and open a session to each node in setup 208
        ssh2env.py 208 -ckP
        # Classic connection once the keys are in place - will open a session to each node in setup 208
        ssh2env.py 208
        # Connect to the first emanage node on setup 208
        ssh2env.py 208 -e0
        # Skipping the id part will connect to the first node (id=0) of the requested type - same as above
        ssh2env.py 208 -e
        # Clear cached json and connect to loader #5 on setup 208
        ssh2env.py 208 -c -l5
        # Disable split-tab mode in iTerm2
        ssh2env.py 208 -S
        # Enable voice messages
        ssh2env.py 208 --voice

usage: ssh2env.py [-h] [-l [LOADER_ID] | -e [EMANAGE_ID] | -v [VHEAD_ID] | -f
                  | -a] [-u USER_NAME] [-p PASSWORD] [-k] [-i PUBLIC_KEY]
                  [-m MAC_TERM] [-S] [--voice] [-P] [-c]
                  setup_id

Connect to all test setup's nodes or to one node specified by type [and id]

positional arguments:
  setup_id              Numeric test setup id

optional arguments:
  -h, --help            show this help message and exit
  -l [LOADER_ID], --loader [LOADER_ID]
                        Loader id
  -e [EMANAGE_ID], --emanage [EMANAGE_ID]
                        eManage id
  -v [VHEAD_ID], --vhead [VHEAD_ID]
                        vHead id
  -f, --floating_ip     eManage VIP
  -a, --all             Connect to all nodes
  -u USER_NAME, --user USER_NAME
                        Node user name
  -p PASSWORD, --password PASSWORD
                        Node user's password
  -k, --add_key         Add your public key to all vHeads
  -i PUBLIC_KEY, --identity_file PUBLIC_KEY
                        Identity (public key) file
  -m MAC_TERM, --mac_term MAC_TERM
                        Override OS X Terminal emulator detection
                        (iTerm/Terminal)
  -S, --iterm_no_split  (iTerm only) Don't split sessions by node type
  --voice               Issue sound alerts
  -P, --customize_prompt
                        Customize prompt on remote hosts
  -c, --clear_cache     Clear cached json for the specified setup id

