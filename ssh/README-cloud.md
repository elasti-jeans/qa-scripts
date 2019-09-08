== Description ==
ssh2cloud.py allow you to connect to a cluster node by cluster id and node type


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
        # Connect to the first loader node on setup 934
        ssh2cloud.py 934 -l0
        # Skipping the id part will connect to the first node (id=0) of the requested type - same as above
        ssh2cloud.py 934 -l
        # Clear cached json and connect to loader #5 on setup 934
        ssh2cloud.py 934 -c -l 5

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
  -u USER_NAME, --user USER_NAME
                        Node user name
  -p PASSWORD, --password PASSWORD
                        Node user's password
  -k, --add_key         Add your public key to all vHeads
  -i PUBLIC_KEY, --identity_file PUBLIC_KEY
                        Identity (public key) file
  -P, --customize_prompt
                        Customize prompt on remote hosts
  -c, --clear_cache     Clear cached json for the specified setup id

