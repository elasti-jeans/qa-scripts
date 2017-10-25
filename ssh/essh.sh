#!/bin/bash

# Connect to a node based on CID (test setup) and node description

MYNAME=$(basename $0)
MYDIR=$(dirname $0)

VERBOSE=0
CLEAR_CACHE=0

function usage {
    msg=$1
    err=$2
    if [ x"$1" != x ]; then
        echo "Error: $msg"
    fi
    cat <<END_OF_USAGE
    Usage: $MYNAME [-v] [-C] <CID> [ss2env.py args]
    Where:
        -C - Clear Cached json
        -v - Verbose
    Examples:
        # Connect to emanage 0 on setup 208
        $MYNAME 208 -e0
        # Clear cached json and connect to loader 5 on setup 208
        $MYNAME -C 30 -l5
END_OF_USAGE

    exit $err
}

function logme {
    msg=$*
    if [ $VERBOSE == 1 ]; then
        echo $(date '+%Y-%m-%d %H:%M:%S') === $msg
    fi
    logger -t $MYNAME "$msg"
}

function exec_cmd () {
    cmd=$*
    logme "Executing: $cmd"
    $cmd
    rv=$?
    if ((rv != 0)); then
        logme "Command execution failed with exit code: $rv"
    else
        logme Command executed successfully
    fi
    return $rv
}

while getopts "vC" opt; do
    echo PROCESSING OPT $opt
    case $opt in
    v)
        VERBOSE=1;;
    C)
        CLEAR_CACHE=1;;
    *)
        usage;;
    esac
done

shift $((OPTIND-1))
CID=$1
shift

if [ "x$CID" == "x" ]; then
    usage "Missing arguments" 2
fi

CONF=$MYDIR/$CID
if [ $CLEAR_CACHE -eq 1 ]; then
    exec_cmd rm -f $CONF
fi

if [ ! -f $CONF ]; then
    exec_cmd wget -P $MYDIR http://elab.il.elastifile.com/api/v1/system/cluster/$CID
fi

$MYDIR/ssh2env.py $@ $MYDIR/$CID

