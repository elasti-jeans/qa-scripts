#!/bin/bash

MYNAME=$(basename $0)
MYDIR=$(dirname $0)

: ${SESSION_ID:=$$}
: ${OUTPUT_DIR:=/tmp/${MYNAME}.out/${SESSION_ID}}
: ${CLUSTERS_DIR:=${MYDIR}/default_clusters}
: ${MOUNT_DIR:=/mnt/parallel}
: ${REMOTE_USER:="centos"}
: ${IDENTITY_FILE:=~/.ssh/elastifile.pem}
: ${SSH_CONF_FILE:=/tmp/ssh-conf}

: ${OUTPUT_DIR_COUNTER:=0}

function logme() {
    echo ===== $(date) $@ | tee -a ${OUTPUT_DIR}/progress.log
}

function assert() {
    local EXIT_CODE=$1
    shift
    local MSG=$@

    if [ "$EXIT_CODE" -gt 0 ]; then
        logme $@
        exit $EXIT_CODE
    fi
}

function run_parallel() {
    local LOADERS="$1"
    shift
    local CMD=$@

    OUTPUT_DIR_ITERATION="${OUTPUT_DIR}/${OUTPUT_DIR_COUNTER}"
    OUTPUT_DIR_COUNTER=$((OUTPUT_DIR_COUNTER+1))
    mkdir -p $OUTPUT_DIR_ITERATION

    logme "[${OUTPUT_DIR_ITERATION}] Running $CMD"
    pssh -t 0 -o $OUTPUT_DIR_ITERATION -x "-o StrictHostKeyChecking=no -i $IDENTITY_FILE" -i -H "$LOADERS" -l ${REMOTE_USER} "$CMD"
}

function check_exit_code () {
    local ACTUAL=$1
    local EXPECTED=$2
    shift; shift
    if [ "${ACTUAL}" -ne "${EXPECTED}" ]; then
        logme "Actual exit code (${ACTUAL}) doesn't match the expected one (${EXPECTED})"
        exit 1
    fi
}

if [ ! -f "$SSH_CONF_FILE" ]; then
    logme "SSH config file ($SSH_CONF_FILE) is missing - creating..."
    cat > $SSH_CONF_FILE <<EOF
Host *
    IdentityFile $IDENTITY_FILE
EOF
fi

mkdir -p ${OUTPUT_DIR}
assert $? "Failed to create directory ${OUTPUT_DIR}"

test -f "${IDENTITY_FILE}"
assert $? "Identity file not found - ${IDENTITY_FILE}"

CLUSTERS=$(ls -1 $CLUSTERS_DIR)
logme "Running on clusters: $CLUSTERS"

LOADERS=$(for f in $(ls -1 $CLUSTERS_DIR/*); do cat $f | jq -r ".loaders[]|.ip"; done | xargs)
logme "All loaders: $LOADERS"

run_parallel "$LOADERS" "mountpoint $MOUNT_DIR && sudo umount $MOUNT_DIR"
# The above command is expected to fail on the first run

run_parallel "$LOADERS" sudo mkdir -p $MOUNT_DIR
assert $? "Failed to create $MOUNT_DIR on the loaders"

run_parallel "$LOADERS" sudo chmod 777 $MOUNT_DIR
assert $? "Failed to chmod $MOUNT_DIR on the loaders"

logme "Mounting clusters sequentially"
for f in $(ls -1 $CLUSTERS_DIR/*); do
    SINGLE_CLUSTER_LOADERS=$(cat $f | jq -r ".loaders[]|.ip" | xargs)
    EXPORT=$(cat $f | jq -jr '.mntPoint')
    logme "Mounting cluster $(basename $f) $EXPORT on loaders $SINGLE_CLUSTER_LOADERS"
    run_parallel "$SINGLE_CLUSTER_LOADERS" sudo mount $EXPORT $MOUNT_DIR
    assert $? "Failed to mount $EXPORT on $SINGLE_CLUSTER_LOADERS:$MOUNT_DIR (from $f)"
done

logme "Killing elfs sequentially"
for f in $(ls -1 $CLUSTERS_DIR/*); do
    # This will result in lockdown
    #SINGLE_CLUSTER_VHEADS=$(cat $f | jq -r ".vheads_list[]|.ip" | xargs)
    #run_parallel "$SINGLE_CLUSTER_VHEADS" sudo systemctl kill -s 11 elfs
    #assert $? "Failed to kill ECS on $EMANAGE_SERVERS"

    EMANAGE=$(cat $f | jq -jr ".ems_ip")
    VHEAD=$(cat $f | jq -jr ".vheads_list[0].ip")
    CMD="ssh -F ${SSH_CONF_FILE} -o StrictHostKeyChecking=no -i ${IDENTITY_FILE} -J ${REMOTE_USER}@${EMANAGE} ${REMOTE_USER}@${VHEAD} sudo systemctl kill -s 11 elfs"
    logme "Running command: ${CMD}"
    ${CMD}
    assert $? "Command failed: ${CMD}"
done

run_parallel "$LOADERS" dd if=/dev/zero bs=4K count=1 of=$MOUNT_DIR/data_file
assert $? "Failed writing to the mount"


logme "Finished. Please review the results under $OUTPUT_DIR"

