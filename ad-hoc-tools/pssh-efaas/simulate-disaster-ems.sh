#!/bin/bash

MYNAME=$(basename $0)
MYDIR=$(dirname $0)

: ${SESSION_ID:=$$}
: ${OUTPUT_DIR:=/tmp/${MYNAME}.out/${SESSION_ID}}
: ${CLUSTERS_DIR:=${MYDIR}/default_clusters}
: ${MOUNT_DIR:=/mnt/parallel}
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
    pssh -t 0 -o $OUTPUT_DIR_ITERATION -x "-o StrictHostKeyChecking=no -i $IDENTITY_FILE" -i -H "$LOADERS" -l centos "$CMD"
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

EMANAGE_SERVERS=$(for f in $(ls -1 $CLUSTERS_DIR/*); do cat $f | jq -r ".ems_ip"; done | xargs)
for f in $(ls -1 test_clusters/*); do cat $f | jq -r ".ems_ip"; done | xargs
logme "All management servers: $EMANAGE_SERVERS"

logme "Checking connectivity"
run_parallel "$EMANAGE_SERVERS" hostname
assert $? "Connectivity check failed"

run_parallel "$EMANAGE_SERVERS" sudo systemctl kill -s 11 ecs
assert $? "Failed to kill ECS on $EMANAGE_SERVERS"

PSSH_REMOTE_COMMAND_FAILED=5
run_parallel "$EMANAGE_SERVERS" sudo systemctl status ecs
check_exit_code $? ${PSSH_REMOTE_COMMAND_FAILED}

#assert $? "Failed to get ECS status on $EMANAGE_SERVERS"

DELAY=30
logme "Waiting for ${DELAY}"
sleep ${DELAY}

run_parallel "$EMANAGE_SERVERS" sudo systemctl status ecs
check_exit_code $? 0

logme "Finished. Please review the results under $OUTPUT_DIR"

