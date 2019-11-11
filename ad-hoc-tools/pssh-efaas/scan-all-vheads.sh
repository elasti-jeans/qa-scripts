#!/bin/bash
OUTPUT_DIR_ROOT=/tmp/output
CLUSTERS_DIR=./clusters
SSH_CONF=/tmp/ssh-conf
mkdir -p $OUTPUT_DIR_ROOT

if [ ! -f "$SSH_CONF" ]; then
    echo "SSH config file ($SSH_CONF) is missing - creating..."
    cat > $SSH_CONF <<EOF
Host *
    IdentityFile ~/.ssh/elastifile.pem
EOF
fi

for f in $(ls -1 $CLUSTERS_DIR/*); do
    EMANAGE=$(cat $f | jq -jr ".ems_ip")
    VHEADS=$(cat $f | jq -r ".vheads_list[]|.ip")
    OUTPUT_DIR=$OUTPUT_DIR_ROOT/$EMANAGE
    echo VHEADS: $VHEADS
    pssh -x "-F /tmp/sshconf.tmp -o StrictHostKeyChecking=no -i ~/.ssh/elastifile.pem -J centos@$EMANAGE" -l centos -H "$VHEADS" -o $OUTPUT_DIR hostname
    cat $OUTPUT_DIR/*
done

