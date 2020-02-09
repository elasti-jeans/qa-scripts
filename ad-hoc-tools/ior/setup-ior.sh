#!/usr/bin/bash -e

# Configurable parameters
: ${NFS_SERVER_EXPORT:=10.255.255.1:/dc1/root}
: ${LOADERS:="172.16.210.2 172.16.210.3 172.16.210.4"}
: ${OUTPUT_FILE:="/tmp/ior-setup.log"}

: ${IOR_REPO:="https://github.com/hpc/ior"}
: ${IOR_BRANCH:="master"}
: ${MOUNT_POINT:="/mnt/ior"}

# Internal parameters
: ${FIRST_RUN:=true}

TOOL_NAME=$(basename ${IOR_REPO})

function logme {
    echo "=== $(date) $* ==="
}

if [ "$FIRST_RUN" == true ]; then
    logme "Installing dependencies"
    for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i sudo yum -y install git make automake gcc mpich-devel bc & done; wait
fi

logme "Updating PATH on the loaders"
STARTUP_SCRIPT=~/.bashrc
for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i "grep -q /usr/lib64/mpich/bin $STARTUP_SCRIPT || echo 'PATH=$PATH:/usr/lib64/mpich/bin' >> $STARTUP_SCRIPT"; done

logme "Updating LD_LIBRARY_PATH on the loaders"
for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i "export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/lib64/mpich/lib && sudo ldconfig"; done

logme "Mounting export on loaders ${LOADERS}"
for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i sudo mkdir -p ${MOUNT_POINT}; done
for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i sudo umount ${MOUNT_POINT}; done || true
for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i sudo mount ${NFS_SERVER_EXPORT} ${MOUNT_POINT}; done
mountpoint ${MOUNT_POINT}

if [ "$FIRST_RUN" == true ]; then
    if [ -d "${TOOL_NAME}" ]; then
        logme "Removing existing dir ${TOOL_NAME}"
        rm -rf "${TOOL_NAME}"
    fi
    logme "Cloning ${IOR_REPO} repo"
    git clone --depth=1 ${IOR_REPO} -b ${IOR_BRANCH}
fi

logme "Copying the tool to ${MOUNT_POINT}"
if [ "$FIRST_RUN" == true ]; then
    sudo chmod 777 ${MOUNT_POINT}
    cp -r "${TOOL_NAME}" ${MOUNT_POINT}/
fi
pushd "${MOUNT_POINT}/${TOOL_NAME}"

CHECK_SSH_SCRIPT=check_ssh.sh
echo 'for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i hostname; done' > ${CHECK_SSH_SCRIPT}
chmod +x ${CHECK_SSH_SCRIPT}
for i in ${LOADERS}; do
    logme "Checking SSH connectivity from $i"
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i "LOADERS=\"${LOADERS}\" ${MOUNT_POINT}/${TOOL_NAME}/${CHECK_SSH_SCRIPT}"
done

if [ "$FIRST_RUN" == true ]; then
    logme "Setting up io500"
    for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i "cd ${MOUNT_POINT}/${TOOL_NAME} && utilities/prepare.sh"; done
fi

popd

if [ "${EXIT_CODE}" -eq 0 ]; then
    logme "Test run successful"
    logme "Unmounting ${MOUNT_POINT}"
    for i in ${LOADERS}; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes $i sudo umount ${MOUNT_POINT}; done
else
    logme "Test run has failed with exit code ${EXIT_CODE}"
    echo "Please examine the following logs:"
    ls -1 "$(ls -1trd ${MOUNT_POINT}/${TOOL_NAME}/results/* | tail -1)"/*
fi

exit ${EXIT_CODE}
