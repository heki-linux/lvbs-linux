#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SRC_DIR=`realpath ${SCRIPT_DIR}/..`

# May be 'ship' for the release build
BUILD_TYPE=${1:-dev}

LINUX_SRC=$SRC_DIR
BUILD_DIR=`realpath $LINUX_SRC/../build`
OUT_DIR=`realpath $LINUX_SRC/out`

echo "Building tests"

INCLUDE_DIR="-I${BUILD_DIR}/include -I${LINUX_SRC}/include -I${LINUX_SRC}/arch/x86/include -I${BUILD_DIR}/linux/include"
klcc ${INCLUDE_DIR} ${SCRIPT_DIR}/hcl-tests.c -o ${BUILD_DIR}/hcl-tests
cp ${BUILD_DIR}/hcl-tests ${BUILD_DIR}/hcl-tests.unstripped

execstack -c ${BUILD_DIR}/hcl-tests
strip ${BUILD_DIR}/hcl-tests

rm ./tests.cpio.gz
./gen_init_ramfs.py ./hcl-rootfs-tests.config ./tests.cpio.gz
