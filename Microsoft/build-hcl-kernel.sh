#!/bin/bash

usage() {
	>&2 echo "Try $0 --help for more information."
	exit 1
}

O=`getopt -n "$0" -l help -- nh "$@"` || usage
eval set -- "$O"

builds=()
build_init=
desc=()
clean=1

while true; do
	case "$1" in
		-n)
			clean=
			shift
			;;
		--)
			shift
			break
			;;
		-h|--help)
			echo "Usage: $0 [-n] [BUILD ...]"
			echo ""
			echo "  Builds everything by default."
			echo ""
			echo "  -n: Do not clean before building"
			echo ""
			echo "  Available builds:"
			echo "    dev"
			echo "    ship"
			echo "    dev-mlx"
			echo "    ship-mlx"
			echo "    init"
			echo ""
			exit
			;;
		*)
			usage
			;;
	esac
done

if [ $# == 0 ]; then
	builds=(dev ship dev-mlx5 ship-mlx5)
	build_init=1
	desc=("dev" "ship" "Mellanox5 dev" "Mellanox5 ship")
else
	while [ $# != 0 ]; do
		case "$1" in
			dev)
				builds+=(dev)
				desc+=("dev")
				;;
			ship)
				builds+=(ship)
				desc+=("ship")
				;;
			dev-mlx)
				builds+=(dev-mlx5)
				desc+=("Mellanox5 dev")
				;;
			ship-mlx)
				builds+=(ship-mlx5)
				desc+=("Mellanox5 ship")
				;;
			init)
				build_init=1
				;;
			*)
				>&2 echo "Unknown build type: $1"
				usage
				;;
		esac
		shift
	done
fi

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SRC_DIR=`realpath ${SCRIPT_DIR}/..`

build_kernel() {
	if [ -n "$clean" ]; then
		make mrproper
	fi
	export KCONFIG_CONFIG=$LINUX_SRC/Microsoft/hcl-${BUILD_TYPE}.config
	# For the verbose build
	#make SHELL='sh -x' ARCH=x86_64 -j `nproc` 2> ${BUILD_DIR}/hcl-build-verbose.log
	make ARCH=x86_64 -j `nproc` olddefconfig vmlinux
	cp $LINUX_SRC/Microsoft/hcl-${BUILD_TYPE}.config $OUT_DIR
	objcopy --only-keep-debug --compress-debug-sections $KBUILD_OUTPUT/vmlinux $BUILD_DIR/vmlinux-${BUILD_TYPE}.debug
	strip $KBUILD_OUTPUT/vmlinux -o $BUILD_DIR/vmlinux-${BUILD_TYPE}
	objcopy --add-gnu-debuglink=$BUILD_DIR/vmlinux-${BUILD_TYPE}.debug $BUILD_DIR/vmlinux-${BUILD_TYPE}
	cp $BUILD_DIR/vmlinux-${BUILD_TYPE} $OUT_DIR
	cp $BUILD_DIR/vmlinux-${BUILD_TYPE}.debug $OUT_DIR
	cp $LINUX_SRC/Microsoft/hcl-${BUILD_TYPE}.config $OUT_DIR
}

LINUX_SRC=$SRC_DIR
BUILD_DIR=`realpath $LINUX_SRC/../build`
OUT_DIR=`realpath $LINUX_SRC/out`

export KBUILD_OUTPUT=$BUILD_DIR/linux
export HCL_INIT=${BUILD_DIR}/hcl-init
export UNDERHILL=/dev/null

if [ -n "$clean" ]; then
	rm -rf $KBUILD_OUTPUT
	rm -rf $OUT_DIR
fi

mkdir -p $KBUILD_OUTPUT
mkdir -p $OUT_DIR

cd $LINUX_SRC

cp $SCRIPT_DIR/HCL-HOWTO.md $OUT_DIR
cp $SCRIPT_DIR/*.cpio.gz $OUT_DIR
cp $SCRIPT_DIR/*.config $OUT_DIR

for b in ${!builds[@]}
do
	echo "Building ${desc[b]} kernel..."
	BUILD_TYPE=${1:-${builds[b]}}
	build_kernel
done

if [ -n "$build_init" ]; then
	echo "Building init"

	INCLUDE_DIR="-I${BUILD_DIR}/include -I${LINUX_SRC}/include -I${LINUX_SRC}/arch/x86/include -I${KBUILD_OUTPUT}/include"
	klcc ${INCLUDE_DIR} ${SCRIPT_DIR}/hcl-init.c -o ${BUILD_DIR}/hcl-init
	cp ${BUILD_DIR}/hcl-init ${BUILD_DIR}/hcl-init.unstripped

	execstack -c ${BUILD_DIR}/hcl-init
	strip ${BUILD_DIR}/hcl-init
	cp $BUILD_DIR/hcl-init $OUT_DIR
	cp $BUILD_DIR/hcl-init.unstripped $OUT_DIR
fi

echo "Installing headers to ${BUILD_DIR}"
rm -rf $BUILD_DIR/include
make headers_install ARCH=x86_64 INSTALL_HDR_PATH=${BUILD_DIR} -j `nproc` > /dev/null
