#!/bin/bash

################################################################################
# Copyright (c) 2023 Microsoft Corporation
################################################################################

#usage: run sudo ./add_sk_to_initramfs.sh <path_to_optee>
export OPTEE_DIR=$1
export SKERNEL_FILE="$1/out/core/tee.bin"
export SKERNEL_FILE_ABSPATH="$(readlink -f $SKERNEL_FILE)"
export SKERNEL_HOOK_FILE="/usr/share/initramfs-tools/hooks/skernel"

# If tee.bin file does not exist, exit
if [[ ! -f $SKERNEL_FILE ]]
then
   echo "Error: $1 file does not exist."
   echo "Compile optee-os first via build_vsm_optee and then re-try."
   exit 0
fi

# If hook script file does not already exist, create it and set its permissions
if [[ ! -f $SKERNEL_HOOK_FILE ]]
then
   touch $SKERNEL_HOOK_FILE
   chmod 755 $SKERNEL_HOOK_FILE
fi

# Copy mkinitramfs hook script to add tee.bin to initramfs
cat > $SKERNEL_HOOK_FILE <<EOF
#!/bin/sh

PREREQ=""
prereqs()
{
   echo "\$PREREQ"
}

case \$1 in
prereqs)
   prereqs
   exit 0
   ;;
esac

. /usr/share/initramfs-tools/hook-functions
# Begin real processing below this line

cp $SKERNEL_FILE_ABSPATH "\${DESTDIR}/lib/firmware"

exit 0
EOF
