Secure linux kernel to run in VTL1.

Secure kernel is loaded in binary format.

To build :

	make mshv_sk_defconfig

	make -j$(nproc --ignore 1) vmlinux

	objcopy -O binary -R .note -R .comment -S vmlinux vmlinux.bin

To clean:

	make clean

	or

	make distclean
