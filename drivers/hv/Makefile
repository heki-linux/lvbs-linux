# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_HYPERV)		+= hv_vmbus.o
obj-$(CONFIG_HYPERV_VMM_API)	+= mshv.o
obj-$(CONFIG_HYPERV_UTILS)	+= hv_utils.o
obj-$(CONFIG_HYPERV_BALLOON)	+= hv_balloon.o
obj-$(CONFIG_DXGKRNL)		+= dxgkrnl/

CFLAGS_hv_trace.o = -I$(src)
CFLAGS_hv_balloon.o = -I$(src)

mshv-y				+= mshv_main.o hv_call.o hv_synic.o hv_portid_table.o \
				   hv_eventfd.o mshv_msi.o vfio.o
obj-$(CONFIG_MSHV_XFER_TO_GUEST_WORK) += xfer_to_guest.o
hv_vmbus-y := vmbus_drv.o \
		 hv.o connection.o channel.o \
		 channel_mgmt.o ring_buffer.o hv_trace.o
hv_vmbus-$(CONFIG_HYPERV_TESTING)	+= hv_debugfs.o
hv_utils-y := hv_util.o hv_kvp.o hv_snapshot.o hv_fcopy.o hv_utils_transport.o

# Code that must be built-in
obj-$(subst m,y,$(CONFIG_HYPERV)) += hv_common.o
