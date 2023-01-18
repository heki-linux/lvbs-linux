#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sched.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/klog.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#include "hcl-tests.h"

u64 set_reg_hvcall(int hcl_fd, const struct hcl_setup_hvcalls_t *setup_hvcalls,
    const struct hcl_set_vp_gp_register_t* set_reg, u64 count)
{
    struct hcl_hvcall_t hvcall;

	u64 hypercall_status;
	u64 control;
	u16 rep_comp;
	u64 i;

	struct hv_set_vp_registers *input_page;

	if (count > HV_PAGE_SIZE/sizeof(struct hv_register_assoc)) {
		printf("attempt to set %ld registers, that's too many\n", count);
        abort();
	}

	input_page = (struct hv_set_vp_registers *)setup_hvcalls->input_page;

	input_page->partition_id = HV_PARTITION_ID_SELF;
	input_page->vp_index = HV_VP_INDEX_SELF;
	input_page->input_vtl.as_uint8 = 0;
	input_page->input_vtl.use_target_vtl = 1;
	input_page->rsvd_z8 = 0;
	input_page->rsvd_z16 = 0;

	for (i = 0; i < count; ++i) {
		input_page->elements[i] = set_reg[i].register_assoc;
	}

	control = (count << HV_HYPERCALL_REP_COMP_OFFSET) | HVCALL_SET_VP_REGISTERS;
	rep_comp = 0;

    hvcall.control = control;

	do {
        int err;

        err = ioctl(hcl_fd, IOCTL_HCL_HVCALL, &hvcall);
        if (err) {
            printf("ioctl failed (%d)\n", err);
            abort();
        }
		hypercall_status = hvcall.status;

		if ((hypercall_status & HV_HYPERCALL_RESULT_MASK) != HV_STATUS_SUCCESS) {
			printf("set_reg, completed %d, error: 0x%lx\n", rep_comp, hypercall_status);
            abort();
		}

		rep_comp = (hypercall_status & HV_HYPERCALL_REP_COMP_MASK) >>
			HV_HYPERCALL_REP_COMP_OFFSET;

		control &= ~HV_HYPERCALL_REP_START_MASK;
		control |= (u64)rep_comp << HV_HYPERCALL_REP_START_OFFSET;
	} while (rep_comp < count);

    return hvcall.status;
}

u64 get_reg_hvcall(int hcl_fd, const struct hcl_setup_hvcalls_t *setup_hvcalls, 
    struct hcl_get_vp_gp_register_t* get_reg)
{
    struct hcl_hvcall_t hvcall;
    int err;

	u64 hypercall_status;
	u64 control;

	struct hv_get_vp_registers *input_page;
	union hv_register_value *output_page;

	input_page = (struct hv_get_vp_registers *)setup_hvcalls->input_page;

	input_page->partition_id = HV_PARTITION_ID_SELF;
	input_page->vp_index = HV_VP_INDEX_SELF;
	input_page->input_vtl.as_uint8 = 0;
	input_page->input_vtl.use_target_vtl = 1;
	input_page->rsvd_z8 = 0;
	input_page->rsvd_z16 = 0;

	input_page->names[0] = get_reg->register_assoc.name;

	output_page = (union hv_register_value *)setup_hvcalls->output_page;

	// The get VP reg's rep. hypercall for one items
	control = (1ULL << HV_HYPERCALL_REP_COMP_OFFSET) | HVCALL_GET_VP_REGISTERS;

    hvcall.control = control;
    err = ioctl(hcl_fd, IOCTL_HCL_HVCALL, &hvcall);
    if (err) {
        printf("ioctl failed (%d)\n", err);
        abort();
    }
    hypercall_status = hvcall.status;

	if ((hypercall_status & HV_HYPERCALL_RESULT_MASK) != HV_STATUS_SUCCESS) {
		printf("get_reg, register %#08x, error: 0x%lx\n", get_reg->register_assoc.name, hypercall_status);
        abort();
	}

	get_reg->register_assoc.value = *output_page;

    return hvcall.status;
}

void test_hvcalls(void)
{
    struct hcl_set_vp_gp_register_t set_reg;
    struct hcl_get_vp_gp_register_t get_reg;

    struct hcl_setup_hvcalls_t setup_hvcalls;
	u64 mask;
    long err;
    int hcl;

    puts("* Affinitize");

    mask = 1;
	err = sched_setaffinity(getpid(), sizeof(mask), &mask);
    if (err < 0) {
        printf("sched_setaffinity failed (%ld)\n", err);
        abort();
    }

    puts("* Open HCL");

    hcl = open("/dev/hcl", O_RDWR);
    if (hcl < 0) {
        printf("opening HCL failed (%d)\n", errno);
        abort();
    }

    puts("* ioctl to setup hvcalls");

    memset(&setup_hvcalls, 0, sizeof(setup_hvcalls));
    memset(&set_reg, 0, sizeof(set_reg));
    memset(&get_reg, 0, sizeof(get_reg));

    err = ioctl(hcl, IOCTL_HCL_SETUP_HVCALLS, &setup_hvcalls);
    if (err) {
        printf("ioctl failed (%ld)\n", err);
        abort();
    }

    printf("Input page %p, output page %p\n", 
        setup_hvcalls.input_page,
        setup_hvcalls.output_page);

    set_reg.register_assoc.name = hv_x64_register_rsp;
    set_reg.register_assoc.value.reg64 = 0xababababababULL;
    set_reg_hvcall(hcl, &setup_hvcalls, &set_reg, 1);

    get_reg.register_assoc.name = set_reg.register_assoc.name;
    get_reg_hvcall(hcl, &setup_hvcalls, &get_reg);

    if (set_reg.register_assoc.value.reg64 != get_reg.register_assoc.value.reg64) {
        printf("Register values do not match: %lx != %lx\n",
            set_reg.register_assoc.value.reg64, 
            get_reg.register_assoc.value.reg64);
        abort();
    }

    printf("%s passed\n", __func__);
}

int main()
{
    test_hvcalls();

    return 0;
}
