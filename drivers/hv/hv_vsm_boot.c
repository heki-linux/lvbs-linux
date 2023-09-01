// SPDX-License-Identifier: GPL-2.0
/*
 * VSM boot framework that enables VTL1, loads secure kernel
 * and boots VTL1.
 *
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */

#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>
#include <linux/hyperv.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/securekernel_core.h>

#include "hv_vsm_boot.h"
#include "hv_vsm.h"

bool hv_vsm_boot_success = false;
struct vsm_ctx vsm;
struct file *sk_loader, *sk;

#ifdef CONFIG_HYPERV_VSM
static int vsm_arch_has_vsm_access(void)
{
	if (!(ms_hyperv.features & HV_MSR_SYNIC_AVAILABLE))
		return false;
	if (!(ms_hyperv.priv_high & HV_ACCESS_VSM))
		return false;
	if (!(ms_hyperv.priv_high & HV_ACCESS_VP_REGS))
		return false;
	return true;
}

static int hv_vsm_get_partition_status(u16 *enabled_vtl_set, u8 *max_vtl)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_vp_registers *hvin = NULL;
	union hv_register_value *hvout = NULL;
	union hv_register_vsm_partition_status vsm_partition_status = { 0 };

	local_irq_save(flags);

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	hvout = *this_cpu_ptr(hyperv_pcpu_output_arg);

	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->vp_index = HV_VP_INDEX_SELF;
	hvin->input_vtl.as_u8 = 0;
	hvin->reserved8_z = 0;
	hvin->reserved16_z = 0;
	hvin->names[0] = HvRegisterVsmPartitionStatus;

	status = hv_do_rep_hypercall(HVCALL_GET_VP_REGISTERS, 1, 0, hvin, hvout);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		return -EFAULT;

	vsm_partition_status = (union hv_register_vsm_partition_status)hvout->as_u64;
	*enabled_vtl_set = vsm_partition_status.enabled_vtl_set;
	*max_vtl = vsm_partition_status.max_vtl;
	return 0;
}

static int hv_vsm_get_vp_status(u16 *enabled_vtl_set)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_vp_registers *hvin = NULL;
	union hv_register_value *hvout = NULL;
	union hv_register_vsm_vp_status vsm_vp_status = { 0 };

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	hvout = *this_cpu_ptr(hyperv_pcpu_output_arg);

	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->vp_index = HV_VP_INDEX_SELF;
	hvin->input_vtl.as_u8 = 0;
	hvin->reserved8_z = 0;
	hvin->reserved16_z = 0;
	hvin->names[0] = HvRegisterVsmVpStatus;

	local_irq_save(flags);
	status = hv_do_rep_hypercall(HVCALL_GET_VP_REGISTERS, 1, 0, hvin, hvout);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		return -EFAULT;

	vsm_vp_status = (union hv_register_vsm_vp_status)hvout->as_u64;
	*enabled_vtl_set = vsm_vp_status.enabled_vtl_set;
	return 0;
}

#ifdef CONFIG_HYPERV_VSM_DEBUG
/* Walks page tables, starting at the PML4 (top level). */
static void hv_vsm_dump_pt(u64 root, int lvl)
{
	int n;

	u64 entry_pa;
	u64 *entry_va;
	u64 next_pa;

	if (lvl == 5)
		return;

	for (n = 0; n < VSM_ENTRIES_PER_PT; n++) {
		entry_pa = root + (n * sizeof(u64));
		entry_va = VSM_NON_LOGICAL_PHYS_TO_VIRT(entry_pa);

		if (*entry_va)
			pr_info("\t\t Entry: %i/%i - 0x%llx\n", n, lvl,
				*entry_va);

		if (*entry_va & VSM_PAGE_PRESENT) {
			next_pa = *entry_va & VSM_PAGE_BASE_ADDR_MASK;
			hv_vsm_dump_pt(next_pa, lvl + 1);
		}
	}
}

static void hv_vsm_dump_secure_kernel_memory(void)
{
	pr_info("%s: Dumping Secure Kernel Memory\n", __func__);
	print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS, 32, 4,
		(void *)vsm.skm_va, 1024, 0);
}
#endif

static __init void hv_vsm_boot_vtl1(void)
{
	unsigned long flags;
	struct vtlcall_param args = {0};

	local_irq_save(flags);
	hv_vsm_vtl_call(&args); // TODO: Change to Secure Kernel arch-agnostic
	local_irq_restore(flags);
}

static int __init hv_vsm_enable_partition_vtl(void)
{
	u64 status = 0;
	unsigned long flags;
	struct hv_input_enable_partition_vtl *hvin = NULL;

	local_irq_save(flags);

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->target_vtl = 1;
	hvin->flags.enable_mbec = 0;
	hvin->flags.reserved = 0;
	hvin->reserved16_z = 0;
	hvin->reserved32_z = 0;

	status = hv_do_hypercall(HVCALL_ENABLE_PARTITION_VTL, hvin, NULL);

	if (status)
		pr_err("%s: Enable Partition VTL failed. status=0x%x\n", __func__, hv_result(status));

	local_irq_restore(flags);

	return hv_result(status);
}

static int __init hv_vsm_reserve_sk_mem(void)
{
	void *va_start;
	struct page **page, **pages;
	unsigned long long paddr;
	unsigned long size;
	int i, npages;

	if (!securek_res.start) {
		pr_err("%s: No memory reserved in cmdline for secure kernel", __func__);
		return -ENOMEM;
	}
	vsm.skm_pa = securek_res.start;
	vsm.skm_va = 0;

	/* Allocate an array of struct page pointers  */
	npages = SK_MEM_SIZE >> PAGE_SHIFT;
	size = sizeof(struct page *) * npages;
	pages = vmalloc(size);

	if (!pages) {
		pr_err("%s: Allocating array of struct page pointers failed (Size: %lu)\n",
				__func__, size);
		return -ENOMEM;
	}

	/* Convert each page frame number to struct page.
	   Memory was allocated using memblock_phys_alloc_range() during boot */
	page = pages;
	paddr = securek_res.start;
	for (i = 0; i < npages; i++) {
		*page++ = pfn_to_page(paddr >> PAGE_SHIFT);
		paddr += PAGE_SIZE;
	}

	/* Map Secure Kernel physical memory into kernel virtual address space */
	va_start = vmap(pages, npages, VM_MAP, PAGE_KERNEL);

	if (!va_start) {
		pr_err("%s: Memory mapping failed\n", __func__);
		vfree(pages);
		return -ENOMEM; 
	}

	vsm.skm_va = va_start;

	pr_info("%s: secure kernel PA=0x%lx, VA=0x%lx\n",
			__func__, (unsigned long)vsm.skm_pa, (unsigned long)vsm.skm_va);

	memset(vsm.skm_va, 0, SK_MEM_SIZE);
	vfree(pages);
	return 0;
}

static void __init hv_vsm_init_cpu(struct hv_initial_vp_context *vp_ctx)
{
	/* Offset rip by any secure kernel header length */
	vp_ctx->rip = (u64)VSM_VA_FROM_PA(PAGE_AT(vsm.skm_pa,
		VSM_FIRST_CODE_PAGE));

	vp_ctx->cr0 =
		CR0_PG |	// Paging
		CR0_WP |	// Write Protect
		CR0_NE |	// Numeric Error
		CR0_ET |	// Extension Type
		CR0_MP |	// Math Present
		CR0_PE;		// Protection Enable

	vp_ctx->cr4 =
		CR4_PSE	|	// Page Size Extensions
		CR4_PGE	|	// Page Global Enable
		CR4_PAE;	// Physical Address Extensions

	vp_ctx->efer =
		MSR_LMA |	// Long Mode Active
		MSR_LME |	// Long Mode Enable
		MSR_NXE |	// No Execute Enable
		MSR_SCE;	// System Call Enable

	/*
	 * Intel CPUs fail if the architectural read-as-one bit 1 of RFLAGS is not
	 * set. See Intel SDM Vol 3C, 26.3.1.4 (RFLAGS).
	 *
	 * TODO: Has Hyper-V implemented setting this automatically?
	 */
	vp_ctx->rflags = 0b10;

	vp_ctx->msr_cr_pat =
		VSM_PAT(0, WB)       | VSM_PAT(1, WT) |
		VSM_PAT(2, UC_MINUS) | VSM_PAT(3, UC) |
		VSM_PAT(4, WB)       | VSM_PAT(5, WT) |
		VSM_PAT(6, UC_MINUS) | VSM_PAT(7, UC);

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s : Printing Initial VP Registers..\n", __func__);
	pr_info("\t\t RIP: 0x%llx\n", vp_ctx->rip);
	pr_info("\t\t CR0: 0x%llx\n", vp_ctx->cr0);
	pr_info("\t\t CR4: 0x%llx\n", vp_ctx->cr4);
	pr_info("\t\t EFER: 0x%llx\n", vp_ctx->efer);
	pr_info("\t\t RFLAGS: 0x%llx\n", vp_ctx->rflags);
	pr_info("\t\t CR PAT: 0x%llx\n", vp_ctx->msr_cr_pat);
#endif
}

static void __init hv_vsm_init_gdt(struct hv_initial_vp_context *vp_ctx)
{
	phys_addr_t gdt_pa;
	phys_addr_t tss_pa;
	phys_addr_t kstack_pa;

	union vsm_code_seg_desc cseg;
	union vsm_data_seg_desc dseg;
	union vsm_sys_seg_desc sseg;
	union vsm_tss *tss;

	u64 tss_sk_va;

	size_t cseg_sz = sizeof(cseg);
	size_t dseg_sz = sizeof(dseg);
	size_t sseg_sz = sizeof(sseg);
	size_t tss_sz = sizeof(*tss);

	size_t gdt_offset = 0;

	/* Get a page for the GDT */
	gdt_pa = PAGE_AT(vsm.skm_pa, VSM_GDT_PAGE);
	/* Get a page for the TSS */
	tss_pa = PAGE_AT(vsm.skm_pa, VSM_TSS_PAGE);
	tss = VSM_NON_LOGICAL_PHYS_TO_VIRT(tss_pa);
	/* Get a page for the secure kernel initial stack */
	kstack_pa = PAGE_AT(vsm.skm_pa, VSM_KERNEL_STACK_PAGE);

	/* Make and add the NULL descriptor to the GDT */
	cseg = MAKE_CSD_LM(0, 0, 0, 0);
	memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(gdt_pa + gdt_offset), &cseg, cseg_sz);
	gdt_offset += cseg_sz;

	/* Make and add a code segment descriptor to the GDT */
	cseg = MAKE_CSD_LM(0, 0, 1, 0);
	memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(gdt_pa + gdt_offset), &cseg, cseg_sz);
	gdt_offset += cseg_sz;

	/* Make and add a data segment descriptor to the GDT */
	dseg = MAKE_DSD_LM(1, 0);
	memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(gdt_pa + gdt_offset), &dseg, dseg_sz);
	gdt_offset += dseg_sz;

	/* Compute the VA that secure kernele will see for the TSS */
	tss_sk_va = VSM_VA_FROM_PA(tss_pa);

	/* Make and add a system segment descriptor for the TSS in the GDT */
	sseg = MAKE_SSD(
		tss_sz,
		tss_sk_va,
		VSM_SYSTEM_SEGMENT_TYPE_TSS,
		0,
		1,
		0,
		0,
		0,
		tss_sk_va >> 24);
	memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(gdt_pa + gdt_offset), &sseg, sseg_sz);
	gdt_offset += sseg_sz;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s: Printing GDT..\n", __func__);
	pr_info("\t\t 0: 0x%llx\n", (u64)0);
	pr_info("\t\t 1: 0x%llx\n", *(u64 *)&cseg);
	pr_info("\t\t 2: 0x%llx\n", *(u64 *)&dseg);
	pr_info("\t\t 3: 0x%llx\n", *(u64 *)&sseg);
#endif
	/* Set up the GDT register */
	vp_ctx->gdtr.base = VSM_VA_FROM_PA(gdt_pa);
	vp_ctx->gdtr.limit = gdt_offset - 1;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s Printing GDTR..\n", __func__);
	pr_info("\t\t Base:  0x%llx\n", vp_ctx->gdtr.base);
	pr_info("\t\t Limit: 0x%x\n",   vp_ctx->gdtr.limit);
#endif
	/* Set the code segment (CS) selector */
	vp_ctx->cs.base = 0;
	vp_ctx->cs.limit = 0;
	vp_ctx->cs.selector = 1 << 3;
	vp_ctx->cs.segment_type = VSM_CODE_SEGMENT_TYPE_EXECUTE_READ_ACCESSED;
	vp_ctx->cs.non_system_segment = 1;
	vp_ctx->cs.descriptor_privilege_level = 0;
	vp_ctx->cs.present = 1;
	vp_ctx->cs.reserved = 0;
	vp_ctx->cs.available = 0;
	vp_ctx->cs._long = 1;
	vp_ctx->cs._default = 0;
	vp_ctx->cs.granularity = 0;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s Printing CS...\n", __func__);
	pr_info("\t\t Sel:   0x%x\n",   vp_ctx->cs.selector);
	pr_info("\t\t Base:  0x%llx\n", vp_ctx->cs.base);
	pr_info("\t\t Limit: 0x%x\n",   vp_ctx->cs.limit);
	pr_info("\t\t Attrs: 0x%x\n",   vp_ctx->cs.attributes);
#endif

	/* Set the data segment (DS) selector */
	vp_ctx->ds.base = 0;
	vp_ctx->ds.limit = 0;
	vp_ctx->ds.selector = 2 << 3;
	vp_ctx->ds.segment_type = VSM_DATA_SEGMENT_TYPE_READ_WRITE_ACCESSED;
	vp_ctx->ds.non_system_segment = 1;
	vp_ctx->ds.descriptor_privilege_level = 0;
	vp_ctx->ds.present = 1;
	vp_ctx->ds.reserved = 0;
	vp_ctx->ds.available = 0;
	vp_ctx->ds._long = 0;
	vp_ctx->ds._default = 1;
	vp_ctx->ds.granularity = 0;

	/* Set the ES, FS and GS to be the same as DS, for now */
	vp_ctx->es = vp_ctx->ds;
	vp_ctx->fs = vp_ctx->ds;
	vp_ctx->gs = vp_ctx->ds;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s: Printing DS/ES/FS/GS...\n");
	pr_info("\t\t Sel:   0x%x\n",   vp_ctx->ds.selector);
	pr_info("\t\t Base:  0x%llx\n", vp_ctx->ds.base);
	pr_info("\t\t Limit: 0x%x\n",   vp_ctx->ds.limit);
	pr_info("\t\t Attrs: 0x%x\n",   vp_ctx->ds.attributes);
#endif

	/* Set the stack selector to 0 (unused in long mode) */
	vp_ctx->ss.selector = 0;

	/* Set the initial stack pointer for the kernel to point to bottom of kernel stack */
	tss->rsp0 = VSM_VA_FROM_PA(kstack_pa) + VSM_PAGE_SIZE - 1;
	vp_ctx->rsp = tss->rsp0;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s: Printing TSS...\n", __func__);
	pr_info("\t\t RSP0: 0x%llx\n", tss->rsp0);
#endif

	/* Set the task register selector  */
	vp_ctx->tr.base = tss_sk_va;
	vp_ctx->tr.limit = tss_sz - 1;
	vp_ctx->tr.selector = 3 << 3;
	vp_ctx->tr.segment_type = VSM_SYSTEM_SEGMENT_TYPE_BUSY_TSS;
	vp_ctx->tr.non_system_segment = 0;
	vp_ctx->tr.descriptor_privilege_level = 0;
	vp_ctx->tr.present = 1;
	vp_ctx->tr.reserved = 0;
	vp_ctx->tr.available = 0;
	vp_ctx->tr._long = 0;
	vp_ctx->tr._default = 0;
	vp_ctx->tr.granularity = 0;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s: Printing TR...\n", __func__);
	pr_info("\t\t Sel:   0x%x\n",   vp_ctx->tr.selector);
	pr_info("\t\t Base:  0x%llx\n", vp_ctx->tr.base);
	pr_info("\t\t Limit: 0x%x\n",   vp_ctx->tr.limit);
	pr_info("\t\t Attrs: 0x%x\n",   vp_ctx->tr.attributes);
#endif
}

/* ToDo: Evaluate whether IDT need to be populated */
static void __init hv_vsm_init_idt(struct hv_initial_vp_context *vp_ctx)
{
	phys_addr_t idt_pa;
	u128 seg;
	u64 target;
	u16 target_lo;
	u128 target_hi;
	u64 type;
	u16 selector;
	size_t seg_sz = sizeof(seg);
	int n;

	idt_pa = PAGE_AT(vsm.skm_pa, VSM_IDT_PAGE);

	/* Fill in the IDT to point to the ISR stubs */
	selector = 1 << 3;
	for (n = 0; n <= 21; n++) {
		type = VSM_GATE_TYPE_INT;
		target = (u64)VSM_VA_FROM_PA(PAGE_AT(vsm.skm_pa,
			VSM_ISRS_CODE_PAGE) + (n * 8));

		target_lo = (u16)target;
		target_hi = (u128)target << 32;

		seg = target_lo | target_hi | ((u64)selector << 16) |
			(VSM_GATE_TYPE_INT << 40) | ((u64)1 << 47);
		
		memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(idt_pa + (n * seg_sz)), &seg, seg_sz);
	}

	/* Set the IDT register */
	vp_ctx->idtr.base = VSM_VA_FROM_PA(idt_pa);
	vp_ctx->idtr.limit = (seg_sz * 22) - 1;
}

static void __init hv_vsm_fill_pte_tables(u64 *pde, int pd_index, int num_pte_tables)
{
	/* 
	 * ToDo: Make a generic solution that can take any PA start and size and adjust
	 * the number of page tables and determine where to start filling them. 
	 */
	u16 i, j;
	phys_addr_t pte_pa;
	u64 *pte;

	/* Fill page tables with entries */
	for (i = 0; i < num_pte_tables; i++) {
		pte_pa = PAGE_AT(vsm.skm_pa, VSM_PTE_0_PAGE + i);
		pte = VSM_NON_LOGICAL_PHYS_TO_VIRT(pte_pa);
		*(pde + pd_index + i) = pte_pa | VSM_PAGE_PTE_OPTEE;
		for (j = 0; j < VSM_ENTRIES_PER_PT; j++) {
			*(pte + j) =
				(vsm.skm_pa + ((j + (i * VSM_ENTRIES_PER_PT)) * VSM_PAGE_SIZE)) |
					VSM_PAGE_PTE_OPTEE;
		}
	}
}

static void __init hv_vsm_init_page_tables(struct hv_initial_vp_context *vp_ctx)
{
	u64 pml4_index;
	u64 pdp_index;
	u64 pd_index;
	phys_addr_t pml4e_pa;
	phys_addr_t pdpe_pa;
	phys_addr_t pde_pa;
	u64 *pml4e;
	u64 *pdpe;
	u64 *pde;
	
	/* Get offset to know where to start mapping. Note vsm.skm_pa is the VA for OP-TEE */
	pml4_index = VSM_GET_PML4_INDEX_FROM_VA(vsm.skm_pa);
	pdp_index = VSM_GET_PDP_INDEX_FROM_VA(vsm.skm_pa);
	pd_index = VSM_GET_PD_INDEX_FROM_VA(vsm.skm_pa);

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s: pml4_index = 0x%llx, pdp_index = 0x%llx, pd_index=0x%llx\n",
			__func__, pml4_index, pdp_index, pd_index);
#endif

	pml4e_pa = PAGE_AT(vsm.skm_pa, VSM_PML4E_PAGE);
	pdpe_pa = PAGE_AT(vsm.skm_pa, VSM_PDPE_PAGE);
	pde_pa = PAGE_AT(vsm.skm_pa, VSM_PDE_PAGE);

	pml4e = VSM_NON_LOGICAL_PHYS_TO_VIRT(pml4e_pa);
	pdpe = VSM_NON_LOGICAL_PHYS_TO_VIRT(pdpe_pa);
	pde = VSM_NON_LOGICAL_PHYS_TO_VIRT(pde_pa);

	/* N.B.: Adding '+ 1' to a pointer moves the underlying value forward by 8 bytes! */
	*(pml4e + pml4_index) = pdpe_pa | VSM_PAGE_OPTEE;
	*(pdpe + pdp_index) = pde_pa | VSM_PAGE_OPTEE;

	hv_vsm_fill_pte_tables(pde, pd_index, VSM_NUM_PTE_TABLES);
	vp_ctx->cr3 = pml4e_pa;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s: Physical Range..\n", __func__);
	pr_info("\t\t Start: 0x%llx\n", vsm.skm_pa);
	pr_info("\t\t End:   0x%llx\n", vsm.skm_pa + SK_MEM_SIZE);
	pr_info("%s: Page Table Physical Addresses\n", __func__);
	pr_info("\t\t PML4:   0x%llx\n", pml4e_pa);
	pr_info("\t\t PDPE:   0x%llx\n", pdpe_pa);
	pr_info("\t\t PDE:    0x%llx\n", pde_pa);
	pr_info("\t\t PTE 0: 0x%llx\n", PAGE_AT(vsm.skm_pa, VSM_PTE_0_PAGE));
	pr_info("\t\t PTE 1: 0x%llx\n", PAGE_AT(vsm.skm_pa, VSM_PTE_0_PAGE + 1));
	pr_info("\t\t PTE 2: 0x%llx\n", PAGE_AT(vsm.skm_pa, VSM_PTE_0_PAGE + 2));
	pr_info("\t\t PTE 3: 0x%llx\n", PAGE_AT(vsm.skm_pa, VSM_PTE_0_PAGE + 3));
	pr_info("%s: Page Table Dump\n", __func__);
	pr_info("\t\t Entry: Idx/Lvl - Raw Value\n");
	hv_vsm_dump_pt(pml4e_pa, 1);
#endif
}

static void __init hv_vsm_arch_init_vp_context(struct hv_initial_vp_context *vp_ctx)
{
	/* The CPU expects these structures to be properly laid out. */
	compiletime_assert(sizeof(union vsm_code_seg_desc) == 8,
		"Code Segment Descriptor is not 8 bytes.");
	compiletime_assert(sizeof(union vsm_data_seg_desc) == 8,
		"Code Segment Descriptor is not 8 bytes.");
	compiletime_assert(sizeof(union vsm_sys_seg_desc) == 16,
		"System Segment Descriptor is not 16 bytes.");
	compiletime_assert(sizeof(union vsm_call_gate_seg_desc) == 16,
		"Call-Gate Segment Descriptor is not 16 bytes.");
	compiletime_assert(sizeof(union vsm_int_trap_gate_seg_desc) == 16,
		"Interrupt-/Trap-Gate Segment Descriptor is not 16 bytes.");

	hv_vsm_init_cpu(vp_ctx);
	hv_vsm_init_gdt(vp_ctx);
	hv_vsm_init_idt(vp_ctx);
	hv_vsm_init_page_tables(vp_ctx);
}

static int __init hv_vsm_enable_vp_vtl(void)
{
	u64 status = 0;
	unsigned long flags;
	struct hv_input_enable_vp_vtl *hvin = NULL;

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->vp_index = HV_VP_INDEX_SELF;
	hvin->target_vtl = 1;
	hvin->reserved_z0 = 0;
	hvin->reserved_z1 = 0;

	hv_vsm_arch_init_vp_context(&hvin->vp_vtl_context);

	local_irq_save(flags);

	status = hv_do_hypercall(HVCALL_ENABLE_VP_VTL, hvin, NULL);

	local_irq_restore(flags);

	return (int) (status & HV_HYPERCALL_RESULT_MASK);
}

static int __init hv_vsm_load_secure_kernel(void)
{
	/*
	 * Till we combine the skloader and kernel into one binary, we have to load them separately
	 * ToDo: Load them as one binary
	 */
	loff_t size_skloader, size_sk;
	char *skloader_buf = NULL, *sk_buf = NULL;
	int err;

	// Find the size of skloader and sk
	size_skloader = vfs_llseek(sk_loader, 0, SEEK_END);
	size_sk = vfs_llseek(sk, 0, SEEK_END);

	// Seek back to the beginning of the file
	vfs_llseek(sk_loader, 0, SEEK_SET);
	vfs_llseek(sk, 0, SEEK_SET);

	// Allocate memory for the buffer
	skloader_buf = kvmalloc(size_skloader, GFP_KERNEL);
	if (!skloader_buf) {
		pr_err("%s: Unable to allocate memory for copying secure kernel\n", __func__);
		return -ENOMEM;
	}
	sk_buf = kvmalloc(size_sk, GFP_KERNEL);
	if (!sk_buf) {
		pr_err("%s: Unable to allocate memory for copying secure kernel\n", __func__);
		kvfree(skloader_buf);
		return -ENOMEM;
	}

	// Read from the file into the buffer
	err = kernel_read(sk_loader, skloader_buf, size_skloader, &sk_loader->f_pos);
	if (err != size_skloader) {
		pr_err("%s Unable to read skloader.bin file\n", __func__);
		kvfree(skloader_buf);
		kvfree(sk_buf);
		return -1;
	}
	err = kernel_read(sk, sk_buf, size_sk, &sk->f_pos);
	if (err != size_sk) {
		pr_err("%s Unable to read vmlinux.bin file\n", __func__);
		kvfree(skloader_buf);
		kvfree(sk_buf);
		return -1;
	}

	memcpy(vsm.skm_va, skloader_buf, size_skloader);
	memcpy(vsm.skm_va + (2 * 1024 * 1024), sk_buf, size_sk);
	kvfree(skloader_buf);
	kvfree(sk_buf);
	return 0;
}

int __init hv_vsm_enable_vtl1(void)
{
	struct cpumask mask;
	unsigned int boot_cpu;
	u16 partition_enabled_vtl_set = 0, vp_enabled_vtl_set = 0;
	u8 partition_max_vtl;
	int ret = 0;

	if (!vsm_arch_has_vsm_access()) {
		pr_err("%s: Arch does not support VSM\n", __func__);
		return -ENOTSUPP;
	}
	if (hv_vsm_reserve_sk_mem()) {
		pr_err("%s: Could not initialize memory for secure kernel\n", __func__);
		return -ENOMEM;
	}

	sk_loader = filp_open("/usr/lib/firmware/skloader.bin", O_RDONLY, 0);
	if (IS_ERR(sk_loader)) {
		pr_err("%s: File usr/lib/firmware/skloader.bin not found\n", __func__);
		ret = -ENOENT;
		goto free_mem;
	}
	sk = filp_open("/usr/lib/firmware/vmlinux.bin", O_RDONLY, 0);
	if (IS_ERR(sk)) {
		pr_err("%s: File usr/lib/firmware/vmlinux.bin not found\n", __func__);
		ret = -ENOENT;
		goto close_file;
	}

	/*
	 * Copy the current cpu mask and pin rest of the running code to boot cpu.
	 * Important since we want boot cpu of VTL0 to be the boot cpu for VTL1.
	 * ToDo: Check if copying and restoring current->cpus_mask is enough
	 * ToDo: Verify the assumption that cpumask_first(cpu_online_mask) is
	 * the boot cpu
	 */
	boot_cpu = cpumask_first(cpu_online_mask);
	cpumask_copy(&mask, &current->cpus_mask);
	set_cpus_allowed_ptr(current, cpumask_of(boot_cpu));

	/* Check and enable VTL1 at the partition level */
	ret = hv_vsm_get_partition_status(&partition_enabled_vtl_set, &partition_max_vtl);
	if (ret)
		goto out;

	if (partition_max_vtl < HV_VTL1) {
		pr_err("%s: VTL1 is not supported", __func__);
		ret = -EINVAL;
		goto out;
	}
	if (partition_enabled_vtl_set & HV_VTL1_ENABLE_BIT) {
		pr_info("%s: Partition VTL1 is already enabled\n", __func__);
	} else {
		ret = hv_vsm_enable_partition_vtl();
		if (ret) {
			pr_err("%s: Enabling Partition VTL1 failed with status 0x%x\n", __func__, ret);
			ret = -EINVAL;
			goto out;
		}
		hv_vsm_get_partition_status(&partition_enabled_vtl_set, &partition_max_vtl);
		if (!(partition_enabled_vtl_set & HV_VTL1_ENABLE_BIT)) {
			pr_err("%s: Tried Enabling Partition VTL 1 and still failed", __func__);
			ret = -EINVAL;
			goto out;
		}
	}

	/* Check and enable VTL1 for the primary virtual processor */
	ret = hv_vsm_get_vp_status(&vp_enabled_vtl_set);
	if (ret)
		goto out;

	if (vp_enabled_vtl_set & HV_VTL1_ENABLE_BIT) {
		pr_info("%s: VP VTL1 is already enabled\n", __func__);
	} else {
		ret = hv_vsm_enable_vp_vtl();
		if (ret) {
			pr_err("%s: Enabling VP VTL1 failed with status 0x%x\n", __func__, ret);
			/* ToDo: Should we disable VTL1 at partition level in this case */
			ret = -EINVAL;
			goto out;
		}
		hv_vsm_get_vp_status(&vp_enabled_vtl_set);
		if (!(vp_enabled_vtl_set & HV_VTL1_ENABLE_BIT)) {
			pr_err("%s: Tried Enabling VP VTL 1 and still failed", __func__);
			ret = -EINVAL;
			goto out;
		}
	}
	ret = hv_vsm_load_secure_kernel();

	/* Kick-start VTL1 boot */
	if (!ret) {
		hv_vsm_boot_vtl1();
		hv_vsm_boot_success = true;
	}

out:
	set_cpus_allowed_ptr(current, &mask);
	filp_close(sk, NULL);
close_file:
	filp_close(sk_loader, NULL);
free_mem:
	vunmap(vsm.skm_va);
	return ret;
}
#else
int __init hv_vsm_enable_vtl1(void)
{
	return 0;
}
#endif

static int __init hv_vsm_boot_init(void)
{
	hv_vsm_enable_vtl1();

    return 0;
}

module_init(hv_vsm_boot_init);
MODULE_DESCRIPTION("Hyper-V VSM Boot VTL0 Driver");
MODULE_LICENSE("GPL");
