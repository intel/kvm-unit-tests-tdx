/*
 * Initialize machine setup information
 *
 * Copyright (C) 2017, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 * Copyright (C) 2021, Google Inc, Zixuan Wang <zixuanwang@google.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"
#include "fwcfg.h"
#include "alloc_phys.h"
#include "argv.h"
#include "desc.h"
#include "apic.h"
#include "apic-defs.h"
#include "asm/setup.h"
#include "atomic.h"
#include "pmu.h"
#include "processor.h"
#include "smp.h"

extern char edata;

struct mbi_bootinfo {
	u32 flags;
	u32 mem_lower;
	u32 mem_upper;
	u32 boot_device;
	u32 cmdline;
	u32 mods_count;
	u32 mods_addr;
	u32 reserved[4];   /* 28-43 */
	u32 mmap_length;
	u32 mmap_addr;
	u32 reserved0[3];  /* 52-63 */
	u32 bootloader;
	u32 reserved1[5];  /* 68-87 */
	u32 size;
};

struct mbi_module {
	u32 start, end;
	u32 cmdline;
	u32 unused;
};

struct mbi_mem {
	u32 size;
	u64 base_addr;
	u64 length;
	u32 type;
} __attribute__((packed));

#define ENV_SIZE 16384

void setup_env(char *env, int size);
void setup_multiboot(struct mbi_bootinfo *bootinfo);
void setup_libcflat(void);

char *initrd;
u32 initrd_size;

static char env[ENV_SIZE];
static struct mbi_bootinfo *bootinfo;

#define HUGEPAGE_SIZE (1 << 21)

#ifdef __x86_64__
void find_highmem(void)
{
#ifdef TARGET_EFI
	/* The largest free memory region is already chosen in setup_efi() */
	return;
#endif /* TARGET_EFI */

	/* Memory above 4 GB is only supported on 64-bit systems.  */
	if (!(bootinfo->flags & 64))
	    	return;

	u64 upper_end = bootinfo->mem_upper * 1024ull;
	u64 best_start = (uintptr_t) &edata;
	u64 best_end = upper_end;
	u64 max_end = fwcfg_get_u64(FW_CFG_MAX_RAM);
	if (max_end == 0)
		max_end = -1ull;
	bool found = false;

	uintptr_t mmap = bootinfo->mmap_addr;
	while (mmap < bootinfo->mmap_addr + bootinfo->mmap_length) {
		struct mbi_mem *mem = (void *)mmap;
		mmap += mem->size + 4;
		if (mem->type != 1)
			continue;
		if (mem->base_addr <= (uintptr_t) &edata ||
		    (mem->base_addr <= upper_end && mem->base_addr + mem->length <= upper_end))
			continue;
		if (mem->length < best_end - best_start)
			continue;
		if (mem->base_addr >= max_end)
			continue;
		best_start = mem->base_addr;
		best_end = mem->base_addr + mem->length;
		if (best_end > max_end)
			best_end = max_end;
		found = true;
	}

	if (found) {
		best_start = (best_start + HUGEPAGE_SIZE - 1) & -HUGEPAGE_SIZE;
		best_end = best_end & -HUGEPAGE_SIZE;
		phys_alloc_init(best_start, best_end - best_start);
	}
}

/* Setup TSS for the current processor, and return TSS offset within GDT */
unsigned long setup_tss(u8 *stacktop)
{
	u32 id;
	tss64_t *tss_entry;
	static u32 cpus = 0;

	id = is_tdx_guest() ? id_map[cpus++] : pre_boot_apic_id();

	/* Runtime address of current TSS */
	tss_entry = &tss[id];

	/* Update TSS */
	memset((void *)tss_entry, 0, sizeof(tss64_t));

	/* Update TSS descriptors; each descriptor takes up 2 entries */
	set_gdt_entry(TSS_MAIN + id * 16, (unsigned long)tss_entry, 0xffff, 0x89, 0);

	return TSS_MAIN + id * 16;
}
#else
/* Setup TSS for the current processor, and return TSS offset within GDT */
unsigned long setup_tss(u8 *stacktop)
{
	u32 id;
	tss32_t *tss_entry;

	id = pre_boot_apic_id();

	/* Runtime address of current TSS */
	tss_entry = &tss[id];

	/* Update TSS */
	memset((void *)tss_entry, 0, sizeof(tss32_t));
	tss_entry->ss0 = KERNEL_DS;

	/* Update descriptors for TSS and percpu data segment.  */
	set_gdt_entry(TSS_MAIN + id * 8,
		      (unsigned long)tss_entry, 0xffff, 0x89, 0);
	set_gdt_entry(TSS_MAIN + MAX_TEST_CPUS * 8 + id * 8,
		      (unsigned long)stacktop - 4096, 0xfffff, 0x93, 0xc0);

	return TSS_MAIN + id * 8;
}
#endif

void setup_multiboot(struct mbi_bootinfo *bi)
{
	struct mbi_module *mods;

	bootinfo = bi;

	u64 best_start = (uintptr_t) &edata;
	u64 best_end = bootinfo->mem_upper * 1024ull;
	phys_alloc_init(best_start, best_end - best_start);

	if (bootinfo->mods_count != 1)
		return;

	mods = (struct mbi_module *)(uintptr_t) bootinfo->mods_addr;

	initrd = (char *)(uintptr_t) mods->start;
	initrd_size = mods->end - mods->start;
}

static void setup_gdt_tss(void)
{
	size_t tss_offset;

	/* 64-bit setup_tss does not use the stacktop argument.  */
	tss_offset = setup_tss(NULL);
	load_gdt_tss(tss_offset);
}

#ifdef CONFIG_EFI

static struct percpu_data __percpu_data[MAX_TEST_CPUS];

static void setup_segments64(void)
{
	/* Update data segments */
	write_ds(KERNEL_DS);
	write_es(KERNEL_DS);
	write_fs(KERNEL_DS);
	write_gs(KERNEL_DS);
	write_ss(KERNEL_DS);


	/*
	 * Update the code segment by putting it on the stack before the return
	 * address, then doing a far return: this will use the new code segment
	 * along with the address.
	 */
	asm volatile("pushq %1\n\t"
		     "lea 1f(%%rip), %0\n\t"
		     "pushq %0\n\t"
		     "lretq\n\t"
		     "1:"
		     :: "r" ((u64)KERNEL_DS), "i" (KERNEL_CS));
}

static efi_status_t setup_memory_allocator(efi_bootinfo_t *efi_bootinfo)
{
	int i;
	unsigned long free_mem_pages = 0;
	unsigned long free_mem_start = 0;
	struct efi_boot_memmap *map = &(efi_bootinfo->mem_map);
	efi_memory_desc_t *buffer = *map->map;
	efi_memory_desc_t *d = NULL;

	/*
	 * The 'buffer' contains multiple descriptors that describe memory
	 * regions maintained by UEFI. This code records the largest free
	 * EFI_CONVENTIONAL_MEMORY region which will be used to set up the
	 * memory allocator, so that the memory allocator can work in the
	 * largest free continuous memory region.
	 */
	for (i = 0; i < *(map->map_size); i += *(map->desc_size)) {
		d = (efi_memory_desc_t *)(&((u8 *)buffer)[i]);
		if (d->type == EFI_CONVENTIONAL_MEMORY) {
			if (free_mem_pages < d->num_pages) {
				free_mem_pages = d->num_pages;
				free_mem_start = d->phys_addr;
			}
		}
	}

	if (free_mem_pages == 0) {
		return EFI_OUT_OF_RESOURCES;
	}

	phys_alloc_init(free_mem_start, free_mem_pages << EFI_PAGE_SHIFT);

	return EFI_SUCCESS;
}

static efi_status_t setup_rsdp(efi_bootinfo_t *efi_bootinfo)
{
	efi_status_t status;
	struct rsdp_descriptor *rsdp;

	/*
	 * RSDP resides in an EFI_ACPI_RECLAIM_MEMORY region, which is not used
	 * by kvm-unit-tests x86's memory allocator. So it is not necessary to
	 * copy the data structure to another memory region to prevent
	 * unintentional overwrite.
	 */
	status = efi_get_system_config_table(ACPI_TABLE_GUID, (void **)&rsdp);
	if (status != EFI_SUCCESS) {
		return status;
	}

	set_efi_rsdp(rsdp);

	return EFI_SUCCESS;
}

/* Defined in cstart64.S or efistart64.S */
extern u8 ptl5;
extern u8 ptl4;
extern u8 ptl3;
extern u8 ptl2;

static void load_page_table(void)
{
	/*
	 * Load new page table based on the level of firmware provided page
	 * table.
	 */
	if (read_cr4() & X86_CR4_LA57)
		write_cr3((ulong)&ptl5);
	else
		write_cr3((ulong)&ptl4);
}

static void setup_page_table(void)
{
	pgd_t *curr_pt;
	phys_addr_t flags;
	int i;

	/* Set default flags */
	flags = PT_PRESENT_MASK | PT_WRITABLE_MASK | PT_USER_MASK;

	/* Set AMD SEV C-Bit for page table entries */
	flags |= get_amd_sev_c_bit_mask();

	/* Level 5 */
	curr_pt = (pgd_t *)&ptl5;
	curr_pt[0] = ((phys_addr_t)&ptl4) | flags;
	/* Level 4 */
	curr_pt = (pgd_t *)&ptl4;
	curr_pt[0] = ((phys_addr_t)&ptl3) | flags;
	/* Level 3 */
	curr_pt = (pgd_t *)&ptl3;
	for (i = 0; i < 4; i++) {
		curr_pt[i] = (((phys_addr_t)&ptl2) + i * PAGE_SIZE) | flags;
	}
	/* Level 2 */
	curr_pt = (pgd_t *)&ptl2;
	flags |= PT_ACCESSED_MASK | PT_DIRTY_MASK | PT_PAGE_SIZE_MASK | PT_GLOBAL_MASK;
	for (i = 0; i < 4 * 512; i++)	{
		curr_pt[i] = ((phys_addr_t) i << 21) | flags;
	}

	if (amd_sev_es_enabled()) {
		setup_ghcb_pte((pgd_t *)&ptl4);
	}

	load_page_table();
}

static void setup_percpu_area(void)
{
	u64 rsp;

	asm volatile ("mov %%rsp, %0" : "=m"(rsp) :: "memory");

	/* per cpu stack size is PAGE_SIZE */
	rsp &= ~((u64)PAGE_SIZE - 1);
	wrmsr(MSR_GS_BASE, rsp);
}

void secondary_startup_64(void)
{
	setup_gdt_tss();
	load_idt();
	setup_percpu_area();
	enable_x2apic();
	tdx_ap_init();
	load_page_table();

	while (1)
		safe_halt();
}

static void aps_init(void)
{
	if (is_tdx_guest())
		tdx_aps_init();
}

efi_status_t setup_efi(efi_bootinfo_t *efi_bootinfo)
{
	efi_status_t status;
	const char *phase;

	/*
	 * TDVF support partial memory accept, accept remaining memory
	 * early so memory allocator can use it.
	 */
	status = setup_tdx(efi_bootinfo);
	if (status != EFI_SUCCESS && status != EFI_UNSUPPORTED) {
		printf("INTEL TDX setup failed, error = 0x%lx\n", status);
		return status;
	}

	status = setup_memory_allocator(efi_bootinfo);
	if (status != EFI_SUCCESS) {
		printf("Failed to set up memory allocator: ");
		switch (status) {
		case EFI_OUT_OF_RESOURCES:
			printf("No free memory region\n");
			break;
		default:
			printf("Unknown error\n");
			break;
		}
		return status;
	}

	status = setup_rsdp(efi_bootinfo);
	if (status != EFI_SUCCESS) {
		printf("Cannot find RSDP in EFI system table\n");
		return status;
	}

	/* Parse all acpi tables, currently only MADT table */
	if (!parse_acpi_table())
		return EFI_NOT_FOUND;

	phase = "AMD SEV";
	status = setup_amd_sev();

	/* Continue if AMD SEV is not supported, but skip SEV-ES setup */
	if (status == EFI_SUCCESS) {
		phase = "AMD SEV-ES";
		status = setup_amd_sev_es();
	}

	if (status != EFI_SUCCESS && status != EFI_UNSUPPORTED) {
		printf("%s setup failed, error = 0x%lx\n", phase, status);
		return status;
	}

	setup_gdt_tss();
	setup_segments64();
	setup_idt();
	load_idt();
	/*
	 * Load GS.base with the per-vCPU data.  This must be done after
	 * loading the IDT as reading the APIC ID may #VC when running
	 * as an SEV-ES guest
	 */
	wrmsr(MSR_GS_BASE, (u64)&__percpu_data[pre_boot_apic_id()]);
	/*
	 * Resetting the APIC sets the per-vCPU APIC ops and so must be
	 * done after loading GS.base with the per-vCPU data.
	 */
	/* xAPIC mode isn't allowed in TDX */
	setup_percpu_area();
	if (!is_tdx_guest())
		reset_apic();
	mask_pic_interrupts();
	setup_page_table();
	if (!is_tdx_guest())
		enable_apic();
	save_id();
	bsp_rest_init();

	return EFI_SUCCESS;
}

#endif /* CONFIG_EFI */

void setup_libcflat(void)
{
	if (initrd) {
		/* environ is currently the only file in the initrd */
		u32 size = MIN(initrd_size, ENV_SIZE);
		const char *str;

		memcpy(env, initrd, size);
		setup_env(env, size);
		if ((str = getenv("BOOTLOADER")) && atol(str) != 0)
			add_setup_arg("bootloader");
	}
}

void save_id(void)
{
	set_bit(apic_id(), online_cpus);
}

void ap_start64(void)
{
	setup_gdt_tss();
	reset_apic();
	load_idt();
	save_id();
	if (!is_tdx_guest())
		enable_apic();
	enable_x2apic();
	ap_online();
}

void bsp_rest_init(void)
{
	bringup_aps();
	enable_x2apic();
	aps_init();
	smp_init();
	pmu_init();
}
