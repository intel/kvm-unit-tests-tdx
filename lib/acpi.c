#include "libcflat.h"
#include "acpi.h"
#include "errno.h"
#include "asm/barrier.h"

#ifdef CONFIG_EFI
struct acpi_table_rsdp *efi_rsdp = NULL;

void set_efi_rsdp(struct acpi_table_rsdp *rsdp)
{
	efi_rsdp = rsdp;
}

static struct acpi_table_rsdp *get_rsdp(void)
{
	if (efi_rsdp == NULL)
		printf("Can't find RSDP from UEFI, maybe set_efi_rsdp() was not called\n");

	return efi_rsdp;
}
#else
static struct acpi_table_rsdp *get_rsdp(void)
{
	struct acpi_table_rsdp *rsdp;
	unsigned long addr;

	for (addr = 0xe0000; addr < 0x100000; addr += 16) {
		rsdp = (void *)addr;
		if (rsdp->signature == RSDP_SIGNATURE_8BYTE)
			break;
	}

	if (addr == 0x100000)
		return NULL;

	return rsdp;
}
#endif /* CONFIG_EFI */

void *find_acpi_table_addr(u32 sig)
{
	struct acpi_table_rsdt_rev1 *rsdt = NULL;
	struct acpi_table_xsdt *xsdt = NULL;
	struct acpi_table_rsdp *rsdp;
	void *end;
	int i;

	/* FACS is special... */
	if (sig == FACS_SIGNATURE) {
		struct acpi_table_fadt *fadt;

		fadt = find_acpi_table_addr(FACP_SIGNATURE);
		if (!fadt)
			return NULL;
		return (void *)(ulong) fadt->firmware_ctrl;
	}

	rsdp = get_rsdp();
	if (rsdp == NULL) {
		printf("Can't find RSDP\n");
		return NULL;
	}

	if (sig == RSDP_SIGNATURE)
		return rsdp;

	rsdt = (void *)(ulong) rsdp->rsdt_physical_address;
	if (rsdt && rsdt->signature != RSDT_SIGNATURE)
		rsdt = NULL;

	if (sig == RSDT_SIGNATURE)
		return rsdt;

	if (rsdp->revision >= 2) {
		xsdt = (void *)(ulong) rsdp->xsdt_physical_address;
		if (xsdt && xsdt->signature != XSDT_SIGNATURE)
			xsdt = NULL;
	}

	if (sig == XSDT_SIGNATURE)
		return xsdt;

	/*
	 * When the system implements APCI 2.0 and above and XSDT is valid we
	 * have use XSDT to find other ACPI tables, otherwise, we use RSDT.
	 */
	if (xsdt) {
		end = (void *)xsdt + xsdt->length;
		for (i = 0; (void *)&xsdt->table_offset_entry[i] < end; i++) {
			struct acpi_table *t = (void *)(ulong) xsdt->table_offset_entry[i];

			if (t && t->signature == sig)
				return t;
		}
	} else if (rsdt) {
		end = (void *)rsdt + rsdt->length;
		for (i = 0; (void *)&rsdt->table_offset_entry[i] < end; i++) {
			struct acpi_table *t = (void *)(ulong) rsdt->table_offset_entry[i];

			if (t && t->signature == sig)
				return t;
		}
	}

	return NULL;
}

int acpi_table_parse_madt(enum acpi_madt_type mtype, acpi_table_handler handler)
{
	struct acpi_table_madt *madt;
	struct acpi_subtable_header *header;
	void *end;
	int count = 0;

	madt = find_acpi_table_addr(MADT_SIGNATURE);
	assert(madt);

	header = (void *)(ulong) madt + sizeof(struct acpi_table_madt);
	end = (void *)((ulong) madt + madt->length);

	while ((void *)header < end) {
		if (header->type == mtype) {
			handler(header);
			count++;
		}

		header = (void *)(ulong) header + header->length;
	}

	return count;
}

struct acpi_madt_multiproc_wakeup_mailbox *acpi_mp_wake_mailbox;

#define smp_store_release(p, val)					\
do {									\
	barrier();							\
	WRITE_ONCE(*p, val);						\
} while (0)

static inline bool test_bit(int nr, const void *addr)
{
	const u32 *p = (const u32 *)addr;
	return ((1UL << (nr & 31)) & (p[nr >> 5])) != 0;
}

int acpi_wakeup_cpu(int apicid, unsigned long start_ip, unsigned char* cpus)
{
	u8 timeout = 0xFF;

	/*
	 * According to the ACPI specification r6.4, sec 5.2.12.19, the
	 * mailbox-based wakeup mechanism cannot be used more than once
	 * for the same CPU, so skip sending wake commands to already
	 * awake CPU.
	 */
	if (test_bit(apicid, cpus)) {
		printf("CPU already awake (APIC ID %x), skipping wakeup\n",
		       apicid);
		return -EINVAL;
	}

	/*
	 * Mailbox memory is shared between firmware and OS. Firmware will
	 * listen on mailbox command address, and once it receives the wakeup
	 * command, CPU associated with the given apicid will be booted. So,
	 * the value of apic_id and wakeup_vector has to be set before updating
	 * the wakeup command. So use smp_store_release to let the compiler know
	 * about it and preserve the order of writes.
	 */
	if (!acpi_mp_wake_mailbox) {
		printf("The acpi_mp_wake_mailbox is not initialized\n");
		return -EINVAL;
	}
	smp_store_release(&acpi_mp_wake_mailbox->apic_id, apicid);
	smp_store_release(&acpi_mp_wake_mailbox->wakeup_vector, start_ip);
	smp_store_release(&acpi_mp_wake_mailbox->command,
			  ACPI_MP_WAKE_COMMAND_WAKEUP);

	/*
	 * After writing wakeup command, wait for maximum timeout of 0xFF
	 * for firmware to reset the command address back zero to indicate
	 * the successful reception of command.
	 * NOTE: 255 as timeout value is decided based on our experiments.
	 *
	 * XXX: Change the timeout once ACPI specification comes up with
	 *      standard maximum timeout value.
	 */
	while (READ_ONCE(acpi_mp_wake_mailbox->command) && timeout--)
		cpu_relax();

	/*
	 * If timed out (timeout == 0), return error.
	 * Otherwise, the CPU wakes up successfully.
	 */
	return timeout == 0 ? -EIO : 0;
}

static bool parse_madt_table(struct acpi_table *madt, unsigned char* id_map)
{
	u64 table_start = (unsigned long)madt + sizeof(struct acpi_table_madt);
	u64 table_end = (unsigned long)madt + madt->length;
	struct acpi_subtable_header *sub_table;
	bool failed = false;
	u32 uid, apic_id;
	u8 enabled;

	while (table_start < table_end && !failed) {
		struct acpi_madt_local_apic *processor;
		struct acpi_madt_local_x2apic *processor2;
		struct acpi_madt_multiproc_wakeup *mp_wake;

		sub_table = (struct acpi_subtable_header *)table_start;

		switch (sub_table->type) {
		case ACPI_MADT_TYPE_LOCAL_APIC:
			processor = (struct acpi_madt_local_apic *)sub_table;

			if (BAD_MADT_ENTRY(processor, table_end)) {
				failed = true;
				break;
			}

			uid = processor->processor_id;
			apic_id = processor->id;
			enabled = processor->lapic_flags & ACPI_MADT_ENABLED;

			/* Ignore invalid ID */
			if (apic_id == 0xff)
				break;
			if (enabled)
				id_map[uid] = apic_id;

			printf("apicid %x uid %x %s\n", apic_id, uid,
			       enabled ? "enabled" : "disabled");
			break;

		case ACPI_MADT_TYPE_LOCAL_X2APIC:
			processor2 = (struct acpi_madt_local_x2apic *)sub_table;

			if (BAD_MADT_ENTRY(processor2, table_end)) {
				failed = true;
				break;
			}

			uid = processor2->uid;
			apic_id = processor2->local_apic_id;
			enabled = processor2->lapic_flags & ACPI_MADT_ENABLED;

			/* Ignore invalid ID */
			if (apic_id == 0xffffffff)
				break;
			if (enabled)
				id_map[uid] = apic_id;

			printf("x2apicid %x uid %x %s\n", apic_id, uid,
			       enabled ? "enabled" : "disabled");
			break;
		case ACPI_MADT_TYPE_MULTIPROC_WAKEUP:
			mp_wake = (struct acpi_madt_multiproc_wakeup *)sub_table;

			if (BAD_MADT_ENTRY(mp_wake, table_end)) {
				failed = true;
				break;
			}

			if (acpi_mp_wake_mailbox)
				printf("WARN: duplicate mailbox %lx\n", (u64)acpi_mp_wake_mailbox);

			acpi_mp_wake_mailbox = (void *)mp_wake->base_address;
			printf("MP Wake (Mailbox version[%d] base_address[%lx])\n",
					mp_wake->mailbox_version, mp_wake->base_address);
			break;
		default:
			/* Ignored currently */
			break;
		}
		if (!failed)
			table_start += sub_table->length;
	}

	return !failed;
}

bool parse_acpi_table(unsigned char* id_map)
{
	struct acpi_table *tb;

	tb = find_acpi_table_addr(MADT_SIGNATURE);
	if (tb)
		return parse_madt_table(tb, id_map);

	return false;
}
