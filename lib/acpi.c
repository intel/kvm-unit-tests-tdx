#include "libcflat.h"
#include "acpi.h"
#include "bitops.h"
#include "asm/barrier.h"

static struct acpi_madt_multiproc_wakeup_mailbox *acpi_mp_wake_mailbox;

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

int acpi_parse_madt_mp_wakeup(struct acpi_subtable_header *sub_table)
{
	struct acpi_madt_multiproc_wakeup *mp_wakeup = (void *)sub_table;

	if (acpi_mp_wake_mailbox)
		printf("WARN: duplicate mailbox, prev: 0x%p\n",
		       acpi_mp_wake_mailbox);

	acpi_mp_wake_mailbox = (void *)(unsigned long)mp_wakeup->base_address;
	printf("MP Wake (Mailbox version[%d] base_address[%"PRIx64"])\n",
	       mp_wakeup->mailbox_version, mp_wakeup->base_address);

	return 0;
}

bool acpi_wakeup_cpu(int apicid, unsigned long start_ip)
{
	if (!acpi_mp_wake_mailbox) {
		printf("No MP wake up mailbox\n");
		return false;
	}

	/*
	 * Mailbox memory is shared between firmware and OS. Firmware will
	 * listen on mailbox command address, and once it receives the wakeup
	 * command, CPU associated with the given apicid will be booted. So,
	 * the value of apic_id and wakeup_vector has to be set before updating
	 * the wakeup command. So use smp_store_release to let the compiler know
	 * about it and preserve the order of writes.
	 */
	acpi_mp_wake_mailbox->apic_id = apicid;
	acpi_mp_wake_mailbox->wakeup_vector = start_ip;
	smp_store_release(&acpi_mp_wake_mailbox->command,
			  ACPI_MP_WAKE_COMMAND_WAKEUP);

	while (READ_ONCE(acpi_mp_wake_mailbox->command))
		cpu_relax();

	return true;
}
