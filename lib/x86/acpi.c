#include "libcflat.h"
#include "errno.h"
#include "acpi.h"
#include "apic.h"
#include "asm/barrier.h"
#include "processor.h"

#ifdef CONFIG_EFI
unsigned char online_cpus[(MAX_TEST_CPUS + 7) / 8];
struct rsdp_descriptor *efi_rsdp = NULL;

void set_efi_rsdp(struct rsdp_descriptor *rsdp)
{
	efi_rsdp = rsdp;
}

static struct rsdp_descriptor *get_rsdp(void)
{
	if (efi_rsdp == NULL) {
		printf("Can't find RSDP from UEFI, maybe set_efi_rsdp() was not called\n");
	}
	return efi_rsdp;
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

int acpi_wakeup_cpu(int apicid, unsigned long start_ip)
{
	u8 timeout = 0xFF;

	/*
	 * According to the ACPI specification r6.4, sec 5.2.12.19, the
	 * mailbox-based wakeup mechanism cannot be used more than once
	 * for the same CPU, so skip sending wake commands to already
	 * awake CPU.
	 */
	if (test_bit(apicid, online_cpus)) {
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

	if (timeout) {
		/*
		 * If the CPU wakeup process is successful, store the
		 * status in online_cpus to prevent re-wakeup
		 * requests.
		 */
		set_bit(apicid, online_cpus);
		return 0;
	}

	/* If timed out (timeout == 0), return error */
	return -EIO;
}

static bool parse_madt_table(struct acpi_table *madt)
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

bool parse_acpi_table(void)
{
	struct acpi_table *tb;

	tb = find_acpi_table_addr(MADT_SIGNATURE);
	if (tb)
		return parse_madt_table(tb);

	return false;
}
#else
static struct rsdp_descriptor *get_rsdp(void)
{
	struct rsdp_descriptor *rsdp;
	unsigned long addr;

	for (addr = 0xe0000; addr < 0x100000; addr += 16) {
		rsdp = (void *)addr;
		if (rsdp->signature == RSDP_SIGNATURE_8BYTE)
			break;
	}

	if (addr == 0x100000) {
		return NULL;
	}

	return rsdp;
}
#endif /* CONFIG_EFI */

void* find_acpi_table_addr(u32 sig)
{
    struct rsdp_descriptor *rsdp;
    struct rsdt_descriptor_rev1 *rsdt;
    void *end;
    int i;

    /* FACS is special... */
    if (sig == FACS_SIGNATURE) {
        struct fadt_descriptor_rev1 *fadt;
        fadt = find_acpi_table_addr(FACP_SIGNATURE);
        if (!fadt) {
            return NULL;
        }
        return (void*)(ulong)fadt->firmware_ctrl;
    }

    rsdp = get_rsdp();
    if (rsdp == NULL) {
        printf("Can't find RSDP\n");
        return 0;
    }

    if (sig == RSDP_SIGNATURE) {
        return rsdp;
    }

    rsdt = (void*)(ulong)rsdp->rsdt_physical_address;
    if (!rsdt || rsdt->signature != RSDT_SIGNATURE)
        return 0;

    if (sig == RSDT_SIGNATURE) {
        return rsdt;
    }

    end = (void*)rsdt + rsdt->length;
    for (i=0; (void*)&rsdt->table_offset_entry[i] < end; i++) {
        struct acpi_table *t = (void*)(ulong)rsdt->table_offset_entry[i];
        if (t && t->signature == sig) {
            return t;
        }
    }
   return NULL;
}
