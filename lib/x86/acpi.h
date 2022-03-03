#ifndef _X86_ACPI_H_
#define _X86_ACPI_H_

#include "../acpi.h"

int acpi_wakeup_cpu(int apicid, unsigned long start_ip);
bool parse_acpi_table(void);


#endif /* _X86_ACPI_H_ */