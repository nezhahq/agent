#ifndef __SMC_H__
#define __SMC_H__ 1

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#if (defined __MAC_OS_X_VERSION_MIN_REQUIRED) && (__MAC_OS_X_VERSION_MIN_REQUIRED < 120000)
#define kIOMainPortDefault kIOMasterPortDefault
#endif

void *find_properties(io_registry_entry_t, int, CFStringRef, CFStringRef);
char **find_devices(char *);
int find_utilization(char *, char *);

#endif