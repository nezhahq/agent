#ifndef __SMC_H__
#define __SMC_H__ 1

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#if (MAC_OS_X_VERSION_MAX_ALLOWED < 101700) // Before macOS 12 Monterey
#define kIOMainPortDefault kIOMasterPortDefault
#endif

void *find_properties(io_registry_entry_t, int, CFStringRef, CFStringRef);
char **find_devices(char *);
int find_utilization(char *, char *);

#endif