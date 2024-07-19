#include "gpu_darwin.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IOSERVICE_GPU "IOAccelerator"
#define IOSERVICE_PCI "IOPCIDevice"

void *find_properties(io_registry_entry_t service, int depth, CFStringRef key,
                      CFStringRef dict_key) {
  CFTypeRef properties = IORegistryEntrySearchCFProperty(
      service, kIOServicePlane, key, kCFAllocatorDefault,
      kIORegistryIterateRecursively);

  if (properties) {
    if (CFGetTypeID(properties) == CFStringGetTypeID()) {
      CFStringRef cfStr = (CFStringRef)properties;
      char buffer[1024];
      CFStringGetCString(cfStr, buffer, sizeof(buffer), kCFStringEncodingUTF8);
      CFRelease(properties);
      return strdup(buffer);
    } else if (CFGetTypeID(properties) == CFDictionaryGetTypeID()) {
      CFDictionaryRef cfDict = (CFDictionaryRef)properties;
      CFNumberRef cfValue = (CFNumberRef)CFDictionaryGetValue(cfDict, dict_key);
      if (cfValue == NULL) {
        return NULL;
      }
      int value;
      if (!CFNumberGetValue(cfValue, kCFNumberIntType, &value)) {
        return NULL;
      }
      return (void *)(intptr_t)value;
    }
  }

  return NULL;
}

char **find_devices(char *key) {
  io_service_t io_reg_err;
  io_iterator_t iterator;
  int capacity = 10;

  char **cards = malloc(capacity * sizeof(char *));
  if (!cards) {
    fprintf(stderr, "Memory allocation failed\n");
    return NULL;
  }

  io_reg_err = IOServiceGetMatchingServices(
      kIOMainPortDefault, IOServiceMatching(IOSERVICE_GPU), &iterator);
  if (io_reg_err != KERN_SUCCESS) {
    printf("Error getting GPU entry\n");
    return NULL;
  }

  io_object_t service;
  int index = 0;
  while ((service = IOIteratorNext(iterator)) != MACH_PORT_NULL) {
    CFStringRef cfStr = CFStringCreateWithCString(kCFAllocatorDefault, key,
                                                  kCFStringEncodingUTF8);
    char *result = find_properties(service, 0, cfStr, CFSTR(""));
    CFRelease(cfStr);
    IOObjectRelease(service);

    if (result != NULL) {
      if (index >= capacity) {
        capacity += 1;
        char **new_cards = (char **)realloc(cards, capacity * sizeof(char *));
        if (!new_cards) {
          fprintf(stderr, "Memory reallocation failed\n");
          for (int i = 0; i < index; i++) {
            free(cards[i]);
          }
          free(cards);
          free(result);
          return NULL;
        }
        cards = new_cards;
      }
      cards[index] = result;
      index++;
    }

    if (result == NULL && strcmp(key, "model") == 0) {
      IOObjectRelease(iterator);

      io_reg_err = IOServiceGetMatchingServices(
          kIOMainPortDefault, IOServiceMatching(IOSERVICE_PCI), &iterator);
      if (io_reg_err != KERN_SUCCESS) {
        printf("Error getting PCI entry\n");
        return NULL;
      }
    }
  }
  IOObjectRelease(iterator);

  char **result_cards = (char **)realloc(cards, sizeof(char *) * (index + 1));
  if (!result_cards) {
    fprintf(stderr, "Memory reallocation failed\n");
    for (int i = 0; i < index; i++) {
      free(cards[i]);
    }
    free(cards);
    return NULL;
  }
  result_cards[index] = NULL;

  return result_cards;
}

int find_utilization(char *key, char *dict_key) {
  void *result_ptr;
  io_service_t io_reg_err;
  io_iterator_t iterator;

  io_reg_err = IOServiceGetMatchingServices(
      kIOMainPortDefault, IOServiceMatching(IOSERVICE_GPU), &iterator);
  if (io_reg_err != KERN_SUCCESS) {
    printf("Error getting GPU entry\n");
    return 0;
  }

  io_object_t service = IOIteratorNext(iterator);
  if (service != MACH_PORT_NULL) {
    CFStringRef cfStr = CFStringCreateWithCString(kCFAllocatorDefault, key,
                                                  kCFStringEncodingUTF8);
    CFStringRef cfDictStr = CFStringCreateWithCString(
        kCFAllocatorDefault, dict_key, kCFStringEncodingUTF8);
    result_ptr = find_properties(service, 0, cfStr, cfDictStr);
    CFRelease(cfStr);
    CFRelease(cfDictStr);
  }

  IOObjectRelease(service);
  IOObjectRelease(iterator);

  if (result_ptr == NULL) {
    return 0;
  }

  return (int)(intptr_t)result_ptr;
}