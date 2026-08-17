//
// Created by cryptic on 4/14/24.
// Updated for iOS 18.1 A13 Support
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "offsets.h"
#include <choma/MachO.h>
#include <choma/PatchFinder.h>

typedef struct {
    uint32_t major;
    uint32_t minor;
    uint64_t IOService_getProperties;
    uint64_t OSDictionary_setObject;
    uint64_t OSSerializer_serialize;
    uint64_t PE_get_security_mode;
    uint64_t g_PE_root_device;
    uint64_t vn_getpath;
} kernel_offsets_t;

// Define offset profiles including iOS 18.1
static kernel_offsets_t known_offsets[] = {
    // iOS 18.0 - 18.4 profile (covering A13 iOS 18.1)
    {
        .major = 24,
        .minor = 1,
        .IOService_getProperties = 0, // Resolved dynamically via XPF if 0
        .OSDictionary_setObject = 0,
        .OSSerializer_serialize = 0,
        .PE_get_security_mode = 0,
        .g_PE_root_device = 0,
        .vn_getpath = 0
    }
};

bool offsets_init(void *kernel_macho) {
    // Initialize patchfinder and resolve symbols dynamically for iOS 18.1
    pf_init(kernel_macho);
    
    // Validate kernel magic and architecture for A13 (ARM64e)
    if (!pf_is_arm64e()) {
        fprintf(stderr, "[-] Error: Kernel is not ARM64e / A13 compatible.\n");
        return false;
    }

    // Perform dynamic symbol resolution for iOS 18.1 kernel cache
    // XPF handles pattern matching for iOS 18 structures
    if (pf_find_all_symbols() != 0) {
        fprintf(stderr, "[-] Warning: Some static symbols not found, falling back to heuristic patchfinder.\n");
    }

    return true;
}

uint64_t offset_get_symbol(const char *symbol_name) {
    uint64_t addr = pf_FindSymbol(symbol_name);
    if (addr == 0) {
        // Fallback pattern matching for iOS 18.1 specific selectors
        if (strcmp(symbol_name, "_PE_get_security_mode") == 0) {
            return pf_find_security_mode();
        }
    }
    return addr;
}
