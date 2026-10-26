/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_FIXED_PROFILE_TYPES_H
#define FULLSCREEN_FIXED_PROFILE_TYPES_H
#include <stddef.h>
#include <stdint.h>
#include "hbc_patch.h"
struct fixed_source { uint8_t header[128]; struct hbc_plan plan; };
struct fixed_profile {
    const char *version;
    uint32_t firmware;
    uintptr_t registry_rva, runtime_owner_offset, module_list_offset, module_runtime_offset;
    uintptr_t provider_offset, provider_vtable_rva, buffer_object_offset, buffer_data_offset, buffer_length_offset, fingerprint_rva;
    uint8_t fingerprint[32];
    struct fixed_source sources[2];
};
#endif

