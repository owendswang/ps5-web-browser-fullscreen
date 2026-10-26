/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_JSC_PROFILE_TYPES_H
#define WEB_BROWSER_JSC_PROFILE_TYPES_H
#include <stdint.h>
#include <stddef.h>
struct jsc_reference_profile {
    uint32_t firmware, entry_length;
    uintptr_t entry_rva, code_rva, constants_rva;
    uint8_t fingerprint[32];
};
#endif
