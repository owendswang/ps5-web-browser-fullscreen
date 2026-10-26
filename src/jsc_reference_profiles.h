/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_JSC_REFERENCE_PROFILES_H
#define WEB_BROWSER_JSC_REFERENCE_PROFILES_H
#include "jsc_profile_types.h"
/* JavaScriptCore layouts are separate from Hermes object/HBC profiles. */
static const struct jsc_reference_profile jsc_reference_profiles[]={
    {.firmware=0x04030000, .entry_length=20, .entry_rva=0x7baa0, .code_rva=0x939610, .constants_rva=0xa96510,
     .fingerprint={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec,
                   0xd8,0x00,0x00,0x00,0x4c,0x8b,0x3d,0x9d,0xac,0xa4,0x00,0x4c,0x89,0x8d,0x20,0xff}},
};
static inline const struct jsc_reference_profile *jsc_profile_for_firmware(uint32_t firmware) {
    for(unsigned i=0;i<sizeof(jsc_reference_profiles)/sizeof(*jsc_reference_profiles);i++)
        if(jsc_reference_profiles[i].firmware==firmware)return &jsc_reference_profiles[i];
    return NULL;
}
#endif
