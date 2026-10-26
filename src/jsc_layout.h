/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_JSC_LAYOUT_H
#define WEB_BROWSER_JSC_LAYOUT_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "jsc_profile_types.h"
#include "jsc_hook_blob.h"
enum { JSC_ENTRY_BYTES=32, JSC_CODE_BYTES=0x1100, JSC_CONSTANT_BYTES=0x1000,
       JSC_ENABLE_OFFSET=JSC_HOOK_STATE_OFFSET+10*8 };
_Static_assert(sizeof(jsc_hook_blob)<=0x1000,"JSC code capacity");
_Static_assert(sizeof(jsc_hook_constants)<=JSC_CONSTANT_BYTES,"JSC constant capacity");
_Static_assert(JSC_HOOK_STATE_OFFSET+11*8<=sizeof(jsc_hook_constants),"JSC API table bounds");
static inline int jsc_zero(const uint8_t *data, size_t size) {
    for(size_t i=0;i<size;i++)if(data[i])return 0;
    return 1;
}
/* Only complete, position-independent frame/register/stack setup instructions
 * may be copied to the trampoline. Unrecognized prologues fail closed. */
static inline unsigned jsc_prologue(const uint8_t bytes[32]) {
    unsigned at=0;
    if(!memcmp(bytes,"\xf3\x0f\x1e\xfa",4))at=4;
    if(memcmp(bytes+at,"\x55\x48\x89\xe5",4))return 0;
    at+=4;
    for(;;) {
        unsigned n=0;
        if(at<32 && bytes[at]>=0x50 && bytes[at]<=0x57)n=1;
        else if(at+2<=32 && bytes[at]==0x41 && bytes[at+1]>=0x50 && bytes[at+1]<=0x57)n=2;
        else if(at+4<=32 && bytes[at]==0x48 && bytes[at+1]==0x83 &&
                (bytes[at+2]==0xec || bytes[at+2]==0xe4))n=4;
        else if(at+7<=32 && bytes[at]==0x48 && bytes[at+1]==0x81 && bytes[at+2]==0xec)n=7;
        if(!n)break;
        at+=n;
    }
    return at>=5?at:0;
}
static inline int jsc_profile_valid(const struct jsc_reference_profile *p) {
    return !p->firmware || p->entry_length<5 || p->entry_length>32 ||
        jsc_prologue(p->fingerprint)!=p->entry_length ||
        p->entry_rva>0x10000000-32 || !p->code_rva || p->code_rva>0x10000000-JSC_CODE_BYTES ||
        !p->constants_rva || p->constants_rva>0x10000000-JSC_CONSTANT_BYTES ||
        (p->code_rva&15) || (p->constants_rva&15) ||
        (p->code_rva<p->constants_rva+JSC_CONSTANT_BYTES && p->constants_rva<p->code_rva+JSC_CODE_BYTES);
}
static inline int jsc_jump(uint8_t *out, uintptr_t address, uintptr_t destination) {
    int64_t displacement=(int64_t)destination-(int64_t)address-5;
    if(displacement<INT32_MIN || displacement>INT32_MAX)return -1;
    int32_t relative=(int32_t)displacement;
    out[0]=0xe9; memcpy(out+1,&relative,4); return 0;
}
static inline int jsc_build_image(const struct jsc_reference_profile *p, uintptr_t base, const uintptr_t state[11],
                                uint8_t code[JSC_CODE_BYTES], uint8_t constants[JSC_CONSTANT_BYTES], uint8_t detour[32]) {
    if(jsc_profile_valid(p))return -1;
    memset(code,0,JSC_CODE_BYTES); memset(constants,0,JSC_CONSTANT_BYTES);
    memcpy(code,jsc_hook_blob,sizeof(jsc_hook_blob));
    int64_t adjustment=(int64_t)p->constants_rva-(int64_t)p->code_rva-JSC_HOOK_CONSTANTS_DELTA;
    for(unsigned i=0;i<sizeof(jsc_hook_constant_fixups)/sizeof(*jsc_hook_constant_fixups);i++) {
        unsigned offset=jsc_hook_constant_fixups[i]; int32_t displacement;
        if(offset>sizeof(jsc_hook_blob)-4)return -1;
        memcpy(&displacement,code+offset,4);
        int64_t updated=(int64_t)displacement+adjustment;
        if(updated<INT32_MIN || updated>INT32_MAX)return -1;
        displacement=(int32_t)updated; memcpy(code+offset,&displacement,4);
    }
    memcpy(constants,jsc_hook_constants,sizeof(jsc_hook_constants));
    memcpy(constants+JSC_HOOK_STATE_OFFSET,state,11*8);
    memcpy(code+0x1000,p->fingerprint,p->entry_length);
    if(jsc_jump(code+0x1000+p->entry_length,base+p->code_rva+0x1000+p->entry_length,base+p->entry_rva+p->entry_length))return -1;
    memcpy(code+0x1040,"JSCFS4V4",8);
    memset(detour,0x90,32); return jsc_jump(detour,base+p->entry_rva,base+p->code_rva);
}
#endif
