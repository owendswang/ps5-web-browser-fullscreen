/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_FIXED_PROFILE_EXPORT_H
#define FULLSCREEN_FIXED_PROFILE_EXPORT_H
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "hbc_patch.h"

struct fp_native {
    uint32_t firmware;
    uintptr_t registry_rva, runtime_owner_offset, module_list_offset, module_runtime_offset;
    uintptr_t provider_offset, provider_vtable_rva, buffer_object_offset, buffer_data_offset, buffer_length_offset;
    uintptr_t fingerprint_rva;
    uint8_t fingerprint[32];
};
struct fp_source { const char *title; const uint8_t *header; size_t length; const struct hbc_plan *plan; };
struct fp_writer { char *data; size_t length, capacity; int failed; };
static inline void fp_write(struct fp_writer *w, const char *format, ...) {
    if(w->failed)return;
    va_list args; va_start(args,format);
    int n=vsnprintf(w->data+w->length,w->capacity-w->length,format,args);
    va_end(args);
    if(n<0 || (size_t)n>=w->capacity-w->length) { w->failed=1; return; }
    w->length+=(size_t)n;
}
static inline void fp_hex(struct fp_writer *w, const uint8_t *data, size_t length) {
    static const char digits[]="0123456789abcdef";
    if(w->failed || length>(SIZE_MAX-3)/2 || 2*length+3>w->capacity-w->length) { w->failed=1; return; }
    w->data[w->length++]='"';
    for(size_t i=0;i<length;i++) {
        w->data[w->length++]=digits[data[i]>>4]; w->data[w->length++]=digits[data[i]&15];
    }
    w->data[w->length++]='"'; w->data[w->length]=0;
}
static inline void fp_string(struct fp_writer *w, const char *s) {
    fp_write(w,"\"");
    for(const unsigned char *p=(const unsigned char *)s;*p;p++) {
        if(*p=='"' || *p=='\\')fp_write(w,"\\%c",*p);
        else if(*p<32)fp_write(w,"\\u%04x",*p);
        else fp_write(w,"%c",*p);
    }
    fp_write(w,"\"");
}
/* One bounded, self-contained line. No absolute heap addresses are exported. */
static inline int fp_serialize(char *out, size_t capacity, const struct fp_native *n,
                               const struct fp_source *sources, size_t count) {
    if(!capacity || count!=2)return -1;
    struct fp_writer w={.data=out,.capacity=capacity}; out[0]=0;
    fp_write(&w,"FIXED_PROFILE_V1 {\"schema\":1,\"firmware\":\"0x%08x\",\"module\":\"libhermes-0.11.sprx\"",n->firmware);
#define FP_FIELD(name) fp_write(&w,",\"" #name "\":\"0x%lx\"",(unsigned long)n->name)
    FP_FIELD(registry_rva); FP_FIELD(runtime_owner_offset); FP_FIELD(module_list_offset);
    FP_FIELD(module_runtime_offset); FP_FIELD(provider_offset); FP_FIELD(provider_vtable_rva);
    FP_FIELD(buffer_object_offset); FP_FIELD(buffer_data_offset); FP_FIELD(buffer_length_offset); FP_FIELD(fingerprint_rva);
#undef FP_FIELD
    fp_write(&w,",\"fingerprint\":"); fp_hex(&w,n->fingerprint,32);
    fp_write(&w,",\"sources\":[");
    for(size_t i=0;i<count;i++) {
        const struct fp_source *s=&sources[i];
        if(!s->plan || s->plan->count>HBC_PATCH_MAX)return -1;
        fp_write(&w,"%s{\"title\":",i?",":""); fp_string(&w,s->title);
        fp_write(&w,",\"length\":%zu,\"header\":",s->length); fp_hex(&w,s->header,128);
        fp_write(&w,",\"patches\":[");
        for(unsigned j=0;j<s->plan->count;j++) {
            const struct hbc_patch *p=&s->plan->patches[j];
            if(!p->length || p->length>HBC_PATCH_BYTES)return -1;
            fp_write(&w,"%s{\"name\":",j?",":""); fp_string(&w,p->name);
            fp_write(&w,",\"offset\":%u,\"length\":%u,\"original\":",p->offset,p->length);
            fp_hex(&w,p->before,p->length); fp_write(&w,",\"replacement\":"); fp_hex(&w,p->after,p->length);
            fp_write(&w,"}");
        }
        fp_write(&w,"]}");
    }
    fp_write(&w,"]}");
    return w.failed?-1:(int)w.length;
}
#endif

