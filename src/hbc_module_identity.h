/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Associated strings require a verified native fingerprint and layout.
 * Their semantic labels are not proven names or source URLs. */
#ifndef HBC_MODULE_IDENTITY_H
#define HBC_MODULE_IDENTITY_H
#include "hbc_candidate_export.h"
struct hmi_context { struct ha_reader *reader; struct ha_layout *layout; int pid; unsigned enabled; };
static struct {
    unsigned used,reads; size_t bytes;
    struct { int pid; uintptr_t module,buffer; } seen[4];
} hmi_budget;
static inline int hmi_read(struct hmi_context *c,uintptr_t address,void *out,size_t size) {
    if(address<0x10000 || address>=0x100000000000ULL || size>0x100000000000ULL-address)return -1;
    uint8_t *p=out;
    while(size) {
        size_t part=4096-(address&4095); if(part>size)part=size;
        if(hmi_budget.reads>=64 || part>4096-hmi_budget.bytes)return -1;
        hmi_budget.reads++; hmi_budget.bytes+=part;
        if(c->reader->read(c->reader->context,address,p,part))return -1;
        p+=part; address+=part; size-=part;
    }
    return 0;
}
struct hmi_text { uint64_t length; unsigned truncated,sanitized; char text[97]; };
static inline const char *hmi_string(struct hmi_context *c,uintptr_t wrapper,struct hmi_text *out) {
    uint8_t value[40],after[40]; memset(out,0,sizeof(*out));
    if(hmi_read(c,wrapper,value,sizeof(value)))return "wrapper_read_failed";
    uint64_t length=ha_u64(value+24),capacity=ha_u64(value+32);
    out->length=length;
    if(length>capacity || capacity>1024*1024 || length>4096)return "invalid_length_capacity";
    size_t n=length>96?96:(size_t)length; out->truncated=length>n;
    if(capacity<16) {
        if(length>15)return "invalid_inline_length";
        memcpy(out->text,value+8,n);
    } else if(n && hmi_read(c,ha_u64(value+8),out->text,n))return "text_read_failed";
    if(hmi_read(c,wrapper,after,sizeof(after)) || memcmp(value,after,sizeof(value)))return "wrapper_changed";
    for(size_t i=0;i<n;i++)if((unsigned char)out->text[i]<32 || (unsigned char)out->text[i]>126) {
        out->text[i]='?'; out->sanitized=1;
    }
    out->text[n]=0;
    return length?"ok":"empty";
}
static inline unsigned hmi_profile(uintptr_t collector_rva,const uint8_t *code) {
    static const uint8_t fingerprint[32]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec,
        0x08,0x03,0x00,0x00,0x48,0x8b,0x05,0x55,0xa3,0x27,0x00,0x48,0x89,0xbd,0x50,0xfd};
    return collector_rva==0x2ac0 && !memcmp(code,fingerprint,32);
}
static void hmi_observe(void *context,uintptr_t runtime,uintptr_t module,uintptr_t provider,uintptr_t buffer,const uint8_t *header) {
    struct hmi_context *c=context;
    if(!hbc_candidate_header(header) || hbc_candidate_length(header)<1024*1024)return;
    for(unsigned i=0;i<hmi_budget.used;i++)if(hmi_budget.seen[i].pid==c->pid &&
        hmi_budget.seen[i].module==module && hmi_budget.seen[i].buffer==buffer)return;
    if(hmi_budget.used==4)return;
    unsigned at=hmi_budget.used++;
    hmi_budget.seen[at].pid=c->pid; hmi_budget.seen[at].module=module; hmi_budget.seen[at].buffer=buffer;
    DIAG_EVENT("HBC association base=%lx module=%lx runtime=%lx provider=%lx",buffer,module,runtime,provider);
    if(!c->enabled || c->layout->modules!=0x2450 || c->layout->runtime!=0x10 || c->layout->provider!=0x60 ||
       c->layout->raw.object!=0x120 || c->layout->raw.data!=0x130 || c->layout->raw.size!=0x10) {
        DIAG_EVENT("HBC associated strings unavailable: native fingerprint/layout unsupported"); return;
    }
    int saved_errno=errno;
    DIAG_EVENT("HBC associated string layout fingerprint verified; labels_unverified=yes");
    const uintptr_t wrappers[2]={module+0x80,runtime+0x460};
    const char *labels[2]={"module_text","runtime_text"};
    for(unsigned i=0;i<2;i++) {
        struct hmi_text text;
        const char *state=hmi_string(c,wrappers[i],&text);
        DIAG_EVENT("HBC %s base=%lx state=%s length=%llu truncated=%u sanitized=%u",labels[i],buffer,state,(unsigned long long)text.length,text.truncated,text.sanitized);
        if(!strcmp(state,"ok"))DIAG_EVENT("HBC %s value=%s",labels[i],text.text);
    }
    errno=saved_errno;
}
#endif
