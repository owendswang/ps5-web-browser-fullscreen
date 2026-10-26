/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_HYBRID_CACHE_H
#define FULLSCREEN_HYBRID_CACHE_H
/* Readable INI cache. No C pointers, native padding or heap addresses. */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "fixed_profile_types.h"
#include "fixed_profile_export.h"
#include "ini_sections.h"
#define HYBRID_CACHE_CAPACITY 8192U
#define HYBRID_CACHE_VERSION 3U
#define HYBRID_PLAN_REVISION 1U
#ifndef HYBRID_CACHE_PATH
#define HYBRID_CACHE_PATH "/data/web-browser-fullscreen.ini"
#endif
struct hybrid_cache { uint32_t firmware; struct fixed_profile profile; };
static inline uint32_t hc_u32(const uint8_t *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static inline uint32_t hc_crc(const uint8_t *data, size_t size) {
    uint32_t crc=0xffffffffU;
    for(size_t i=0;i<size;i++) {
        crc^=data[i];
        for(unsigned b=0;b<8;b++)crc=(crc>>1)^(0xedb88320U&(0U-(crc&1)));
    }
    return ~crc;
}
static inline const char *hc_patch_name(unsigned id) {
    static const char *names[]={"height","width","browser_mount","browser_header"};
    return id<4?names[id]:NULL;
}
static inline int hc_valid(const struct hybrid_cache *c) {
    const struct fixed_profile *p=&c->profile;
    if(!c->firmware || p->firmware!=(c->firmware&0xffff0000U) ||
       !p->registry_rva || p->registry_rva>0xfffff8 || (p->registry_rva&7) ||
       p->runtime_owner_offset<8 || p->runtime_owner_offset>0x3ff8 || (p->runtime_owner_offset&7) ||
       p->module_list_offset<0x40 || p->module_list_offset>0x10000 || (p->module_list_offset&7) ||
       p->module_runtime_offset<16 || p->module_runtime_offset>56 || (p->module_runtime_offset&7) ||
       p->provider_offset<24 || p->provider_offset>184 || (p->provider_offset&7) ||
       !p->provider_vtable_rva || p->provider_vtable_rva>0xfffff8 || (p->provider_vtable_rva&7) ||
       p->buffer_object_offset<8 || p->buffer_object_offset>0x800 || (p->buffer_object_offset&7) ||
       p->buffer_data_offset<8 || p->buffer_data_offset>0x800 || (p->buffer_data_offset&7) ||
       p->buffer_data_offset==p->buffer_object_offset ||
       p->buffer_length_offset<8 || p->buffer_length_offset>56 || (p->buffer_length_offset&7) ||
       p->fingerprint_rva>0xffffe0)return -1;
    for(unsigned s=0;s<2;s++) {
        const struct fixed_source *source=&p->sources[s];
        if(memcmp(source->header,"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f",8) || hc_u32(source->header+8)!=89 ||
           hc_u32(source->header+32)<128 || hc_u32(source->header+32)>32U*1024*1024 ||
           source->plan.count!=(s?2U:4U))return -1;
        for(unsigned i=0;i<source->plan.count;i++) {
            const struct hbc_patch *patch=&source->plan.patches[i];
            if(!patch->name || strcmp(patch->name,hc_patch_name(i)) || !patch->length || patch->length>HBC_PATCH_BYTES ||
               patch->offset<128 || patch->offset>hc_u32(source->header+32)-patch->length)return -1;
            for(unsigned j=0;j<i;j++) {
                const struct hbc_patch *other=&source->plan.patches[j];
                if(patch->offset<other->offset+other->length && other->offset<patch->offset+patch->length)return -1;
            }
        }
    }
    return 0;
}
static inline void hc_hex(struct fp_writer *w, const uint8_t *bytes, size_t length) {
    for(size_t i=0;i<length;i++)fp_write(w,"%02x",bytes[i]);
    fp_write(w,"\n");
}
static inline void hc_body(struct fp_writer *w, const struct hybrid_cache *c) {
    fp_write(w,"[cache]\nformat=web-browser-fullscreen\nversion=%u\nengine=hermes\nplan_revision=%u\nfirmware=0x%08x\nmodule=libhermes-0.11.sprx\n\n[native]\n",
             HYBRID_CACHE_VERSION,HYBRID_PLAN_REVISION,c->firmware);
    const struct fixed_profile *p=&c->profile;
#define HC_FIELD(name) fp_write(w,#name "=0x%lx\n",(unsigned long)p->name)
    HC_FIELD(registry_rva); HC_FIELD(runtime_owner_offset); HC_FIELD(module_list_offset);
    HC_FIELD(module_runtime_offset); HC_FIELD(provider_offset); HC_FIELD(provider_vtable_rva);
    HC_FIELD(buffer_object_offset); HC_FIELD(buffer_data_offset); HC_FIELD(buffer_length_offset); HC_FIELD(fingerprint_rva);
#undef HC_FIELD
    fp_write(w,"fingerprint="); hc_hex(w,p->fingerprint,32);
    for(unsigned s=0;s<2;s++) {
        const struct fixed_source *source=&p->sources[s];
        const char *title=s?"NPXS40003":"NPXS40036";
        fp_write(w,"\n[%s]\nlength=%u\npatch_count=%u\nheader=",title,hc_u32(source->header+32),source->plan.count);
        hc_hex(w,source->header,128);
        for(unsigned i=0;i<source->plan.count;i++) {
            const struct hbc_patch *patch=&source->plan.patches[i];
            fp_write(w,"\n[%s.%s]\noffset=0x%x\nlength=%u\noriginal=",title,patch->name,patch->offset,patch->length);
            hc_hex(w,patch->before,patch->length); fp_write(w,"replacement="); hc_hex(w,patch->after,patch->length);
        }
    }
}
/* The checksum covers the canonical body, so CRLF, blank lines, hex case and
 * whitespace around values do not change a record's identity. */
static inline int hc_encode(const struct hybrid_cache *c, uint8_t *out, size_t capacity) {
    if(!capacity || hc_valid(c))return -1;
    struct fp_writer w={.data=(char *)out,.capacity=capacity}; out[0]=0;
    hc_body(&w,c);
    if(w.failed)return -1;
    uint32_t crc=hc_crc(out,w.length);
    fp_write(&w,"\n[integrity]\ncrc32=0x%08x\n",crc);
    return w.failed?-1:(int)w.length;
}
struct hc_reader { const uint8_t *data; size_t length, at; char line[600]; };
static inline int hc_space(unsigned char c) { return c==' ' || c=='\t' || c=='\r'; }
static inline int hc_line(struct hc_reader *r) {
    while(r->at<r->length) {
        size_t start=r->at;
        while(r->at<r->length && r->data[r->at]!='\n')r->at++;
        size_t end=r->at;
        if(r->at<r->length)r->at++;
        while(start<end && hc_space(r->data[start]))start++;
        while(end>start && hc_space(r->data[end-1]))end--;
        if(start==end)continue;
        if(end-start>=sizeof(r->line))return -1;
        for(size_t i=start;i<end;i++)if((r->data[i]<32 && r->data[i]!='\t') || r->data[i]>126)return -1;
        memcpy(r->line,r->data+start,end-start); r->line[end-start]=0; return 1;
    }
    return 0;
}
static inline int hc_expect(struct hc_reader *r, const char *line) {
    return hc_line(r)==1 && !strcmp(r->line,line)?0:-1;
}
static inline char *hc_value(struct hc_reader *r, const char *key) {
    if(hc_line(r)!=1)return NULL;
    char *equal=strchr(r->line,'=');
    if(!equal)return NULL;
    char *end=equal; while(end>r->line && hc_space(end[-1]))end--;
    *end=0;
    if(strcmp(r->line,key))return NULL;
    char *value=equal+1; while(hc_space(*value))value++;
    return value;
}
static inline int hc_number(struct hc_reader *r, const char *key, uint32_t *out) {
    char *value=hc_value(r,key), *end;
    if(!value || !*value || *value=='-' || *value=='+')return -1;
    errno=0; unsigned long number=strtoul(value,&end,0);
    if(errno || *end || number>UINT32_MAX)return -1;
    *out=(uint32_t)number; return 0;
}
static inline int hc_match(struct hc_reader *r, const char *key, const char *expected) {
    const char *value=hc_value(r,key); return value && !strcmp(value,expected)?0:-1;
}
static inline int hc_unhex(struct hc_reader *r, const char *key, uint8_t *out, size_t length) {
    const char *value=hc_value(r,key);
    if(!value || strlen(value)!=length*2)return -1;
    for(size_t i=0;i<length;i++) {
        unsigned byte=0;
        for(unsigned j=0;j<2;j++) {
            unsigned char c=value[i*2+j]; unsigned digit;
            if(c>='0' && c<='9')digit=c-'0';
            else if(c>='a' && c<='f')digit=c-'a'+10;
            else if(c>='A' && c<='F')digit=c-'A'+10;
            else return -1;
            byte=byte*16+digit;
        }
        out[i]=(uint8_t)byte;
    }
    return 0;
}
static inline int hc_decode(const uint8_t *data, size_t length, uint32_t firmware, struct hybrid_cache *c) {
    if(length>=INI_FILE_CAPACITY)return -1;
    length=ini_profile_length(data,length);
    if(!length || length>=HYBRID_CACHE_CAPACITY || memchr(data,0,length))return -1;
    struct hc_reader r={.data=data,.length=length}; uint32_t version,revision,expected_crc,value;
    memset(c,0,sizeof(*c));
    if(hc_expect(&r,"[cache]") || hc_match(&r,"format","web-browser-fullscreen") ||
       hc_number(&r,"version",&version) || version!=HYBRID_CACHE_VERSION ||
       hc_match(&r,"engine","hermes") ||
       hc_number(&r,"plan_revision",&revision) || revision!=HYBRID_PLAN_REVISION ||
       hc_number(&r,"firmware",&c->firmware) || (firmware && c->firmware!=firmware) ||
       hc_match(&r,"module","libhermes-0.11.sprx") || hc_expect(&r,"[native]"))return -1;
    struct fixed_profile *p=&c->profile; p->version="text disk cache"; p->firmware=c->firmware&0xffff0000U;
#define HC_FIELD(name) if(hc_number(&r,#name,&value))return -1; p->name=value
    HC_FIELD(registry_rva); HC_FIELD(runtime_owner_offset); HC_FIELD(module_list_offset);
    HC_FIELD(module_runtime_offset); HC_FIELD(provider_offset); HC_FIELD(provider_vtable_rva);
    HC_FIELD(buffer_object_offset); HC_FIELD(buffer_data_offset); HC_FIELD(buffer_length_offset); HC_FIELD(fingerprint_rva);
#undef HC_FIELD
    if(hc_unhex(&r,"fingerprint",p->fingerprint,32))return -1;
    for(unsigned s=0;s<2;s++) {
        struct fixed_source *source=&p->sources[s];
        const char *title=s?"NPXS40003":"NPXS40036"; char section[80]; uint32_t size;
        snprintf(section,sizeof(section),"[%s]",title);
        if(hc_expect(&r,section) || hc_number(&r,"length",&size) ||
           hc_number(&r,"patch_count",&source->plan.count) || source->plan.count!=(s?2U:4U) ||
           hc_unhex(&r,"header",source->header,128) || size!=hc_u32(source->header+32))return -1;
        for(unsigned i=0;i<source->plan.count;i++) {
            struct hbc_patch *patch=&source->plan.patches[i]; patch->name=hc_patch_name(i);
            snprintf(section,sizeof(section),"[%s.%s]",title,patch->name);
            if(hc_expect(&r,section) || hc_number(&r,"offset",&patch->offset) ||
               hc_number(&r,"length",&size) || !size || size>HBC_PATCH_BYTES)return -1;
            patch->length=(uint8_t)size;
            if(hc_unhex(&r,"original",patch->before,size) || hc_unhex(&r,"replacement",patch->after,size))return -1;
        }
    }
    if(hc_expect(&r,"[integrity]") || hc_number(&r,"crc32",&expected_crc) || hc_line(&r)!=0 || hc_valid(c))return -1;
    char canonical[HYBRID_CACHE_CAPACITY];
    struct fp_writer w={.data=canonical,.capacity=sizeof(canonical)}; hc_body(&w,c);
    return !w.failed && hc_crc((const uint8_t *)canonical,w.length)==expected_crc?0:-1;
}
static inline int hc_from_native(struct hybrid_cache *cache, const struct fp_native *n,
                                  const struct fp_source sources[2]) {
    memset(cache,0,sizeof(*cache)); cache->firmware=n->firmware;
    struct fixed_profile *p=&cache->profile; p->version="fresh discovery"; p->firmware=n->firmware&0xffff0000U;
#define HC_COPY(field, native_field) p->field=n->native_field
    HC_COPY(registry_rva,registry_rva); HC_COPY(runtime_owner_offset,runtime_owner_offset);
    HC_COPY(module_list_offset,module_list_offset); HC_COPY(module_runtime_offset,module_runtime_offset);
    HC_COPY(provider_offset,provider_offset); HC_COPY(provider_vtable_rva,provider_vtable_rva);
    HC_COPY(buffer_object_offset,buffer_object_offset); HC_COPY(buffer_data_offset,buffer_data_offset);
    HC_COPY(buffer_length_offset,buffer_length_offset); HC_COPY(fingerprint_rva,fingerprint_rva);
#undef HC_COPY
    memcpy(p->fingerprint,n->fingerprint,32);
    for(unsigned i=0;i<2;i++) {
        memcpy(p->sources[i].header,sources[i].header,128); p->sources[i].plan=*sources[i].plan;
    }
    return hc_valid(cache);
}
#endif

