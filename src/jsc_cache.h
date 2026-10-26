/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_JSC_CACHE_H
#define WEB_BROWSER_JSC_CACHE_H
#include "hybrid_cache.h"
#include "cache_file.h"
#include "jsc_layout.h"
/* Native identities and relative offsets only; no absolute runtime pointers. */
static inline uint32_t jc_recipe_crc(void) {
    return hc_crc(jsc_hook_blob,sizeof(jsc_hook_blob)) ^ hc_crc(jsc_hook_constants,sizeof(jsc_hook_constants)) ^
           hc_crc((const uint8_t *)jsc_hook_constant_fixups,sizeof(jsc_hook_constant_fixups));
}
static inline void jc_body(struct fp_writer *w, const struct jsc_reference_profile *p) {
    fp_write(w,"[cache]\nformat=web-browser-fullscreen\nversion=%u\nengine=jsc\nplan_revision=1\nfirmware=0x%08x\nmodule=libSceJsc.sprx\nhook_crc32=0x%08x\n\n[native]\n",
             HYBRID_CACHE_VERSION,p->firmware,jc_recipe_crc());
    fp_write(w,"entry_rva=0x%lx\nentry_length=%u\ncode_rva=0x%lx\nconstants_rva=0x%lx\nfingerprint=",
             (unsigned long)p->entry_rva,p->entry_length,(unsigned long)p->code_rva,(unsigned long)p->constants_rva);
    hc_hex(w,p->fingerprint,32);
}
static inline int jc_encode(const struct jsc_reference_profile *p, uint8_t *out, size_t capacity) {
    if(!capacity || jsc_profile_valid(p))return -1;
    struct fp_writer w={.data=(char *)out,.capacity=capacity}; out[0]=0;
    jc_body(&w,p);
    if(w.failed)return -1;
    uint32_t crc=hc_crc(out,w.length);
    fp_write(&w,"\n[integrity]\ncrc32=0x%08x\n",crc);
    return w.failed?-1:(int)w.length;
}
static inline int jc_decode(const uint8_t *data, size_t length, uint32_t firmware, struct jsc_reference_profile *p) {
    if(length>=INI_FILE_CAPACITY)return -1;
    length=ini_profile_length(data,length);
    if(!length || length>=HYBRID_CACHE_CAPACITY || memchr(data,0,length))return -1;
    struct hc_reader r={.data=data,.length=length}; uint32_t version,revision,recipe,value,checksum;
    memset(p,0,sizeof(*p));
    if(hc_expect(&r,"[cache]") || hc_match(&r,"format","web-browser-fullscreen") ||
       hc_number(&r,"version",&version) || version!=HYBRID_CACHE_VERSION || hc_match(&r,"engine","jsc") ||
       hc_number(&r,"plan_revision",&revision) || revision!=1 ||
       hc_number(&r,"firmware",&p->firmware) || (firmware && firmware!=p->firmware) ||
       hc_match(&r,"module","libSceJsc.sprx") || hc_number(&r,"hook_crc32",&recipe) || recipe!=jc_recipe_crc() ||
       hc_expect(&r,"[native]"))return -1;
#define JC_FIELD(name) if(hc_number(&r,#name,&value))return -1; p->name=value
    JC_FIELD(entry_rva); JC_FIELD(entry_length); JC_FIELD(code_rva); JC_FIELD(constants_rva);
#undef JC_FIELD
    if(hc_unhex(&r,"fingerprint",p->fingerprint,32) || hc_expect(&r,"[integrity]") ||
       hc_number(&r,"crc32",&checksum) || hc_line(&r) || jsc_profile_valid(p))return -1;
    char canonical[HYBRID_CACHE_CAPACITY]; struct fp_writer w={.data=canonical,.capacity=sizeof(canonical)};
    jc_body(&w,p); return w.failed || hc_crc((uint8_t *)canonical,w.length)!=checksum?-1:0;
}
static inline int jc_load(const char *path, uint32_t firmware, struct jsc_reference_profile *p) {
    uint8_t data[INI_FILE_CAPACITY]; size_t length=0;
    int result=cache_file_read(path,data,sizeof(data),&length);
    return result?result:jc_decode(data,length,firmware,p)?HC_CONTENT_REJECTED:0;
}
static inline int jc_save(const char *path, const struct jsc_reference_profile *p) {
    uint8_t data[HYBRID_CACHE_CAPACITY]; int length=jc_encode(p,data,sizeof(data));
    return length<0?-1:cache_file_write(path,data,(size_t)length);
}
static inline int jc_same(const struct jsc_reference_profile *a, const struct jsc_reference_profile *b) {
    return a->firmware==b->firmware && a->entry_length==b->entry_length && a->entry_rva==b->entry_rva &&
        a->code_rva==b->code_rva && a->constants_rva==b->constants_rva && !memcmp(a->fingerprint,b->fingerprint,32);
}
#endif
