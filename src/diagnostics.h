/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_DIAGNOSTICS_H
#define WEB_BROWSER_DIAGNOSTICS_H
#include <stdarg.h>
#include <time.h>
#include "hybrid_cache_io.h"
#include "jsc_cache.h"
#if FULLSCREEN_PASSIVE_DIAGNOSTICS
#define DIAG_BUILD "2026-10-28-passive-vm-diagnostics-v5"
#elif TEST_HBC_LIVE_PLAN
#define DIAG_BUILD "2026-10-28-test-community-1001-v10"
#elif TEST_HBC_EXPORT
#define DIAG_BUILD "2026-10-28-test-hbc-evidence-v7"
#elif FULLSCREEN_SAFE_SCAN
#define DIAG_BUILD "2026-10-28-test-open-home-v6"
#else
#define DIAG_BUILD "2026-10-28-community-1001-v10"
#endif
enum { DIAG_EVENTS=256, DIAG_EVENT_BYTES=192, DIAG_CAPACITY=54272 };
_Static_assert(DIAG_CAPACITY+HYBRID_CACHE_CAPACITY<INI_FILE_CAPACITY,"profile and report capacity");
struct diagnostic_report {
    uint32_t version,firmware,timestamp,pid,result,error_code,total,dropped,truncated;
    char build[64];
    char engine[16],operation[16],stage[64],reason[256],summary[256],cache[80];
    char hermes[8],jsc[8],events[DIAG_EVENTS][DIAG_EVENT_BYTES];
};
static struct diagnostic_report diagnostic;
static inline void diag_ascii(char *text) {
    for(unsigned char *p=(unsigned char *)text;*p;p++)if(*p<32 || *p>126)*p='?';
    char *start=text; while(*start==' ')start++;
    if(start!=text)memmove(text,start,strlen(start)+1);
    size_t n=strlen(text); while(n && text[n-1]==' ')text[--n]=0;
}
static inline void diag_text(char *out, size_t size, const char *text) {
    if(out==text)return;
    snprintf(out,size,"%s",text?text:""); diag_ascii(out);
}
static inline void diag_begin(uint32_t firmware, const char *operation) {
    memset(&diagnostic,0,sizeof(diagnostic)); diagnostic.version=2; diagnostic.firmware=firmware;
    diag_text(diagnostic.build,sizeof(diagnostic.build),DIAG_BUILD);
    time_t now=time(NULL); diagnostic.timestamp=now>0 && (uint64_t)now<=UINT32_MAX?(uint32_t)now:0;
    diag_text(diagnostic.operation,sizeof(diagnostic.operation),operation);
    diag_text(diagnostic.engine,sizeof(diagnostic.engine),"unknown");
    diag_text(diagnostic.hermes,sizeof(diagnostic.hermes),"unknown");
    diag_text(diagnostic.jsc,sizeof(diagnostic.jsc),"unknown");
    diag_text(diagnostic.stage,sizeof(diagnostic.stage),"startup");
}
static inline void diag_event(const char *format, ...) {
    char *out=diagnostic.events[diagnostic.total%DIAG_EVENTS];
    va_list args; va_start(args,format); int n=vsnprintf(out,DIAG_EVENT_BYTES,format,args); va_end(args);
    if(n<0)out[0]=0;
    if(n>=DIAG_EVENT_BYTES)diagnostic.truncated++;
    diag_ascii(out); diagnostic.total++;
    if(diagnostic.total>DIAG_EVENTS)diagnostic.dropped++;
}
static inline void diag_step(const char *stage) {
    diag_text(diagnostic.stage,sizeof(diagnostic.stage),stage);
    diagnostic.reason[0]=0; diagnostic.error_code=0;
}
static inline void diag_bytes(const char *label, const uint8_t *bytes, size_t length) {
    char hex[129]; if(length>64)length=64;
    for(size_t i=0;i<length;i++)snprintf(hex+i*2,3,"%02x",bytes[i]);
    hex[length*2]=0; diag_event("%s=%s",label,hex);
}
/* Retain complete bounded code/header windows, not just a function prologue. */
static inline void diag_span(const char *label, const uint8_t *bytes, size_t length) {
    size_t bounded=length>512?512:length;
    for(size_t at=0;at<bounded;at+=64) {
        char key[48]; snprintf(key,sizeof(key),"%.32s+%03zx",label,at);
        diag_bytes(key,bytes+at,bounded-at<64?bounded-at:64);
    }
    if(length>bounded)diag_event("%s: sample limited to %zu/%zu bytes",label,bounded,length);
}
static inline void diag_error(const char *stage, uint32_t code, const char *format, ...) {
    diag_text(diagnostic.stage,sizeof(diagnostic.stage),stage); diagnostic.error_code=code;
    va_list args; va_start(args,format); vsnprintf(diagnostic.reason,sizeof(diagnostic.reason),format,args); va_end(args);
    diag_ascii(diagnostic.reason);
    diag_event("%s: %s (code=0x%08x)",stage,diagnostic.reason,code);
}
static inline void diag_engine(int hermes, int jsc, const char *engine) {
    diag_text(diagnostic.engine,sizeof(diagnostic.engine),engine);
    diag_text(diagnostic.hermes,sizeof(diagnostic.hermes),hermes?"yes":"no");
    diag_text(diagnostic.jsc,sizeof(diagnostic.jsc),jsc?"yes":"no");
    diag_event("Engine detection: Hermes=%d JSC=%d selected=%s",hermes,jsc,engine);
}
static inline void diag_body(struct fp_writer *w, const struct diagnostic_report *d) {
    unsigned count=d->total<DIAG_EVENTS?d->total:DIAG_EVENTS;
    fp_write(w,"[diagnostics]\nformat=web-browser-fullscreen-failure\nversion=%u\n",d->version);
    if(d->version>=2)fp_write(w,"build=%s\n",d->build);
    fp_write(w,"timestamp_unix=%u\nfirmware=0x%08x\nengine=%s\noperation=%s\nresult=%u\nshellui_pid=%u\nhermes_loaded=%s\njsc_loaded=%s\nstage=%s\nreason=%s\nsummary=%s\nerror_code=0x%08x\ncache_state=%s\nevent_count=%u\nevents_dropped=%u\nevents_truncated=%u\n",
             d->timestamp,d->firmware,d->engine,d->operation,d->result,d->pid,d->hermes,d->jsc,d->stage,d->reason,d->summary,
             d->error_code,d->cache,count,d->dropped,d->truncated);
    for(unsigned i=0;i<count;i++) {
        unsigned slot=d->total<=DIAG_EVENTS?i:(d->total+i)%DIAG_EVENTS;
        fp_write(w,"event.%u=%s\n",i,d->events[slot]);
    }
}
static inline int diag_encode(const struct diagnostic_report *d, uint8_t *out, size_t capacity) {
    struct fp_writer w={.data=(char *)out,.capacity=capacity};
    if(!capacity)return -1;
    out[0]=0; diag_body(&w,d);
    if(w.failed)return -1;
    uint32_t crc=hc_crc(out,w.length); fp_write(&w,"crc32=0x%08x\n",crc);
    return w.failed?-1:(int)w.length;
}
static inline int diag_value(struct hc_reader *r, const char *key, char *out, size_t capacity) {
    const char *text=hc_value(r,key);
    if(!text || strlen(text)>=capacity)return -1;
    memcpy(out,text,strlen(text)+1); return 0;
}
/* The report's own CRC never participates in native-profile validation. */
static inline int diag_decode(const uint8_t *data, size_t length, struct diagnostic_report *d) {
    if(!length || length>=DIAG_CAPACITY || memchr(data,0,length))return -1;
    struct hc_reader r={.data=data,.length=length}; uint32_t version,count,crc;
    memset(d,0,sizeof(*d));
    if(hc_expect(&r,"[diagnostics]") || hc_match(&r,"format","web-browser-fullscreen-failure") ||
       hc_number(&r,"version",&version) || (version!=1 && version!=2))return -1;
    d->version=version;
    if(version>=2 && diag_value(&r,"build",d->build,sizeof(d->build)))return -1;
#define DN(key,field) if(hc_number(&r,key,&d->field))return -1
#define DT(key,field) if(diag_value(&r,key,d->field,sizeof(d->field)))return -1
    DN("timestamp_unix",timestamp); DN("firmware",firmware); DT("engine",engine); DT("operation",operation);
    DN("result",result); DN("shellui_pid",pid); DT("hermes_loaded",hermes); DT("jsc_loaded",jsc);
    DT("stage",stage); DT("reason",reason); DT("summary",summary); DN("error_code",error_code); DT("cache_state",cache);
    if(hc_number(&r,"event_count",&count) || count>(version==1?24U:DIAG_EVENTS))return -1;
    DN("events_dropped",dropped); DN("events_truncated",truncated);
#undef DN
#undef DT
    d->total=count;
    for(unsigned i=0;i<count;i++) {
        char key[32]; snprintf(key,sizeof(key),"event.%u",i);
        if(diag_value(&r,key,d->events[i],sizeof(d->events[i])))return -1;
    }
    if(hc_number(&r,"crc32",&crc) || hc_line(&r) || d->result>2)return -1;
    /* A successful test may retain export warnings or live-plan evidence. */
    if(!d->result && (d->version<2 || (strcmp(d->stage,"test.hermes_export") &&
                                     strcmp(d->stage,"test.hermes_live_plan"))))return -1;
    uint8_t canonical[DIAG_CAPACITY]; struct fp_writer w={.data=(char *)canonical,.capacity=sizeof(canonical)};
    diag_body(&w,d); return w.failed || hc_crc(canonical,w.length)!=crc?-1:0;
}
/* Preserve an existing text profile, even if rejected, for troubleshooting.
 * Binary/oversized files are never copied into a purported readable INI. */
static inline int diag_publish(const char *path) {
    uint8_t *file=malloc(INI_FILE_CAPACITY); if(!file)return -1;
    size_t length=0,prefix=0; int loaded=cache_file_read(path,file,INI_FILE_CAPACITY,&length);
    if(!loaded) {
        prefix=ini_profile_length(file,length);
        if(prefix>=HYBRID_CACHE_CAPACITY || (prefix && (prefix<7 || memcmp(file,"[cache]",7))))prefix=0;
        for(size_t i=0;i<prefix;i++)if((file[i]<32 && file[i]!='\n' && file[i]!='\r' && file[i]!='\t') || file[i]>126) { prefix=0; break; }
    }
    if(prefix && file[prefix-1]!='\n')file[prefix++]='\n';
    int n=diag_encode(&diagnostic,file+prefix,INI_FILE_CAPACITY-prefix);
    int result=n<0?-1:cache_file_write(path,file,prefix+(size_t)n);
    free(file); return result;
}
static inline int diag_clear(const char *path) {
    uint8_t *file=malloc(INI_FILE_CAPACITY); if(!file)return -1;
    size_t length=0; int result=cache_file_read(path,file,INI_FILE_CAPACITY,&length);
    if(result) { free(file); return result==HC_FILE_MISSING?0:-1; }
    size_t prefix=ini_profile_length(file,length);
    if(prefix==length)result=0;
    else if(prefix)result=cache_file_write(path,file,prefix);
    else result=unlink(path);
    free(file); return result;
}
static inline void diag_print(const struct diagnostic_report *d) {
    printf("Diagnostics format=%u build=%s\n",d->version,d->version>=2?d->build:"legacy");
    printf("Last operation diagnostics: timestamp=%u firmware=%08x engine=%s operation=%s result=%u\nStage: %s\nReason: %s\nSummary: %s\nError code: 0x%08x; cache: %s\n",
           d->timestamp,d->firmware,d->engine,d->operation,d->result,d->stage,d->reason,d->summary,d->error_code,d->cache);
    printf("ShellUI PID: %u; loaded Hermes=%s JSC=%s; events dropped=%u truncated=%u\n",d->pid,d->hermes,d->jsc,d->dropped,d->truncated);
    unsigned count=d->total<DIAG_EVENTS?d->total:DIAG_EVENTS;
    for(unsigned i=0;i<count;i++)printf("  %s\n",d->events[i]);
}
#undef DIAG_STEP
#undef DIAG_EVENT
#undef DIAG_ERROR
#undef DIAG_ENGINE
#undef DIAG_BYTES
#undef DIAG_SPAN
#define DIAG_STEP(...) diag_step(__VA_ARGS__)
#define DIAG_EVENT(...) diag_event(__VA_ARGS__)
#define DIAG_ERROR(...) diag_error(__VA_ARGS__)
#define DIAG_ENGINE(...) diag_engine(__VA_ARGS__)
#define DIAG_BYTES(...) diag_bytes(__VA_ARGS__)
#define DIAG_SPAN(...) diag_span(__VA_ARGS__)
#endif
