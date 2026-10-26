/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_JSC_FULLSCREEN_H
#define WEB_BROWSER_JSC_FULLSCREEN_H
#include "jsc_reference_profiles.h"
#include "jsc_discovery.h"
#include "diagnostic_events.h"
#ifndef JSC_REFERENCE_LOOKUP
#define JSC_REFERENCE_LOOKUP jsc_profile_for_firmware
#endif
#ifndef JSC_NO_REFERENCE
#define JSC_NO_REFERENCE 0
#endif
static struct jsc_reference_profile jsc_record;
static int jsc_pending;
static const char *jsc_cache_status="not attempted";
static int jsc_write(int pid, uintptr_t address, const void *data, size_t size) {
    uint8_t check[JSC_CODE_BYTES];
    return size>sizeof(check) || kernel_proc_copyin(pid,data,address,size) ||
           jsc_read(pid,address,check,size) || memcmp(check,data,size);
}
static int jsc_entry_idle(int pid, uintptr_t target, unsigned length) {
    int count=trace_request(PT_GETNUMLWPS,pid,NULL,0), ids[512];
    if(count<=0 || count>512 || trace_request(PT_GETLWPLIST,pid,ids,count)!=count)return -1;
    for(int i=0;i<count;i++) {
        struct reg regs;
        if(trace_request(PT_GETREGS,ids[i],&regs,0))return -1;
        uintptr_t pc=(uintptr_t)regs.r_rip;
        if(pc>=target && pc<target+length) {
            puts("JSC entry is active on a stopped thread; retry later"); return -1;
        }
    }
    return 0;
}
static int jsc_select(struct jsc_context *c, struct jsc_snapshot *snapshot) {
    struct jsc_reference_profile disk;
    int cached=HC_FILE_MISSING,cache_loaded=0,reference_selected=0;
    const struct jsc_reference_profile *reference=JSC_NO_REFERENCE?NULL:JSC_REFERENCE_LOOKUP(c->original.firmware);
    const char *source=NULL;
    jsc_pending=0;
    if(reference) {
        DIAG_STEP("jsc.reference"); DIAG_EVENT("Trying exact-firmware JSC reference %08x",c->original.firmware);
        puts("JSC trying built-in reference");
        if(!jsc_validate(c,reference,snapshot)) { jsc_record=*reference; source="built-in reference"; reference_selected=1; }
        else { DIAG_EVENT("JSC reference rejected"); puts("JSC reference rejected; trying INI and discovery"); }
    } else DIAG_EVENT("No built-in JSC reference for %08x",c->original.firmware);
    if(!source) {
        cached=jc_load(HYBRID_CACHE_PATH,c->original.firmware,&disk); cache_loaded=1;
        jsc_cache_status=cached?hc_load_reason(cached):"loaded; pending live validation";
        DIAG_EVENT("JSC INI: %s",hc_load_reason(cached));
    }
    if(!source && !cached) {
        DIAG_STEP("jsc.cache");
        puts("JSC trying disk INI");
        if(!jsc_validate(c,&disk,snapshot)) { jsc_record=disk; source="INI"; }
        else { jsc_cache_status="rejected by live checks"; DIAG_EVENT("JSC INI rejected by native/segment/live checks"); puts("JSC INI rejected by native/segment/live checks; discovering again"); }
    } else if(!source && cached)printf("JSC INI: %s\n",hc_load_reason(cached));
    if(!source) {
        DIAG_STEP("jsc.discovery"); DIAG_EVENT("JSC dynamic discovery started");
        puts("JSC fallback: exported entry -> original prologue -> bounded ELF padding");
        if(jsc_discover(c,&jsc_record) || jsc_validate(c,&jsc_record,snapshot))return 1;
        source="dynamic discovery";
    } else if(snapshot->blank) {
        DIAG_STEP("jsc.retained_storage"); DIAG_EVENT("Checking for retained callback storage before using blank candidate");
        /* A blank table entry must not displace callback storage left by a
         * previous dynamically discovered layout after restore. */
        struct jsc_reference_profile discovered; struct jsc_snapshot existing;
        if(jsc_discover(c,&discovered) || jsc_validate(c,&discovered,&existing))return 1;
        if(existing.initialized && !jc_same(&jsc_record,&discovered)) {
            puts("JSC blank candidate superseded by retained callback storage");
            jsc_record=discovered; *snapshot=existing; source="dynamic discovery (retained storage)"; reference_selected=0;
        }
    }
    if(reference_selected) {
        jsc_cache_status="skipped (built-in reference)";
        puts("JSC built-in reference verified; INI cache not needed");
    } else {
        if(!cache_loaded)cached=jc_load(HYBRID_CACHE_PATH,c->original.firmware,&disk);
        jsc_pending=cached || !jc_same(&jsc_record,&disk);
        jsc_cache_status=jsc_pending?"refresh pending":"hit";
    }
    DIAG_EVENT("JSC selected %s: entry=+%lx length=%u code=+%lx constants=+%lx",source,jsc_record.entry_rva,jsc_record.entry_length,jsc_record.code_rva,jsc_record.constants_rva);
    printf("JSC plan source: %s; entry=+%lx length=%u code=+%lx constants=+%lx\n",
           source,(unsigned long)jsc_record.entry_rva,jsc_record.entry_length,
           (unsigned long)jsc_record.code_rva,(unsigned long)jsc_record.constants_rva);
    return 0;
}
/* Caller detaches before committing the selected relative profile to disk. */
static int jsc_run(int pid, int *attached, const char **failure) {
    struct jsc_context context; struct jsc_snapshot snapshot;
    DIAG_STEP("jsc.bind");
    *failure="JSC native image or exports unavailable";
    if(jsc_bind_context(pid,&context))return 1;
    *failure="cannot stop ShellUI for JSC validation";
    if(trace(PT_ATTACH,pid)) { DIAG_ERROR("jsc.attach",errno,"Cannot attach to ShellUI"); return 1; }
    *attached=1;
    int status=0;
    if(waitpid(pid,&status,0)!=pid || !WIFSTOPPED(status)) { DIAG_ERROR("jsc.stop",errno,"Cannot confirm ShellUI stop"); return 1; }
    *failure="JSC reference, INI and discovery rejected";
    if(jsc_select(&context,&snapshot))return 1;
    const struct jsc_reference_profile *p=&jsc_record;
    uintptr_t cave=context.base+p->code_rva, data_cave=context.base+p->constants_rva;
    uint8_t code[JSC_CODE_BYTES],constants[JSC_CONSTANT_BYTES],detour[32];
    context.state[0]=cave+0x1000;
    if(jsc_build_image(p,context.base,context.state,code,constants,detour))return 1;
    printf("JSC verified: hook=%s enabled=%lu\n",snapshot.initialized?"installed":"absent",(unsigned long)snapshot.enabled);
    if(LOCATE_ONLY)return 0;
    DIAG_STEP("jsc.transaction");
    const uint8_t *wanted=RESTORE?p->fingerprint:detour;
    unsigned n=p->entry_length;
    *failure="cannot verify stopped JSC thread positions";
    if(memcmp(snapshot.entry,wanted,n) && jsc_entry_idle(pid,context.target,n)) { DIAG_ERROR("jsc.thread_check",0,"Cannot verify that all threads are outside the entry prologue"); return 1; }
    *failure="JSC RAM write or readback error";
    if(!RESTORE && !snapshot.initialized) {
        if(jsc_write(pid,data_cave,constants,sizeof(constants)) || jsc_write(pid,cave,code,sizeof(code)))goto rollback;
    }
    if(snapshot.initialized && snapshot.enabled!=context.state[10] &&
       jsc_write(pid,data_cave+JSC_ENABLE_OFFSET,&context.state[10],8))goto rollback;
    if(memcmp(snapshot.entry,wanted,n) && jsc_write(pid,context.target,wanted,n))goto rollback;
    puts(RESTORE?"JSC fullscreen disabled; callback storage retained for compiled functions":
                 "JSC fullscreen enabled; browser prototypes will use the live toggle");
    return 0;
rollback:
    DIAG_ERROR("jsc.transaction",errno,"JSC write/readback failed; attempting pre-call rollback");
    puts("JSC transaction failed; restoring pre-call entry and state");
    if(jsc_write(pid,context.target,snapshot.entry,n)) { *failure="JSC entry rollback verification error"; DIAG_ERROR("jsc.rollback",errno,"JSC entry rollback failed"); }
    if(snapshot.initialized) {
        if(jsc_write(pid,data_cave+JSC_ENABLE_OFFSET,&snapshot.enabled,8)) { *failure="JSC toggle rollback verification error"; DIAG_ERROR("jsc.rollback",errno,"JSC toggle rollback failed"); }
    } else if(snapshot.blank) {
        if(jsc_write(pid,cave,snapshot.code,sizeof(snapshot.code)) ||
           jsc_write(pid,data_cave,snapshot.constants,sizeof(snapshot.constants)))*failure="JSC storage rollback verification error";
    }
    return 1;
}
static int jsc_commit(void) {
    if(!jsc_pending)return 0;
    if(jc_save(HYBRID_CACHE_PATH,&jsc_record)) {
        jsc_cache_status="write failed"; perror("JSC INI save"); return -1;
    }
    jsc_cache_status="saved"; jsc_pending=0;
    printf("JSC cache saved atomically: %s\n",HYBRID_CACHE_PATH); return 0;
}
#endif
