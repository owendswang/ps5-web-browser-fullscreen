/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Disk cache is an optimization. A rejected cache never causes target writes. */
#include "hybrid_cache_io.h"
#include "hbc_reference_profiles.h"
#include "diagnostic_events.h"
#ifndef HYBRID_REFERENCE_LOOKUP
#define HYBRID_REFERENCE_LOOKUP reference_for_firmware
#define HYBRID_REFERENCE_NEXT reference_next_for_firmware
#endif
#ifndef HYBRID_REFERENCE_NEXT
#define HYBRID_REFERENCE_NEXT(firmware,previous) NULL
#endif
#ifndef HYBRID_AUTO_BROWSER
#define HYBRID_AUTO_BROWSER 1
#endif
#ifndef FULLSCREEN_SAFE_SCAN
#define FULLSCREEN_SAFE_SCAN 0
#endif
#ifndef FULLSCREEN_MAPS_ONLY
#define FULLSCREEN_MAPS_ONLY 0
#endif
static struct hybrid_cache hybrid_record;
static struct hybrid_cache hybrid_disk_record;
static int hybrid_pending;
#if FULLSCREEN_SAFE_SCAN
static int hybrid_safe_used;
#endif
static const char *hybrid_cache_status="not attempted";
static void hybrid_note_rejected_ini(void) {
    uint8_t *data=malloc(INI_FILE_CAPACITY); size_t length=0;
    if(!data)return;
    if(!cache_file_read(HYBRID_CACHE_PATH,data,INI_FILE_CAPACITY,&length)) {
        size_t prefix=ini_profile_length(data,length);
        DIAG_EVENT("Rejected INI: bytes=%zu profile_bytes=%zu diagnostics_only=%u",length,prefix,!prefix);
        struct hc_reader reader={.data=data,.length=prefix};
        for(unsigned i=0;i<9;i++) {
            if(hc_line(&reader)!=1 || (reader.line[0]=='[' && i))break;
            DIAG_EVENT("Rejected INI header: %.150s",reader.line);
        }
    }
    free(data);
}
static int hybrid_stop(int pid, int *attached) {
    if(*attached)return 0;
    if(trace(PT_ATTACH,pid)) { DIAG_ERROR("hermes.attach",errno,"Cannot attach to ShellUI"); perror("PT_ATTACH"); return -1; }
    *attached=1;
    int status=0;
    if(waitpid(pid,&status,0)!=pid || !WIFSTOPPED(status)) { DIAG_ERROR("hermes.stop",errno,"Cannot confirm ShellUI stop"); perror("waitpid"); return -1; }
    return 0;
}
static int hybrid_release(int pid, int *attached) {
    if(*attached && trace(PT_DETACH,pid)) { DIAG_ERROR("hermes.detach",errno,"Cannot detach before fallback/UI"); perror("PT_DETACH; refusing fallback"); return -1; }
    *attached=0; return 0;
}
static int hybrid_preflight(int pid, const struct source *sources) {
    uint8_t bytes[128];
    for(unsigned i=0;i<2;i++) {
        const struct source *s=&sources[i];
        int read_error=kernel_proc_copyout(pid,s->base,bytes,128);
        if(read_error || memcmp(bytes,s->data,128)) {
            DIAG_ERROR("hermes.preflight",0,"%s live HBC header mismatch",s->title);
            if(!read_error)DIAG_BYTES("observed_hbc_header",bytes,32);
            printf("Hybrid preflight mismatch: %s header\n",s->title); return -1;
        }
        for(unsigned j=0;j<s->plan.count;j++) {
            const struct hbc_patch *p=&s->plan.patches[j];
            read_error=kernel_proc_copyout(pid,s->base+p->offset,bytes,p->length);
            if(read_error ||
               (memcmp(bytes,p->before,p->length) && memcmp(bytes,p->after,p->length))) {
                DIAG_ERROR("hermes.preflight",0,"%s/%s has unknown live bytes at HBC+%x",s->title,p->name,p->offset);
                if(!read_error)DIAG_BYTES("observed_patch",bytes,p->length);
                printf("Hybrid preflight mismatch: %s +%x %s\n",s->title,p->offset,p->name); return -1;
            }
        }
    }
    return 0;
}
static void hybrid_clear_sources(struct source *sources) {
    for(unsigned i=0;i<2;i++) {
        const char *title=sources[i].title;
        free(sources[i].allocation); memset(&sources[i],0,sizeof(sources[i])); sources[i].title=title;
    }
}
static int hybrid_same_record(const struct hybrid_cache *a, const struct hybrid_cache *b) {
    uint8_t left[HYBRID_CACHE_CAPACITY],right[HYBRID_CACHE_CAPACITY];
    int n=hc_encode(a,left,sizeof(left)), m=hc_encode(b,right,sizeof(right));
    return n>=0 && n==m && !memcmp(left,right,(size_t)n);
}
/* 0=ready, 1=rejected, HA_MISSING=valid graph without target, -1=stop failure. */
static int hybrid_try_profile(int pid, struct source *sources, int *attached, const struct hybrid_cache *record) {
    if(hc_valid(record) || fixed_bind(pid,sources,&record->profile))return 1;
    if(hybrid_stop(pid,attached))return -1;
    int located=locate_sources(pid,sources,2);
    if(located==FIXED_TARGET_MISSING)return HA_MISSING;
    if(located || hybrid_preflight(pid,sources))return 1;
    return 0;
}
static int hybrid_prepare_once(int pid, struct source *sources, int *attached, int may_bootstrap) {
    DIAG_STEP("hermes.prepare");
    DIAG_EVENT("Hermes prepare attempt=%u attached=%u",may_bootstrap?1U:2U,!!*attached);
    START_TIMER(cache_started);
    hybrid_pending=0;
    uint32_t firmware=kernel_get_fw_version();
    if(!firmware) { DIAG_ERROR("hermes.firmware",0,"Current firmware is unavailable"); puts("Hybrid refused: current firmware is unavailable"); return -1; }
    const struct hybrid_cache *reference=HYBRID_REFERENCE_LOOKUP(firmware);
    int reference_result=1;
    while(reference) {
        DIAG_STEP("hermes.reference"); DIAG_EVENT("Trying exact-firmware Hermes reference %08x",firmware);
        printf("Trying built-in reference for exact firmware %08x\n",firmware);
        reference_result=hybrid_try_profile(pid,sources,attached,reference);
        DIAG_EVENT("Hermes reference result=%d",reference_result);
        if(reference_result<0)return -1;
        if(!reference_result) {
            hybrid_record=*reference; hybrid_cache_status="skipped (built-in reference)";
            puts("Plan source: built-in reference; INI cache not needed");
            REPORT_TIMER("reference_hit",cache_started); return 0;
        }
        puts("Built-in reference rejected; checking remaining references before INI and dynamic discovery");
        if(hybrid_release(pid,attached))return -1;
        hybrid_clear_sources(sources);
        const struct hybrid_cache *next=HYBRID_REFERENCE_NEXT(firmware,reference);
        if(!next)break;
        reference=next;
    }
    if(!reference) { DIAG_EVENT("No built-in Hermes reference for %08x",firmware); printf("No built-in reference for exact firmware %08x\n",firmware); }
    int cache_result=hc_load(HYBRID_CACHE_PATH,firmware,&hybrid_disk_record);
    DIAG_EVENT("Hermes INI: %s",hc_load_reason(cache_result));
    if(cache_result==HC_CONTENT_REJECTED)hybrid_note_rejected_ini();
    int same=reference && !cache_result && hybrid_same_record(reference,&hybrid_disk_record);
    if(!cache_result) {
        DIAG_STEP("hermes.cache");
        int located;
        if(same) {
            puts("INI matches the rejected reference; reusing its validation result");
            located=reference_result;
        } else {
            puts("Trying INI; validating native identity, live objects and patch sites");
            located=hybrid_try_profile(pid,sources,attached,&hybrid_disk_record);
        }
        DIAG_EVENT("Hermes INI live validation result=%d",located);
        if(located<0)return -1;
        if(!located) {
            hybrid_record=hybrid_disk_record; hybrid_cache_status="hit";
            puts("Plan source: INI");
            REPORT_TIMER("cache_hit",cache_started); return 0;
        }
        if(located==HA_MISSING && may_bootstrap) {
            hybrid_cache_status="miss"; return HA_MISSING;
        }
        puts("Hybrid cache rejected: native identity, object path or patch-site mismatch");
        if(hybrid_release(pid,attached))return -1;
        hybrid_clear_sources(sources);
    } else printf("Hybrid INI not used: %s (%s)\n",hc_load_reason(cache_result),HYBRID_CACHE_PATH);
    hybrid_cache_status="miss";
    REPORT_TIMER("cache_attempt",cache_started);
    puts("Hybrid fallback: current system bundles -> fast native anchors");
    DIAG_STEP("hermes.discovery"); DIAG_EVENT("Hermes dynamic discovery started");
    if(load_source(&sources[0],1) || load_source(&sources[1],0))return -1;
    int located=locate_sources_fast(pid,sources,2,attached);
    DIAG_EVENT("Hermes fast native location result=%d",located);
    if(located)return located;
    if(hybrid_stop(pid,attached) || hybrid_preflight(pid,sources))return -1;
    puts("Plan source: dynamic discovery");
    if(hybrid_discovered_valid) {
        struct fp_source exported[2];
        for(unsigned i=0;i<2;i++)exported[i]=(struct fp_source){sources[i].title,sources[i].data,sources[i].length,&sources[i].plan};
        if(!hc_from_native(&hybrid_record,&hybrid_discovered_native,exported))hybrid_pending=1;
    }
    if(!hybrid_pending)puts("Hybrid cache not refreshed: fast did not verify a complete reusable native profile");
    return 0;
}
#if TEST_HBC_LIVE_PLAN
#include "hbc_live_plan.h"
#endif
#if FULLSCREEN_SAFE_SCAN
static int hybrid_safe_prepare(int pid, struct source *sources, int *attached) {
    /* No long process-memory scan is allowed while ShellUI is attached. */
    if(hybrid_release(pid,attached))return -1;
    hybrid_safe_used=1;
    hybrid_pending=0; hybrid_discovered_valid=0;
    START_TIMER(safe_started);
    DIAG_STEP("hermes.safe_scan");
    if(FULLSCREEN_MAPS_ONLY) {
        DIAG_EVENT("Passive fallback: VM metadata and known HBC address coverage only");
        puts("Passive fallback: VM metadata only; no bulk process-memory reads");
    } else {
        DIAG_EVENT("Final fallback: expanded safe scan, 64 KiB reads; one pass only");
        puts("Final fallback: expanded safe scan; this may take several seconds");
    }
    int scanned=locate_sources_safe(pid,sources,2);
    REPORT_TIMER("safe_scan",safe_started);
    if(scanned) {
        if(scanned==1 && !FULLSCREEN_MAPS_ONLY) {
#ifdef FULLSCREEN_SCAN_HAS_COVERAGE
            if(scan_omitted_oversized_bytes)
                DIAG_ERROR("hermes.targets_unlocated",0,"HBC targets unlocated in selected windows; oversized readable mappings omitted (%llu bytes)",(unsigned long long)scan_omitted_oversized_bytes);
            else
#endif
                DIAG_ERROR("hermes.targets_unlocated",0,"HBC targets still unlocated after fast, initialization and expanded safe scan");
        }
        return scanned==1?HA_MISSING:-1;
    }
    DIAG_STEP("hermes.scan_cache_recovery");
    if(recover_scan_native(pid,sources,2,attached)<0)return -1;
    if(hybrid_stop(pid,attached) || hybrid_preflight(pid,sources))return -1;
    if(hybrid_discovered_valid) {
        struct fp_source exported[2];
        for(unsigned i=0;i<2;i++)exported[i]=(struct fp_source){sources[i].title,sources[i].data,sources[i].length,&sources[i].plan};
        if(!hc_from_native(&hybrid_record,&hybrid_discovered_native,exported)) {
            /* Prove the exact persisted path with the existing fixed reader,
             * including both target bases, before scheduling its disk write. */
            struct source check[2]={{.title=sources[0].title},{.title=sources[1].title}};
            if(!fixed_bind(pid,check,&hybrid_record.profile) && !locate_sources(pid,check,2) &&
               check[0].base==sources[0].base && check[1].base==sources[1].base && !hybrid_preflight(pid,check))
                hybrid_pending=1;
        }
    }
    hybrid_cache_status=hybrid_pending?"pending (safe scan native recovery)":"scan only (native profile unavailable)";
    DIAG_EVENT("Safe scan complete: reusable_native_profile=%u",!!hybrid_pending);
    puts(hybrid_pending?"Safe scan verified a reusable fixed profile; INI will be saved after patch success":
                       "Safe scan located HBC targets; no reusable native profile, so no fixed cache will be saved");
    return 0;
}
#endif
static int hybrid_prepare(int *target_pid, struct source *sources, int *attached) {
    int pid=*target_pid;
#if FULLSCREEN_SAFE_SCAN
    hybrid_safe_used=0;
#endif
    int result=hybrid_prepare_once(pid,sources,attached,1);
#if TEST_HBC_LIVE_PLAN
    if(result==HA_MISSING) {
        int live=hybrid_live_prepare(pid,sources,attached);
        if(live<=0)return live;
    }
#endif
#if FULLSCREEN_SAFE_SCAN && FULLSCREEN_MAPS_ONLY
    if(!result || result==HA_MISSING || result==HA_UNSUPPORTED)
        return hybrid_safe_prepare(pid,sources,attached);
#endif
    if((result!=HA_MISSING && result!=HA_UNSUPPORTED) || !HYBRID_AUTO_BROWSER)return result;
    /* Never issue UI requests or wait while ShellUI is stopped. Discard every
     * pre-launch heap address, including any one target that was already found. */
    if(hybrid_release(pid,attached))return -1;
    hybrid_clear_sources(sources);
    START_TIMER(bootstrap_started);
    puts("Fast location incomplete: initializing browser once before retry");
    DIAG_STEP("hermes.browser_bootstrap"); DIAG_EVENT("Fast location missing/unsupported; attempting one open/home cycle");
    if(hybrid_bootstrap_browser(pid)) { DIAG_ERROR("hermes.browser_bootstrap",0,"Browser open/home initialization failed"); return -1; }
    REPORT_TIMER("browser_bootstrap",bootstrap_started);
    if(hybrid_refresh_shellui(target_pid))return -1;
    pid=*target_pid;
    result=hybrid_prepare_once(pid,sources,attached,0);
    if(result==HA_MISSING || result==HA_UNSUPPORTED) {
#if TEST_HBC_LIVE_PLAN
        int live=hybrid_live_prepare(pid,sources,attached);
        if(live<=0)return live;
#endif
#if FULLSCREEN_SAFE_SCAN
        return hybrid_safe_prepare(pid,sources,attached);
#else
        DIAG_ERROR("hermes.targets_unlocated",0,"Fast location failed after one initialization; slow scan is test-only");
#endif
    }
    return result;
}
/* Called only after complete RAM success and successful detach. */
static int hybrid_commit(void) {
    if(!hybrid_pending)return 0;
    START_TIMER(save_started);
    if(hc_save(HYBRID_CACHE_PATH,&hybrid_record)) {
        hybrid_cache_status="write failed";
        perror("Hybrid cache write failed; the RAM operation already completed"); return -1;
    }
    hybrid_cache_status="saved";
    printf("Hybrid cache saved atomically: %s (plain text v%u)\n",HYBRID_CACHE_PATH,HYBRID_CACHE_VERSION);
    REPORT_TIMER("cache_save",save_started); return 0;
}

