/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Disk cache is an optimization. A rejected cache never causes target writes. */
#include "hybrid_cache_io.h"
#include "reference_profiles.h"
#include "diagnostic_events.h"
#ifndef HYBRID_REFERENCE_LOOKUP
#define HYBRID_REFERENCE_LOOKUP reference_for_firmware
#endif
#ifndef HYBRID_AUTO_BROWSER
#define HYBRID_AUTO_BROWSER 1
#endif
static struct hybrid_cache hybrid_record;
static struct hybrid_cache hybrid_disk_record;
static int hybrid_pending;
static const char *hybrid_cache_status="not attempted";
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
    START_TIMER(cache_started);
    hybrid_pending=0;
    uint32_t firmware=kernel_get_fw_version();
    if(!firmware) { DIAG_ERROR("hermes.firmware",0,"Current firmware is unavailable"); puts("Hybrid refused: current firmware is unavailable"); return -1; }
    const struct hybrid_cache *reference=HYBRID_REFERENCE_LOOKUP(firmware);
    int reference_result=1;
    if(reference) {
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
        puts("Built-in reference rejected; continuing with INI and dynamic discovery");
        if(hybrid_release(pid,attached))return -1;
        hybrid_clear_sources(sources);
    } else { DIAG_EVENT("No built-in Hermes reference for %08x",firmware); printf("No built-in reference for exact firmware %08x\n",firmware); }
    int cache_result=hc_load(HYBRID_CACHE_PATH,firmware,&hybrid_disk_record);
    DIAG_EVENT("Hermes INI: %s",hc_load_reason(cache_result));
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
    puts("Hybrid fallback: current system bundles -> fast anchors -> scan if required");
    DIAG_STEP("hermes.discovery"); DIAG_EVENT("Hermes dynamic discovery started");
    if(load_source(&sources[0],1) || load_source(&sources[1],0))return -1;
    int located=locate_sources_fast(pid,sources,2,attached);
    DIAG_EVENT("Hermes native/scan location result=%d",located);
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
static int hybrid_prepare(int pid, struct source *sources, int *attached) {
    int result=hybrid_prepare_once(pid,sources,attached,1);
    if(result!=HA_MISSING || !HYBRID_AUTO_BROWSER)return result;
    /* Never issue UI requests or wait while ShellUI is stopped. Discard every
     * pre-launch heap address, including any one target that was already found. */
    if(hybrid_release(pid,attached))return -1;
    hybrid_clear_sources(sources);
    START_TIMER(bootstrap_started);
    puts("Hybrid target absent: initializing browser once before retry");
    DIAG_STEP("hermes.browser_bootstrap"); DIAG_EVENT("Missing browser module; attempting one open/home cycle");
    if(hybrid_bootstrap_browser()) { DIAG_ERROR("hermes.browser_bootstrap",0,"Browser open/home initialization failed"); return -1; }
    REPORT_TIMER("browser_bootstrap",bootstrap_started);
    result=hybrid_prepare_once(pid,sources,attached,0);
    if(result==HA_MISSING) { DIAG_ERROR("hermes.browser_missing",0,"Browser module still absent after one initialization"); puts("Browser target still absent after initialization; no writes, no further UI retries"); }
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

