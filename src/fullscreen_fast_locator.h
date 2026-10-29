/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Adaptive small native anchors first; retain the previous scanner as fallback. */
#include "hermes_anchor.h"
#include "fixed_profile_export.h"
#include "diagnostic_events.h"
#include "scan_observations.h"
#if TEST_HBC_LIVE_PLAN || TEST_HBC_EXPORT
#include "hbc_candidate_export.h"
#endif
#if TEST_HBC_LIVE_PLAN && DIAG_DEEP
#include "hbc_module_identity.h"
#endif
#ifndef FULLSCREEN_SAFE_SCAN
#define FULLSCREEN_SAFE_SCAN 0
#endif
#if !FULLSCREEN_HYBRID || FULLSCREEN_SAFE_SCAN
#include "fullscreen_scan_locator.h"
#endif
#if FULLSCREEN_HYBRID && FULLSCREEN_SAFE_SCAN
#include "hermes_registry_scan.h"
#ifndef HERMES_LIBRARY_PATH
#define HERMES_LIBRARY_PATH "/system_ex/common_ex/lib/libhermes-0.11.sprx"
#endif
#endif
#ifndef FULLSCREEN_ANCHOR
#define FULLSCREEN_ANCHOR 1
#endif
#ifndef EXPORT_FIXED_PROFILE
#define EXPORT_FIXED_PROFILE 1
#endif
static int trace(int request, int pid);
#if FULLSCREEN_HYBRID
static struct fp_native hybrid_discovered_native;
static int hybrid_discovered_valid;
#endif
static int anchor_copy(void *context, uintptr_t address, void *out, size_t size) {
    int pid=*(int *)context;
    /* Bound each SDK read to one page, including short native getter reads. */
    uint8_t *p=out;
    while(size) {
        size_t part=0x1000-(address&0xfff);
        if(part>size)part=size;
        if(kernel_proc_copyout(pid,address,p,part))return -1;
        p+=part; address+=part; size-=part;
    }
    return 0;
}
/* Resolve known collector roles, then require the same strict instruction
 * shape. Neither symbol identity nor a readable export alone authorizes a walk. */
static int anchor_collector(int pid,uint32_t handle,struct ha_reader *reader,
                             uintptr_t *entry,uint8_t code[HA_CODE_BYTES]) {
    static const char *const nids[]={"SZeSnZKptS8","UHH-6O3SBv8"};
    for(unsigned i=0;i<sizeof(nids)/sizeof(*nids);i++) {
        uintptr_t address=kernel_dynlib_resolve(pid,handle,nids[i]),slot=0;
        int valid=reader->image_base && ha_image(reader,address,HA_CODE_BYTES);
        int read=valid?ha_read(reader,address,code,HA_CODE_BYTES):HA_UNSUPPORTED;
        int parsed=read?HA_UNSUPPORTED:ha_registry_anchor(code,HA_CODE_BYTES,address,reader,&slot);
        DIAG_EVENT("Hermes collector candidate=%s in_image=%u read=%d parse=%d rva=%lx",
                   nids[i],valid,read,parsed,valid?address-reader->image_base:0UL);
        if(!read && parsed)DIAG_SPAN("collector_code",code,HA_CODE_BYTES);
        if(parsed==HA_AMBIGUOUS)return parsed;
        if(!parsed) { *entry=address; return HA_OK; }
    }
    *entry=0; return HA_UNSUPPORTED;
}
static void export_fixed_profile(struct ha_reader *reader, const struct ha_layout *layout,
                                  uintptr_t collector, const uint8_t *code, const struct source *sources) {
    if(!EXPORT_FIXED_PROFILE && !FULLSCREEN_HYBRID)return;
    START_TIMER(export_started);
    struct fp_native native={.firmware=kernel_get_fw_version(),
        .registry_rva=layout->registry_slot-reader->image_base,.module_list_offset=layout->modules,
        .module_runtime_offset=layout->runtime,.provider_offset=layout->provider,
        .provider_vtable_rva=layout->vtable-reader->image_base,.buffer_object_offset=layout->raw.object,
        .buffer_data_offset=layout->raw.data,.buffer_length_offset=layout->raw.size,
        .fingerprint_rva=collector-reader->image_base};
    if(ha_owner_field(reader,layout,&native.runtime_owner_offset)) {
        puts("FIXED_PROFILE_UNAVAILABLE runtime-owner backlink not uniquely verified"); return;
    }
    memcpy(native.fingerprint,code,sizeof(native.fingerprint));
#if FULLSCREEN_HYBRID
    hybrid_discovered_native=native; hybrid_discovered_valid=1;
#endif
    if(!EXPORT_FIXED_PROFILE)return;
    struct fp_source source[2];
    for(unsigned i=0;i<2;i++)source[i]=(struct fp_source){sources[i].title,sources[i].data,sources[i].length,&sources[i].plan};
    char output[8192];
    if(fp_serialize(output,sizeof(output),&native,source,2)<0)puts("FIXED_PROFILE_UNAVAILABLE output capacity");
    else puts(output);
    REPORT_TIMER("fixed_profile_export",export_started);
}
struct anchor_hbc_samples {
    const struct source *sources;
    size_t observed,shape[2],exact[2],used,unsampled;
    unsigned near_sampled[2]; uint8_t near_header[2][128];
    struct { uintptr_t base; uint8_t header[128]; } samples[8];
};
static void anchor_sample_hbc(void *context,uintptr_t base,const uint8_t *header) {
#if TEST_HBC_LIVE_PLAN || TEST_HBC_EXPORT
    hbc_candidate_note(base,header);
#endif
    struct anchor_hbc_samples *s=context; s->observed++;
    for(unsigned i=0;i<2;i++) {
        if(!memcmp(header+8,s->sources[i].data+8,4) && !memcmp(header+32,s->sources[i].data+32,4)) {
            s->shape[i]++;
            if(!s->near_sampled[i] && memcmp(header,s->sources[i].data,128)) {
                memcpy(s->near_header[i],header,128); s->near_sampled[i]=1;
            }
        }
        if(!memcmp(header,s->sources[i].data,128))s->exact[i]++;
    }
    for(size_t i=0;i<s->used;i++)if(!memcmp(header,s->samples[i].header,128))return;
    if(s->used==8) { s->unsampled++; return; }
    s->samples[s->used].base=base; memcpy(s->samples[s->used].header,header,128); s->used++;
    scan_native_note(base,header);
}
/* Diagnostic-only snapshot. An unpaused walk is never a patch/cache input. */
static struct {
    int valid,pid;
    uintptr_t image;
    struct ha_layout layout;
    uint8_t headers[2][128];
} anchor_last_graph;
struct anchor_probe_budget { int pid; size_t calls,bytes; unsigned exhausted; };
#if DIAG_DEEP
static struct {
    int valid,pid;
    uintptr_t image,bases[2];
} anchor_open_graph;
static inline int anchor_probe_read(void *context,uintptr_t address,void *out,size_t length) {
    struct anchor_probe_budget *b=context;
    if(b->calls>=1024 || length>262144-b->bytes) { b->exhausted=1; return -1; }
    b->calls++; b->bytes+=length;
    return kernel_proc_copyout(b->pid,address,out,length);
}
static inline void anchor_phase_snapshot(const char *phase,int pid,uintptr_t image) {
    if(!anchor_last_graph.valid || anchor_last_graph.pid!=pid || anchor_last_graph.image!=image) {
        DIAG_EVENT("HBC phase=%s snapshot skipped: no validated graph for current PID/image",phase); return;
    }
    int saved_errno=errno;
    struct anchor_probe_budget budget={.pid=pid};
    struct ha_reader reader={.context=&budget,.read=anchor_probe_read,.image_base=image};
    struct ha_layout layout=anchor_last_graph.layout;
    struct ha_target targets[2]={{.header=anchor_last_graph.headers[0]},{.header=anchor_last_graph.headers[1]}};
    int result=ha_walk(&reader,&layout,targets,2);
    DIAG_EVENT("HBC phase=%s result=%d unpaused=yes runtimes=%zu modules=%zu reads=%zu bytes=%zu exhausted=%u",phase,result,reader.runtimes,reader.modules,budget.calls,budget.bytes,budget.exhausted);
    DIAG_EVENT("HBC phase=%s NPXS40036=%lx NPXS40003=%lx diagnostic_only=yes",phase,targets[0].base,targets[1].base);
    if(!strcmp(phase,"after_open")) {
        anchor_open_graph.valid=result==HA_OK || result==HA_MISSING;
        anchor_open_graph.pid=pid; anchor_open_graph.image=image;
        for(unsigned i=0;i<2;i++)anchor_open_graph.bases[i]=targets[i].base;
    } else if(!strcmp(phase,"after_home") && anchor_open_graph.valid &&
              anchor_open_graph.pid==pid && anchor_open_graph.image==image) {
        const char *state[2]={"not_seen_while_open","not_seen_while_open"};
        for(unsigned i=0;i<2;i++)if(anchor_open_graph.bases[i]) {
            uint8_t header[128];
            state[i]=anchor_probe_read(&budget,anchor_open_graph.bases[i],header,sizeof(header))?"unreadable":
                     memcmp(header,anchor_last_graph.headers[i],sizeof(header))?"changed":"unchanged";
        }
        DIAG_EVENT("HBC open-to-home same_PID_image=yes prior_header_36=%s prior_header_03=%s reads=%zu bytes=%zu exhausted=%u",state[0],state[1],budget.calls,budget.bytes,budget.exhausted);
        (void)state;
    }
    (void)result;
    errno=saved_errno;
}
#endif
static void anchor_report_code(unsigned index,const char *label,const uint8_t *code) {
    static uint8_t previous[2][HA_CODE_BYTES]; static unsigned valid;
    if((valid&(1U<<index)) && !memcmp(previous[index],code,HA_CODE_BYTES)) {
        DIAG_EVENT("%s unchanged from previous attempt; complete first window retained",label);
        (void)label; return;
    }
    memcpy(previous[index],code,HA_CODE_BYTES); valid|=1U<<index;
    DIAG_SPAN(label,code,HA_CODE_BYTES);
}
static void anchor_report_hbc(const struct anchor_hbc_samples *s) {
    (void)s;
    DIAG_EVENT("Native HBC inventory: modules=%zu sampled_distinct=%zu additional_unsampled=%zu",s->observed,s->used,s->unsampled);
    for(unsigned i=0;i<2;i++) {
        DIAG_EVENT("Native target %s expected_length=%zu same_shape=%zu exact=%zu",s->sources[i].title,s->sources[i].length,s->shape[i],s->exact[i]);
        if(s->near_sampled[i]) {
            size_t at=0; while(at<128 && s->near_header[i][at]==s->sources[i].data[at])at++;
            if(at<128)DIAG_EVENT("Native target %s same-shape first_difference=%zu expected=%02x observed=%02x",s->sources[i].title,at,s->sources[i].data[at],s->near_header[i][at]);
            DIAG_SPAN("native_same_shape_header",s->near_header[i],128);
        }
    }
    for(size_t i=0;i<s->used;i++) {
        DIAG_EVENT("Native HBC sample=%zu base=%lx version=%u length=%u",i,s->samples[i].base,ha_u32(s->samples[i].header+8),ha_u32(s->samples[i].header+32));
        DIAG_SPAN("native_hbc_header",s->samples[i].header,128);
    }
}
static int locate_sources_fast(int pid, struct source *sources, size_t count, int *attached) {
#if TEST_HBC_LIVE_PLAN || TEST_HBC_EXPORT
    hbc_candidate_reset(pid);
#endif
    scan_native_reset(pid);
    anchor_last_graph.valid=0;
#if DIAG_DEEP
    anchor_open_graph.valid=0;
#endif
    DIAG_STEP("hermes.native_anchor");
    uint32_t handle=0;
    struct ha_reader reader={.context=&pid,.read=anchor_copy};
    struct ha_layout layout={0};
    struct ha_target targets[2];
    uint8_t collector_code[HA_CODE_BYTES], module_code[HA_CODE_BYTES];
    int ret=HA_UNSUPPORTED;
#if FULLSCREEN_HYBRID
    hybrid_discovered_valid=0;
#endif
    START_TIMER(anchor_started);
    DIAG_EVENT("Hermes anchor policy: image_limit=%lu code_bytes=%u module_bytes=%u",HA_IMAGE_LIMIT,HA_CODE_BYTES,HA_MODULE_BYTES);
    const char *anchor_stage="library lookup";
    int handle_result=FULLSCREEN_ANCHOR && count==2?kernel_dynlib_handle(pid,"libhermes-0.11.sprx",&handle):-1;
    if(!handle_result) {
        reader.image_base=kernel_dynlib_mapbase_addr(pid,handle);
        uintptr_t collector=0;
        int collector_status=anchor_collector(pid,handle,&reader,&collector,collector_code);
        if(collector_status==HA_AMBIGUOUS) {
            DIAG_ERROR("hermes.native_anchor",0,"Ambiguous collector registry anchors"); return -1;
        }
        uintptr_t modules=kernel_dynlib_resolve(pid,handle,"2S-+xsSllxg");
        int collector_in_image=reader.image_base && ha_image(&reader,collector,sizeof(collector_code));
        int modules_in_image=reader.image_base && ha_image(&reader,modules,sizeof(module_code));
        anchor_stage="export/range";
        printf("Hermes exports: image=%s collector=%s modules=%s\n",reader.image_base?"yes":"no",
               collector_in_image?"in image":"unresolved/out of range",modules_in_image?"in image":"unresolved/out of range");
        DIAG_EVENT("Hermes exports: image=%u collector=%u modules=%u collector_rva=%lx modules_rva=%lx",
                   !!reader.image_base,collector_in_image,modules_in_image,
                   reader.image_base && collector>=reader.image_base && collector!=(uintptr_t)-1?collector-reader.image_base:0UL,
                   reader.image_base && modules>=reader.image_base && modules!=(uintptr_t)-1?modules-reader.image_base:0UL);
        int collector_read=collector_status;
        int modules_read=modules_in_image?ha_read(&reader,modules,module_code,sizeof(module_code)):HA_UNSUPPORTED;
        if(collector_in_image && modules_in_image)anchor_stage="getter read";
        DIAG_EVENT("Hermes getter reads: collector=%d modules=%d",collector_read,modules_read);
        if(DIAG_DEEP || collector_read || modules_read) {
            if(!collector_read)anchor_report_code(0,"collector_code",collector_code);
            if(!modules_read)anchor_report_code(1,"modules_code",module_code);
        }
        if(!collector_read && !modules_read) {
            anchor_stage="registry pattern";
            ret=ha_registry_anchor(collector_code,sizeof(collector_code),collector,&reader,&layout.registry_slot);
            if(!ret) { anchor_stage="module-list pattern"; ret=ha_modules_anchor(module_code,sizeof(module_code),&layout.modules); }
            DIAG_EVENT("Hermes anchor parse: stage=%s result=%d registry_rva=%lx module_list=%x",anchor_stage,ret,
                       layout.registry_slot?layout.registry_slot-reader.image_base:0UL,layout.modules);
            if(ret) {
                anchor_report_code(0,"collector_code",collector_code);
                anchor_report_code(1,"modules_code",module_code);
            }
            if(ret==HA_AMBIGUOUS) { DIAG_ERROR("hermes.native_anchor",0,"Ambiguous native anchors"); puts("Ambiguous native anchors; no writes"); return -1; }
            if(!ret) {
                printf("Hermes native anchors: registry slot=%lx module-list=+%x\n",layout.registry_slot,layout.modules);
                if(trace(PT_ATTACH,pid)) { DIAG_ERROR("hermes.native_attach",errno,"Cannot attach for native walk"); perror("PT_ATTACH; no writes"); return -1; }
                *attached=1;
                int status=0;
                if(waitpid(pid,&status,0)!=pid || !WIFSTOPPED(status)) { DIAG_ERROR("hermes.native_stop",errno,"Cannot confirm ShellUI stop for native walk"); perror("waitpid"); return -1; }
                reader.cache_headers=1;
                for(unsigned i=0;i<2;i++)targets[i]=(struct ha_target){.header=sources[i].data};
                anchor_stage="object walk";
                struct anchor_hbc_samples samples={.sources=sources};
                reader.observe_hbc=anchor_sample_hbc; reader.observe_context=&samples;
#if TEST_HBC_LIVE_PLAN && DIAG_DEEP
                struct hmi_context identity={.reader=&reader,.layout=&layout,.pid=pid,
                    .enabled=hmi_profile(collector-reader.image_base,collector_code)};
                reader.observe_module=hmi_observe; reader.module_context=&identity;
#endif
                ret=ha_walk(&reader,&layout,targets,2);
                if(ret && ret!=HA_MISSING) {
                    anchor_report_code(0,"collector_code",collector_code);
                    anchor_report_code(1,"modules_code",module_code);
                }
                if(ret==HA_OK || ret==HA_MISSING) {
                    anchor_last_graph.pid=pid; anchor_last_graph.image=reader.image_base;
                    anchor_last_graph.layout=layout;
                    for(unsigned i=0;i<2;i++)memcpy(anchor_last_graph.headers[i],sources[i].data,128);
                    anchor_last_graph.valid=1;
                }
                DIAG_EVENT("Hermes anchor walk result=%d runtimes=%zu modules=%zu reads=%zu",ret,reader.runtimes,reader.modules,reader.calls);
                DIAG_EVENT("Hermes stopped-walk header reuse=%u",reader.header_hits);
                DIAG_EVENT("Hermes walk stage=%s read_failures=%zu runtime=%x provider=%x object=%x data=%x size=%x",
                           reader.walk_stage?reader.walk_stage:"unknown",reader.read_failures,layout.runtime,layout.provider,
                           layout.raw.object,layout.raw.data,layout.raw.size);
                for(unsigned i=0;i<2;i++)DIAG_EVENT("Hermes graph target %s: located=%s",sources[i].title,targets[i].base?"yes":"no");
                if(ret)anchor_report_hbc(&samples);
                if(!ret) {
                    for(unsigned i=0;i<2;i++) {
                        sources[i].base=targets[i].base;
                        printf("Located %s at %lx via native anchors\n",sources[i].title,sources[i].base);
                    }
                    printf("Derived fields: module-runtime=+%x provider=+%x buffer=+%x data=+%x length=+%x\n",
                           layout.runtime,layout.provider,layout.raw.object,layout.raw.data,layout.raw.size);
                    printf("Anchor walk: %zu runtimes / %zu modules; %zu bytes in %zu reads\n",
                           reader.runtimes,reader.modules,reader.bytes,reader.calls);
                    REPORT_TIMER("native_anchor",anchor_started);
                    export_fixed_profile(&reader,&layout,collector,collector_code,sources);
                    return 0;
                }
                if(ret==HA_AMBIGUOUS) { DIAG_ERROR("hermes.native_anchor",0,"Ambiguous providers or live HBC images"); puts("Ambiguous provider or live HBC images; no writes"); return -1; }
#if FULLSCREEN_HYBRID
                if(ret==HA_MISSING) {
                    puts("Validated native graph lacks a browser target; deferring scan for browser initialization");
                    REPORT_TIMER("native_anchor_missing",anchor_started);
                    return HA_MISSING;
                }
#endif
                printf("Anchor layout rejected after %zu runtimes / %zu modules (%zu bytes); runtime=+%x provider=+%x\n",
                       reader.runtimes,reader.modules,reader.bytes,layout.runtime,layout.provider);
                /* Never hold ShellUI stopped during the large fallback scan. */
                if(trace(PT_DETACH,pid)) { DIAG_ERROR("hermes.native_detach",errno,"Cannot detach before scan fallback"); perror("PT_DETACH; refusing scan"); return -1; }
                *attached=0;
            }
        }
    }
    printf("Hermes anchor fallback: stage=%s result=%d handle_result=%d\n",anchor_stage,ret,handle_result);
    DIAG_EVENT("Hermes anchor fallback: stage=%s result=%d handle_result=%d",anchor_stage,ret,handle_result);
#if FULLSCREEN_HYBRID
    puts("Fast native location unavailable");
    REPORT_TIMER("native_anchor_attempt",anchor_started);
    return HA_UNSUPPORTED;
#else
    puts("Native anchors/layout unavailable: using the verified scan fallback");
    DIAG_STEP("hermes.scan"); DIAG_EVENT("Native anchors unavailable; starting bounded scan fallback");
    REPORT_TIMER("native_anchor_attempt",anchor_started);
    for(size_t i=0;i<count;i++)sources[i].base=0;
    int scanned=locate_sources_scan(pid,sources,count);
    if(scanned==1)DIAG_ERROR("hermes.scan",0,"Scan did not locate all verified HBC targets");
    else if(scanned)DIAG_EVENT("Hermes scan error result=%d; retaining detailed failure",scanned);
    return scanned;
#endif
}
#if FULLSCREEN_HYBRID && FULLSCREEN_SAFE_SCAN
/* Scan success alone supplies only heap addresses. Recover and verify a native
 * layout before allowing the controller to save a cross-reboot cache. */
static int recover_scan_native(int pid, const struct source *sources, size_t count, int *attached) {
    hybrid_discovered_valid=0;
    if(count!=2 || *attached)return 1;
    struct ha_code_ranges ranges;
    if(ha_code_ranges_load(HERMES_LIBRARY_PATH,&ranges)) {
        DIAG_EVENT("Safe scan cache: executable ELF/SELF metadata unavailable"); return 1;
    }
    uint32_t handle=0;
    struct ha_reader reader={.context=&pid,.read=anchor_copy};
    if(kernel_dynlib_handle(pid,"libhermes-0.11.sprx",&handle) ||
       !(reader.image_base=kernel_dynlib_mapbase_addr(pid,handle)))return 1;
    uintptr_t modules=kernel_dynlib_resolve(pid,handle,"2S-+xsSllxg");
    uint8_t code[HA_CODE_BYTES],fingerprint[32]; unsigned module_offset=0;
    if(!ha_image(&reader,modules,sizeof(code)) || ha_read(&reader,modules,code,sizeof(code)) ||
       ha_modules_anchor(code,sizeof(code),&module_offset)) {
        DIAG_EVENT("Safe scan cache: native module-list anchor unavailable"); return 1;
    }
    /* Metadata IO and symbol lookup finish before stopping ShellUI. */
    if(trace(PT_ATTACH,pid)) { DIAG_ERROR("hermes.recovery_attach",errno,"Cannot stop ShellUI for cache recovery"); return -1; }
    *attached=1; int status=0;
    if(waitpid(pid,&status,0)!=pid || !WIFSTOPPED(status)) {
        DIAG_ERROR("hermes.recovery_stop",errno,"Cannot confirm ShellUI stop for cache recovery"); return -1;
    }
    struct ha_target expected[2];
    for(unsigned i=0;i<2;i++)expected[i]=(struct ha_target){.header=sources[i].data,.base=sources[i].base};
    struct ha_layout layout={0}; uintptr_t anchor=0;
    int result=ha_recover_registry(&reader,&ranges,module_offset,expected,2,&layout,&anchor,fingerprint);
    DIAG_EVENT("Safe scan native recovery: result=%d module_list=%x",result,module_offset);
    if(result)return 1;
    export_fixed_profile(&reader,&layout,anchor,fingerprint,sources);
    printf("Safe scan native recovery: registry=+%lx module-list=+%x fingerprint=+%lx reusable=%s\n",
           layout.registry_slot-reader.image_base,layout.modules,anchor-reader.image_base,
           hybrid_discovered_valid?"yes":"no");
    return hybrid_discovered_valid?0:1;
}
#endif

