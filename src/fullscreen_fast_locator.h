/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Adaptive small native anchors first; retain the previous scanner as fallback. */
#include "hermes_anchor.h"
#include "fixed_profile_export.h"
#include "fullscreen_scan_locator.h"
#include "diagnostic_events.h"
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
static int locate_sources_fast(int pid, struct source *sources, size_t count, int *attached) {
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
    if(FULLSCREEN_ANCHOR && count==2 && !kernel_dynlib_handle(pid,"libhermes-0.11.sprx",&handle)) {
        reader.image_base=kernel_dynlib_mapbase_addr(pid,handle);
        uintptr_t collector=kernel_dynlib_resolve(pid,handle,"SZeSnZKptS8");
        uintptr_t modules=kernel_dynlib_resolve(pid,handle,"2S-+xsSllxg");
        if(reader.image_base && ha_image(&reader,collector,sizeof(collector_code)) &&
           ha_image(&reader,modules,sizeof(module_code)) &&
           !ha_read(&reader,collector,collector_code,sizeof(collector_code)) &&
           !ha_read(&reader,modules,module_code,sizeof(module_code))) {
            ret=ha_registry_anchor(collector_code,sizeof(collector_code),collector,&reader,&layout.registry_slot);
            if(!ret)ret=ha_modules_anchor(module_code,sizeof(module_code),&layout.modules);
            if(ret==HA_AMBIGUOUS) { DIAG_ERROR("hermes.native_anchor",0,"Ambiguous native anchors"); puts("Ambiguous native anchors; no writes"); return -1; }
            if(!ret) {
                printf("Hermes native anchors: registry slot=%lx module-list=+%x\n",layout.registry_slot,layout.modules);
                if(trace(PT_ATTACH,pid)) { perror("PT_ATTACH; no writes"); return -1; }
                *attached=1;
                int status=0;
                if(waitpid(pid,&status,0)!=pid || !WIFSTOPPED(status)) { perror("waitpid"); return -1; }
                for(unsigned i=0;i<2;i++)targets[i]=(struct ha_target){.header=sources[i].data};
                ret=ha_walk(&reader,&layout,targets,2);
                DIAG_EVENT("Hermes anchor walk result=%d runtimes=%zu modules=%zu reads=%zu",ret,reader.runtimes,reader.modules,reader.calls);
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
                if(trace(PT_DETACH,pid)) { perror("PT_DETACH; refusing scan"); return -1; }
                *attached=0;
            }
        }
    }
    puts("Native anchors/layout unavailable: using the verified scan fallback");
    DIAG_STEP("hermes.scan"); DIAG_EVENT("Native anchors unavailable; starting bounded scan fallback");
    REPORT_TIMER("native_anchor_attempt",anchor_started);
    for(size_t i=0;i<count;i++)sources[i].base=0;
    int scanned=locate_sources_scan(pid,sources,count);
    if(scanned)DIAG_ERROR("hermes.scan",0,"Scan failed to locate all verified HBC targets: result=%d",scanned);
#if FULLSCREEN_HYBRID
    if(scanned==1)return HA_MISSING;
#endif
    return scanned;
}

