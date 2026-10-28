/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef HBC_CANDIDATE_CONSOLE_H
#define HBC_CANDIDATE_CONSOLE_H
#include "hbc_candidate_export.h"

static int hbc_dump_scope(int pid) {
    uint32_t handle=0;
    return anchor_last_graph.valid && anchor_last_graph.pid==pid && find_shellui()==pid &&
        !kernel_dynlib_handle(pid,"libhermes-0.11.sprx",&handle) &&
        (uintptr_t)kernel_dynlib_mapbase_addr(pid,handle)==anchor_last_graph.image;
}
static int hbc_dump_range(int pid,uintptr_t base,size_t length) {
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_VMMAP,pid}; size_t size=0;
    if(sysctl(mib,4,NULL,&size,NULL,0) || size>15U*1024*1024)return 0;
    size+=1024*1024;
    char *maps=malloc(size); if(!maps)return 0;
    int accepted=0;
    if(!sysctl(mib,4,maps,&size,NULL,0))for(size_t at=0;at<size;) {
        struct kinfo_vmentry *v=(void *)(maps+at);
        if(size-at<144 || v->kve_structsize<144 || (size_t)v->kve_structsize>size-at) { accepted=0; break; }
        if(v->kve_start<=base && base<v->kve_end && length<=v->kve_end-base &&
           (v->kve_protection&1) && v->kve_type!=4 && v->kve_type!=8)accepted=1;
        at+=v->kve_structsize;
    }
    free(maps); return accepted;
}
#if TEST_HBC_EXPORT
static void hbc_candidate_export(int pid) {
    int saved_errno=errno;
    /* Only the two exact source-hash/length identities in the forwarded v6
     * report. No nearby-size heuristic and no unrelated process memory dump. */
    if(kernel_get_fw_version()!=0x10010000 || hbc_candidate_inventory.pid!=pid || !hbc_dump_scope(pid)) {
        DIAG_EVENT("HBC evidence skipped: firmware/PID/validated graph scope unavailable"); goto done;
    }
    DIAG_EVENT("HBC evidence: at most 2 reported candidates; raw<=8MiB/file gzip<=4MiB/file; diagnostic only");
    for(unsigned candidate=0;candidate<2;candidate++) {
        unsigned hits=hbc_candidate_inventory.items[candidate].matches;
        if(hits!=1) { DIAG_EVENT("HBC evidence %s skipped: matching samples=%u",hbc_dump_specs[candidate].tag,hits); continue; }
        uintptr_t base=hbc_candidate_inventory.items[candidate].base;
        if(!hbc_dump_scope(pid) || !hbc_dump_range(pid,base,hbc_dump_specs[candidate].length)) {
            DIAG_EVENT("HBC evidence %s skipped: PID/image or readable non-device range changed",hbc_dump_specs[candidate].tag); continue;
        }
        char path[160];
        snprintf(path,sizeof(path),"/data/web-browser-hbc-10010000-%s.hbc.gz",hbc_dump_specs[candidate].tag);
        struct hbc_dump_result report;
        const char *failure=hbc_dump_capture(anchor_copy,&pid,base,hbc_candidate_inventory.items[candidate].header,candidate,path,&report);
        if(!failure && !hbc_dump_scope(pid)) {
            unlink(path); failure="scope_changed_after_capture";
        }
        if(failure)DIAG_EVENT("HBC evidence %s failed=%s read_bytes=%zu",hbc_dump_specs[candidate].tag,failure,report.read_bytes);
        else {
            DIAG_EVENT("HBC evidence saved=%s raw=%zu gzip=%zu base=%lx",path,report.raw_bytes,report.gzip_bytes,base);
            DIAG_EVENT("HBC evidence %s raw_crc32=%08x read_bytes=%zu two_pass_equal=yes",hbc_dump_specs[candidate].tag,report.raw_crc32,report.read_bytes);
        }
    }
done:
    errno=saved_errno;
}
#endif
#endif
