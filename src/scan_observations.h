/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_SCAN_OBSERVATIONS_H
#define FULLSCREEN_SCAN_OBSERVATIONS_H
#include "scan_windows.h"
#include "diagnostic_events.h"
/* Diagnostic addresses only. Never used to select a write target. */
static struct {
    int pid;
    size_t count;
    struct { uintptr_t base; uint32_t length; uint8_t header[128]; } items[8];
} scan_native_probes;
static inline void scan_native_reset(int pid) {
    scan_native_probes.pid=pid; scan_native_probes.count=0;
}
static inline void scan_native_note(uintptr_t base,const uint8_t header[128]) {
    if(scan_native_probes.count==8)return;
    size_t at=scan_native_probes.count++;
    scan_native_probes.items[at].base=base;
    memcpy(&scan_native_probes.items[at].length,header+32,4);
    memcpy(scan_native_probes.items[at].header,header,128);
}
static inline void scan_report_native_maps(int pid,const struct scan_mapping *maps,size_t count,
                                          const struct scan_window *windows,size_t window_count) {
    if(scan_native_probes.pid!=pid)return;
    int saved_errno=errno;
    for(size_t p=0;p<scan_native_probes.count;p++) {
        uintptr_t base=scan_native_probes.items[p].base;
        size_t index=0;
        while(index<count && !(maps[index].start<=base && base<maps[index].end))index++;
        if(index==count) {
            DIAG_EVENT("Native HBC VM base=%lx length=%u region=absent",base,scan_native_probes.items[p].length);
            continue;
        }
        const struct scan_mapping *m=&maps[index];
        unsigned selected=0;
        for(size_t w=0;w<window_count;w++)if(windows[w].start<=base && base<windows[w].end) { selected=1; break; }
        const char *why=selected?"included":!(m->protection&1)?"not_readable":m->end-m->start>0x60000000ULL?"oversized":
                        m->kind==4 || m->kind==8?"device":"other_filter";
        (void)why;
        DIAG_EVENT("Native HBC VM base=%lx length=%u map=%zu start=%llx end=%llx kind=%u prot=%u reason=%s",base,scan_native_probes.items[p].length,index,
                   (unsigned long long)m->start,(unsigned long long)m->end,m->kind,m->protection,why);
        /* At most eight known 128-byte headers. Never sweep an excluded map,
         * read device memory or trust a stale sample as a patch candidate. */
        if((m->protection&1) && m->kind!=4 && m->kind!=8 && m->end-base>=128) {
            uint8_t current[128]; errno=0;
            int ret=kernel_proc_copyout(pid,base,current,sizeof(current)),error=ret?errno:0;
            const char *fresh=ret?"read_failed":memcmp(current,scan_native_probes.items[p].header,128)?"changed":"unchanged";
            (void)fresh; (void)error;
            DIAG_EVENT("Native HBC freshness base=%lx state=%s read_ret=%d errno=%d bytes=128",base,fresh,ret,error);
            if(!ret && memcmp(current,scan_native_probes.items[p].header,128))DIAG_BYTES("fresh_hbc_prefix",current,32);
        } else DIAG_EVENT("Native HBC freshness base=%lx state=unsafe_range_skipped",base);
    }
    errno=saved_errno;
}
#endif
