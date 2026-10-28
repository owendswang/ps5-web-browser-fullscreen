/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_SCAN_WINDOWS_H
#define FULLSCREEN_SCAN_WINDOWS_H
#include <stddef.h>
#include <stdint.h>

struct scan_mapping {
    uint64_t start, end;
    unsigned kind, protection, resident;
};
struct scan_window { uint64_t start, end, readable_end; };
enum { HBC_SCAN_UNPRUNED=0, HBC_SCAN_PRUNED=1, HBC_SCAN_SAFE=2 };

/* A complete HBC must fit in contiguous readable virtual memory. The package
 * may cross mapping boundaries, so do not discard individual short mappings
 * until the readable extent of their adjacent mappings is known.
 * Output preserves the original order and never reads across a map boundary.
 * SAFE broadens kind/residency coverage, retaining device and size exclusions. */
static inline int hbc_scan_windows(const struct scan_mapping *maps, size_t count,
                                  uint64_t minimum_length, int mode,
                                  struct scan_window *windows, size_t *window_count) {
    if (minimum_length<128 || mode<0 || mode>HBC_SCAN_SAFE) return -1;
    for (size_t i=0;i<count;i++) {
        if (maps[i].end<maps[i].start || maps[i].end>0x800000000000ULL ||
            (i && maps[i].start<maps[i-1].end)) return -1;
    }
    size_t used=0;
    uint64_t extent=0;
    for (size_t i=count;i>0;) {
        i--;
        const struct scan_mapping *m=&maps[i];
        if (!(m->protection&1)) { extent=m->start; continue; }
        if (i+1>=count || m->end!=maps[i+1].start || !(maps[i+1].protection&1)) extent=m->end;
        if(m->end-m->start>0x60000000ULL)continue;
        if(mode==HBC_SCAN_SAFE) {
            /* Broaden ordinary memory coverage without reading device maps. */
            if(m->kind==4 || m->kind==8)continue;
        } else if((m->kind!=1 && m->kind!=3) || !m->resident)continue;
        uint64_t end=m->end;
        if (mode==HBC_SCAN_PRUNED) {
            if (extent-m->start<minimum_length) continue;
            uint64_t limit=extent-minimum_length+128;
            /* Page rounding keeps SDK fallback reads page-sized. Extra header
             * candidates are checked against readable_end before acceptance. */
            limit=(limit+4095)&~4095ULL;
            if (limit<end) end=limit;
            if (end<=m->start) continue;
        }
        windows[used++]=(struct scan_window){m->start,end,extent};
    }
    for (size_t i=0;i<used/2;i++) {
        struct scan_window tmp=windows[i]; windows[i]=windows[used-i-1]; windows[used-i-1]=tmp;
    }
    *window_count=used;
    return 0;
}
#endif

