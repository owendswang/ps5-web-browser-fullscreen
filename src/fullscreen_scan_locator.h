/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Included by fullscreen.c only with FULLSCREEN_FAST=1.
 * Search all possible complete HBC images, with a full-range fallback when
 * required. No cached addresses or early successful exit. */
#include "header_search.h"
#include "scan_windows.h"
#define FAST_READ_BYTES (1024U*1024U)
#ifndef FAST_PRUNE
#define FAST_PRUNE 1
#endif

static int locate_scan(int pid, struct source *sources, size_t count, int prune) {
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_VMMAP,pid};
    size_t length=0;
    if (sysctl(mib,4,NULL,&length,NULL,0)) return -1;
    length+=1024*1024;
    char *maps=malloc(length);
    uint8_t *buf=malloc(FAST_READ_BYTES+127);
    if (!maps || !buf) { free(maps); free(buf); return -1; }
    if (sysctl(mib,4,maps,&length,NULL,0)) { free(maps); free(buf); return -1; }
    size_t map_count=0;
    for (char *p=maps;p<maps+length;) {
        struct kinfo_vmentry *v=(void *)p;
        if (v->kve_structsize<144 || v->kve_structsize>maps+length-p) { free(maps); free(buf); return -1; }
        p+=v->kve_structsize; map_count++;
    }
    struct scan_mapping *regions=calloc(map_count,sizeof(*regions));
    struct scan_window *windows=calloc(map_count,sizeof(*windows));
    if (!regions || !windows) { free(regions); free(windows); free(maps); free(buf); return -1; }
    size_t index=0;
    for (char *p=maps;p<maps+length;) {
        struct kinfo_vmentry *v=(void *)p;
        regions[index++]=(struct scan_mapping){v->kve_start,v->kve_end,v->kve_type,v->kve_protection,
                                              v->kve_resident?1U:0U};
        p+=v->kve_structsize;
    }
    uint64_t minimum_length=UINT64_MAX;
    for (size_t i=0;i<count;i++) if (sources[i].length<minimum_length) minimum_length=sources[i].length;
    size_t window_count=0;
    if (hbc_scan_windows(regions,map_count,minimum_length,prune,windows,&window_count)) {
        free(regions); free(windows); free(maps); free(buf); return -1;
    }
    size_t scanned=0, read_calls=0, next_progress=256*1024*1024;
    int result=-1;
#if PROFILE
    uint64_t read_ns=0, search_ns=0;
#endif
    printf("Fast locator: %s, %zu candidate mapping windows, 1 MiB reads\n",
           prune?"complete-HBC extents":"full-range fallback",window_count);
    uint64_t previous_end=0; size_t carry=0;
    for (size_t w=0;w<window_count;w++) {
        const struct scan_window *v=&windows[w];
        if (v->start!=previous_end) carry=0;
        for (uintptr_t addr=v->start;addr<v->end;) {
            size_t n=v->end-addr;
            if (n>FAST_READ_BYTES) n=FAST_READ_BYTES;
            START_TIMER(read_started);
            read_calls++;
            if (kernel_proc_copyout(pid,addr,buf+carry,n)) {
                if (n>0x1000) n=0x1000;
                read_calls++;
                if (kernel_proc_copyout(pid,addr,buf+carry,n)) {
#if PROFILE
                    read_ns+=tick_ns()-read_started;
#endif
                    addr+=n; carry=0; continue;
                }
            }
#if PROFILE
            read_ns+=tick_ns()-read_started;
#endif
            START_TIMER(search_started);
            size_t total=n+carry;
            for (size_t at=hbc_header_next(buf,total,0);at!=SIZE_MAX;at=hbc_header_next(buf,total,at+1)) {
                for (size_t i=0;i<count;i++) if (!memcmp(buf+at,sources[i].data,128)) {
                    uintptr_t found=addr-carry+at;
                    if (prune && (found>v->readable_end || sources[i].length>v->readable_end-found)) continue;
                    if (sources[i].base && sources[i].base!=found) {
                        printf("Multiple matching live %s images; no writes\n",sources[i].title); goto finish;
                    }
                    sources[i].base=found;
                    printf("Located %s at %lx\n",sources[i].title,found);
                }
            }
            carry=total<127?total:127;
            memmove(buf,buf+total-carry,carry); addr+=n; scanned+=n;
#if PROFILE
            search_ns+=tick_ns()-search_started;
#endif
            if (scanned>=next_progress) {
                printf("Scanned %zu MiB\n",scanned>>20); next_progress=scanned+256*1024*1024;
            }
        }
        previous_end=v->end;
    }
    for (size_t i=0;i<count;i++) if (!sources[i].base) {
        printf("%s not found in this scan\n",sources[i].title); result=1; goto finish;
    }
    result=0;
finish:
    printf("Fast scan: %zu MiB, %zu read calls\n",scanned>>20,read_calls);
#if PROFILE
    printf("Timing scan_reads=%.3f ms scan_search=%.3f ms\n",read_ns/1000000.0,search_ns/1000000.0);
#endif
    free(regions); free(windows); free(maps); free(buf); return result;
}

static int locate_sources_scan(int pid, struct source *sources, size_t count) {
    int result=locate_scan(pid,sources,count,FAST_PRUNE);
    if (FAST_PRUNE && result==1) {
        puts("Retrying full-range scan without extent pruning");
        for (size_t i=0;i<count;i++) sources[i].base=0;
        result=locate_scan(pid,sources,count,0);
    }
    return result;
}

