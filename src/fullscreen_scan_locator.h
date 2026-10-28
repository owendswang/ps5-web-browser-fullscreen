/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Scan policy-selected readable ranges, or report their metadata only.
 * Excluded mappings are not evidence that a target is absent from the process. */
#include "header_search.h"
#include "scan_windows.h"
#include "diagnostic_events.h"
#include "scan_observations.h"
#ifndef FULLSCREEN_MAPS_ONLY
#define FULLSCREEN_MAPS_ONLY 0
#endif
#define FAST_READ_BYTES (1024U*1024U)
#ifndef FAST_PRUNE
#define FAST_PRUNE 1
#endif
struct scan_target_stats { size_t shape,exact,extent_rejected; int sample; uint8_t header[128]; };
#define FULLSCREEN_SCAN_HAS_COVERAGE 1
static uint64_t scan_omitted_oversized_bytes;

static int locate_scan(int pid, struct source *sources, size_t count, int mode) {
    scan_omitted_oversized_bytes=0;
    int safe=mode==HBC_SCAN_SAFE,prune=mode==HBC_SCAN_PRUNED;
    size_t read_size=safe?0x10000U:FAST_READ_BYTES;
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_VMMAP,pid};
    size_t length=0;
    if (sysctl(mib,4,NULL,&length,NULL,0)) { DIAG_ERROR("hermes.scan.maps_size",errno,"Cannot query VM map size"); return -1; }
    if(length>SIZE_MAX-1024*1024) { DIAG_ERROR("hermes.scan.maps_size",0,"VM map size overflow"); return -1; }
    length+=1024*1024;
    char *maps=malloc(length);
    uint8_t *buf=malloc(read_size+127);
    if (!maps || !buf) { DIAG_ERROR("hermes.scan.allocate",errno,"Cannot allocate VM map/scan buffers"); free(maps); free(buf); return -1; }
    if (sysctl(mib,4,maps,&length,NULL,0)) { DIAG_ERROR("hermes.scan.maps_read",errno,"Cannot read VM maps"); free(maps); free(buf); return -1; }
    size_t map_count=0;
    for (char *p=maps;p<maps+length;) {
        struct kinfo_vmentry *v=(void *)p;
        if (maps+length-p<(ptrdiff_t)sizeof(v->kve_structsize) ||
            v->kve_structsize<144 || v->kve_structsize>maps+length-p) {
            DIAG_ERROR("hermes.scan.maps_format",0,"Invalid VM map record at index=%zu remaining=%zu",map_count,(size_t)(maps+length-p));
            free(maps); free(buf); return -1;
        }
        p+=v->kve_structsize; map_count++;
    }
    struct scan_mapping *regions=calloc(map_count,sizeof(*regions));
    struct scan_window *windows=calloc(map_count,sizeof(*windows));
    if (!regions || !windows) { DIAG_ERROR("hermes.scan.allocate",errno,"Cannot allocate %zu VM windows",map_count); free(regions); free(windows); free(maps); free(buf); return -1; }
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
    if (hbc_scan_windows(regions,map_count,minimum_length,mode,windows,&window_count)) {
        DIAG_ERROR("hermes.scan.maps_order",0,"Rejected VM ordering, bounds or source length; maps=%zu min_length=%llu",map_count,(unsigned long long)minimum_length);
        free(regions); free(windows); free(maps); free(buf); return -1;
    }
    size_t readable_maps=0,other_kind=0,nonresident=0,oversized=0,devices=0,kind_counts[8]={0};
    uint64_t readable_bytes=0,planned_bytes=0,oversized_bytes=0,device_bytes=0;
    for(size_t i=0;i<map_count;i++)if(regions[i].protection&1) {
        readable_maps++; readable_bytes+=regions[i].end-regions[i].start;
        kind_counts[regions[i].kind<7?regions[i].kind:7]++;
        if(regions[i].kind!=1 && regions[i].kind!=3)other_kind++;
        if(regions[i].kind==4 || regions[i].kind==8) { devices++; device_bytes+=regions[i].end-regions[i].start; }
        if(!regions[i].resident)nonresident++;
        if(regions[i].end-regions[i].start>0x60000000ULL) { oversized++; oversized_bytes+=regions[i].end-regions[i].start; }
    }
    for(size_t i=0;i<window_count;i++)planned_bytes+=windows[i].end-windows[i].start;
    printf("Scan VM policy: %s max_map=0x60000000; prune=%d\n",
           safe?"readable non-device mappings; residency unrestricted":"kinds=1,3 resident=yes",prune);
    DIAG_EVENT("VM coverage: maps=%zu readable=%zu readable_bytes=%llu planned_bytes=%llu min_length=%llu",
               map_count,readable_maps,(unsigned long long)readable_bytes,(unsigned long long)planned_bytes,(unsigned long long)minimum_length);
    if(safe)DIAG_EVENT("VM safe exclusions: devices=%zu oversized=%zu; resident=any kinds=except4,8 max=0x60000000",devices,oversized);
    else DIAG_EVENT("VM exclusions (overlap allowed): other_kind=%zu nonresident=%zu oversized=%zu; kinds=1,3 resident=yes max=0x60000000 prune=%d",
                    other_kind,nonresident,oversized,prune);
    DIAG_EVENT("VM map ABI: bytes=%zu records=%zu first_record=%u sdk_record=%zu",length,map_count,map_count?((struct kinfo_vmentry *)maps)->kve_structsize:0U,sizeof(struct kinfo_vmentry));
    DIAG_EVENT("Readable VM kinds: 0=%zu 1=%zu 2=%zu 3=%zu 4=%zu 5=%zu 6=%zu >=7=%zu",kind_counts[0],kind_counts[1],kind_counts[2],kind_counts[3],kind_counts[4],kind_counts[5],kind_counts[6],kind_counts[7]);
    DIAG_EVENT("VM excluded byte totals (overlap allowed): oversized=%llu device=%llu",(unsigned long long)oversized_bytes,(unsigned long long)device_bytes);
    scan_omitted_oversized_bytes=oversized_bytes;
    unsigned large_samples=0; size_t record_index=0;
    for(char *p=maps;p<maps+length;p+=((struct kinfo_vmentry *)p)->kve_structsize,record_index++) {
        const struct scan_mapping *m=&regions[record_index];
        if((m->protection&1) && m->end-m->start>0x60000000ULL && large_samples++<2) {
            DIAG_EVENT("VM oversized region=%zu start=%llx end=%llx bytes=%llu kind=%u prot=%u resident=%u",record_index,
                       (unsigned long long)m->start,(unsigned long long)m->end,(unsigned long long)(m->end-m->start),m->kind,m->protection,m->resident);
            DIAG_SPAN("vm_oversized_record",(const uint8_t *)p,144);
        }
    }
    scan_report_native_maps(pid,regions,map_count,windows,window_count);
    if(FULLSCREEN_MAPS_ONLY) {
        DIAG_EVENT("Passive VM inventory: bulk_process_reads=0; selected ranges are planned only");
        DIAG_ERROR("hermes.scan.metadata_only",0,"VM inventory complete; bulk memory scan, browser bootstrap and SELF export disabled");
        free(regions); free(windows); free(maps); free(buf); return 1;
    }
    struct scan_target_stats *stats=calloc(count,sizeof(*stats));
    if(!stats)DIAG_EVENT("Scan target diagnostic allocation failed; continuing verified scan");
    size_t scanned=0, read_calls=0, next_progress=256*1024*1024;
    size_t unreadable=0, failed_reads=0, headers=0;
    int result=-1;
#if PROFILE
    uint64_t read_ns=0, search_ns=0;
#endif
    printf("%s: %s, %zu candidate mapping windows, %zu KiB reads\n",safe?"Safe locator":"Fast locator",
           safe?"expanded readable ranges":prune?"complete-HBC extents":"full-range fallback",window_count,read_size>>10);
    uint64_t previous_end=0; size_t carry=0;
    for (size_t w=0;w<window_count;w++) {
        const struct scan_window *v=&windows[w];
        if (v->start!=previous_end) carry=0;
        for (uintptr_t addr=v->start;addr<v->end;) {
            size_t n=v->end-addr;
            if (n>read_size) n=read_size;
            START_TIMER(read_started);
            read_calls++;
            errno=0; int read_result=kernel_proc_copyout(pid,addr,buf+carry,n);
            if (read_result) {
                failed_reads++;
                if(failed_reads<=2)DIAG_EVENT("Scan read failure: window=%zu offset=%llx bytes=%zu ret=%d errno=%d",w,(unsigned long long)(addr-v->start),n,read_result,errno);
                if (n>0x1000) n=0x1000;
                read_calls++;
                errno=0; read_result=kernel_proc_copyout(pid,addr,buf+carry,n);
                if (read_result) {
                    failed_reads++; unreadable+=n;
                    if(failed_reads<=2)DIAG_EVENT("Scan page failure: window=%zu offset=%llx bytes=%zu ret=%d errno=%d",w,(unsigned long long)(addr-v->start),n,read_result,errno);
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
            scanned+=n;
            for (size_t at=hbc_header_next(buf,total,0);at!=SIZE_MAX;at=hbc_header_next(buf,total,at+1)) {
                headers++;
                for(size_t i=0;stats && i<count;i++)
                    if(!memcmp(buf+at+8,sources[i].data+8,4) && !memcmp(buf+at+32,sources[i].data+32,4)) {
                        stats[i].shape++;
                        if(!stats[i].sample && memcmp(buf+at,sources[i].data,128)) {
                            stats[i].sample=1; memcpy(stats[i].header,buf+at,128);
                        }
                    }
                for (size_t i=0;i<count;i++) if (!memcmp(buf+at,sources[i].data,128)) {
                    if(stats)stats[i].exact++;
                    uintptr_t found=addr-carry+at;
                    if (prune && (found>v->readable_end || sources[i].length>v->readable_end-found)) {
                        if(stats)stats[i].extent_rejected++;
                        continue;
                    }
                    if (sources[i].base && sources[i].base!=found) {
                        DIAG_ERROR("hermes.scan.ambiguous",0,"Multiple matching %s HBC images",sources[i].title);
                        printf("Multiple matching live %s images; no writes\n",sources[i].title); goto finish;
                    }
                    sources[i].base=found;
                    printf("Located %s at %lx\n",sources[i].title,found);
                }
            }
            carry=total<127?total:127;
            memmove(buf,buf+total-carry,carry); addr+=n;
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
    printf("Fast scan coverage: maps=%zu windows=%zu unreadable=%zu failed_reads=%zu HBC_headers=%zu result=%d\n",
           map_count,window_count,unreadable,failed_reads,headers,result);
    DIAG_EVENT("HBC scan: prune=%d maps=%zu windows=%zu bytes=%zu unreadable=%zu reads=%zu failed=%zu headers=%zu result=%d mode=%d",
               prune,map_count,window_count,scanned,unreadable,read_calls,failed_reads,headers,result,mode);
    for(size_t i=0;i<count;i++) {
        DIAG_EVENT("HBC scan target %s: located=%s",sources[i].title,sources[i].base?"yes":"no");
        if(stats) {
            DIAG_EVENT("HBC target %s: same_version_length=%zu exact_header=%zu extent_rejected=%zu",sources[i].title,stats[i].shape,stats[i].exact,stats[i].extent_rejected);
            if(stats[i].sample) {
                unsigned first=0; while(first<128 && stats[i].header[first]==sources[i].data[first])first++;
                DIAG_EVENT("HBC near %s: first_diff=%u expected=%02x observed=%02x; diagnostic only",sources[i].title,first,sources[i].data[first],stats[i].header[first]);
                DIAG_SPAN("scan_expected",sources[i].data,128);
                DIAG_SPAN("scan_observed",stats[i].header,128);
            }
        }
    }
#if PROFILE
    printf("Timing scan_reads=%.3f ms scan_search=%.3f ms\n",read_ns/1000000.0,search_ns/1000000.0);
#endif
    free(stats); free(regions); free(windows); free(maps); free(buf); return result;
}

#if !FULLSCREEN_HYBRID
static int locate_sources_scan(int pid, struct source *sources, size_t count) {
    int result=locate_scan(pid,sources,count,FAST_PRUNE);
    if (FAST_PRUNE && result==1) {
        puts("Retrying full-range scan without extent pruning");
        for (size_t i=0;i<count;i++) sources[i].base=0;
        result=locate_scan(pid,sources,count,0);
    }
    return result;
}
#endif
static inline int locate_sources_safe(int pid, struct source *sources, size_t count) {
    for(size_t i=0;i<count;i++)sources[i].base=0;
    return locate_scan(pid,sources,count,HBC_SCAN_SAFE);
}

