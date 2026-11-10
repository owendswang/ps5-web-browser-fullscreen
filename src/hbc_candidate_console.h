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
#endif
