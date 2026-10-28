/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_RELATED_PROCESSES_H
#define WEB_BROWSER_RELATED_PROCESSES_H
/* Failure metadata only; no attach, process selection or process-memory scan. */
static void observe_related_processes(int selected_pid) {
    int saved=errno,mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0};
    size_t length=0,matched=0,reported=0,shells=0;
    if(sysctl(mib,4,NULL,&length,NULL,0) || !length || length>16*1024*1024) {
        DIAG_EVENT("Related process inventory unavailable: bytes=%zu errno=%d",length,errno); errno=saved; return;
    }
    size_t capacity=length+65536;
    char *list=malloc(capacity);
    if(!list) { DIAG_EVENT("Related process inventory allocation failed"); errno=saved; return; }
    length=capacity;
    if(sysctl(mib,4,list,&length,NULL,0) || length>capacity) {
        DIAG_EVENT("Related process inventory read failed: errno=%d",errno); free(list); errno=saved; return;
    }
    for(size_t at=0;at<length;) {
        struct kinfo_proc *p=(void *)(list+at);
        size_t minimum=offsetof(struct kinfo_proc,ki_comm)+sizeof(p->ki_comm);
        if(length-at<sizeof(p->ki_structsize) || p->ki_structsize<=0 ||
           (size_t)p->ki_structsize<minimum || (size_t)p->ki_structsize>length-at) {
            DIAG_EVENT("Related process inventory rejected record at=%zu remaining=%zu",at,length-at); break;
        }
        at+=(size_t)p->ki_structsize;
        char name[sizeof(p->ki_comm)+1]; memcpy(name,p->ki_comm,sizeof(p->ki_comm)); name[sizeof(p->ki_comm)]=0;
        for(size_t i=0;name[i];i++)if((unsigned char)name[i]<32 || (unsigned char)name[i]>126)name[i]='?';
        if(!strcmp(name,"SceShellUI"))shells++;
        if(!strstr(name,"Shell") && !strstr(name,"NK") && !strstr(name,"Web") &&
           !strstr(name,"Browser") && !strstr(name,"Rnps"))continue;
        matched++; if(reported>=8)continue;
        uint32_t handle=0;
        int hermes=!kernel_dynlib_handle(p->ki_pid,"libhermes-0.11.sprx",&handle);
        uintptr_t hermes_base=hermes?kernel_dynlib_mapbase_addr(p->ki_pid,handle):0;
        int jsc=!kernel_dynlib_handle(p->ki_pid,"libSceJsc.sprx",&handle);
        uintptr_t jsc_base=jsc?kernel_dynlib_mapbase_addr(p->ki_pid,handle):0;
        DIAG_EVENT("Related process name=%s pid=%d ppid=%d state=%d selected=%u Hermes=%u base=%lx JSC=%u base=%lx",name,p->ki_pid,p->ki_ppid,p->ki_stat,p->ki_pid==selected_pid,hermes,hermes_base,jsc,jsc_base);
        (void)hermes_base; (void)jsc_base; reported++;
    }
    DIAG_EVENT("Related process inventory: name-filter=Shell,NK,Web,Browser,Rnps matched=%zu reported=%zu ShellUI_matches=%zu",matched,reported,shells);
    free(list); errno=saved;
}
#endif
