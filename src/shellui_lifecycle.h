/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_SHELLUI_LIFECYCLE_H
#define WEB_BROWSER_SHELLUI_LIFECYCLE_H
/* Used only after UI initialization or failure; ordinary cache hits do not poll. */
struct shellui_state { int pid,vm_result,vm_error,hermes,jsc; size_t vm_bytes; uintptr_t base; };
static int shellui_vm_probe(int pid,size_t *length,int *error) {
    if(pid<=0) { *length=0; *error=ESRCH; return -1; }
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_VMMAP,pid};
    *length=0; errno=0;
    int result=sysctl(mib,4,NULL,length,NULL,0);
    *error=result?errno:0; return result;
}
static struct shellui_state shellui_state_read(void) {
    struct shellui_state s={.pid=find_shellui()}; uint32_t handle=0;
    s.vm_result=shellui_vm_probe(s.pid,&s.vm_bytes,&s.vm_error);
    if(s.pid>0) {
        s.hermes=!kernel_dynlib_handle(s.pid,"libhermes-0.11.sprx",&handle);
        if(s.hermes)s.base=kernel_dynlib_mapbase_addr(s.pid,handle);
        s.jsc=!kernel_dynlib_handle(s.pid,"libSceJsc.sprx",&handle);
    }
    return s;
}
static void observe_shellui(const char *phase,int previous) {
    int saved=errno; struct shellui_state s=shellui_state_read();
    DIAG_EVENT("ShellUI state phase=%s previous=%d observed=%d pid_changed=%u",phase,previous,s.pid,s.pid>0 && s.pid!=previous);
    DIAG_EVENT("ShellUI readiness pid=%d vm_ret=%d vm_errno=%d vm_bytes=%zu Hermes=%u JSC=%u base=%lx",s.pid,s.vm_result,s.vm_error,s.vm_bytes,s.hermes,s.jsc,s.base);
#if FULLSCREEN_SAFE_SCAN && !FULLSCREEN_PASSIVE_DIAGNOSTICS
    if((!strcmp(phase,"after_open") || !strcmp(phase,"after_home")) && s.pid>0 && s.hermes && s.base)
        anchor_phase_snapshot(phase,s.pid,s.base);
#endif
    if(previous>0 && previous!=s.pid) {
        size_t length; int error;
        int ret=shellui_vm_probe(previous,&length,&error);
        DIAG_EVENT("Previous ShellUI pid=%d vm_ret=%d vm_errno=%d vm_bytes=%zu",previous,ret,error,length);
    }
    errno=saved;
}
static int hybrid_refresh_shellui(int *target_pid) {
    int previous=*target_pid,prior=-2,prior_ready=-1,stable=0;
    for(unsigned attempt=0;attempt<30;attempt++) {
        struct shellui_state s=shellui_state_read();
        /* VM permission/ABI errors must not disable otherwise usable native
         * location. Only ESRCH confirms this observed PID is already gone. */
        int ready=s.pid>0 && s.hermes && s.base && !(s.vm_result && s.vm_error==ESRCH);
        if(s.pid!=prior || ready!=prior_ready || attempt==29)
            DIAG_EVENT("ShellUI rebind attempt=%u previous=%d observed=%d ready=%u vm_errno=%d Hermes=%u base=%lx",attempt+1,previous,s.pid,ready,s.vm_error,s.hermes,s.base);
        stable=ready?(s.pid==prior && prior_ready?stable+1:1):0;
        prior=s.pid; prior_ready=ready;
        if(stable>=2) {
            *target_pid=s.pid; diagnostic.pid=(uint32_t)s.pid;
            if(browser_engine(s.pid)!=BROWSER_HERMES) {
                DIAG_ERROR("shellui.engine_changed",0,"RNPS engine changed during browser initialization; no writes"); return -1;
            }
            DIAG_EVENT("ShellUI rebound previous=%d current=%d pid_changed=%u stable_probes=%d",previous,s.pid,previous!=s.pid,stable);
            return 0;
        }
        if(attempt<29)usleep(100000);
    }
    DIAG_ERROR("shellui.not_ready",0,"ShellUI/Hermes did not become ready after browser initialization; previous_pid=%d observed_pid=%d",previous,prior);
    return -1;
}
#endif
