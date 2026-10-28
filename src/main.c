/* SPDX-License-Identifier: GPL-3.0-or-later */
/* One mainline: verified references, persistent INI, adaptive discovery. */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <machine/reg.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ps5/kernel.h>
#include "hbc_patch.h"
#include "notification.h"

#ifndef RESTORE
#define RESTORE 0
#endif
#ifndef LOCATE_ONLY
#define LOCATE_ONLY 0
#endif
#ifndef PROFILE
#define PROFILE 1
#endif
#ifndef FULLSCREEN_PASSIVE_DIAGNOSTICS
#define FULLSCREEN_PASSIVE_DIAGNOSTICS 0
#endif
#define FULLSCREEN_HYBRID 1
#define FULLSCREEN_FAST 1
#include "diagnostics.h"

#if PROFILE
static uint64_t tick_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC,&now)) return 0;
    return (uint64_t)now.tv_sec*1000000000UL+now.tv_nsec;
}
#define START_TIMER(name) uint64_t name=tick_ns()
#define REPORT_TIMER(label,name) printf("Timing %s=%.3f ms\n",label,(tick_ns()-(name))/1000000.0)
#else
#define START_TIMER(name) ((void)0)
#define REPORT_TIMER(label,name) ((void)0)
#endif

struct source {
    const char *title;
    uint8_t *allocation, *data;
    size_t length;
    uintptr_t base;
    struct hbc_plan plan;
};
struct rnps_request { void *buffer; uint32_t size; int32_t result; };
_Static_assert(sizeof(struct rnps_request)==16,"RNPS ioctl ABI");
static const uint8_t magic[]={0xc6,0x1f,0xbc,3,0xc1,3,0x19,0x1f};

static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static int read_bundle(struct source *source) {
    DIAG_STEP("bundle.read");
    DIAG_EVENT("Reading original RNPS bundle: %s",source->title);
    START_TIMER(read_started);
    char path[256];
    snprintf(path,sizeof(path),"/system_ex/rnps/apps/%s/application.ps.bundle",source->title);
    FILE *file=fopen(path,"rb");
    if (!file) { DIAG_ERROR("bundle.open",errno,"Cannot open %s",path); perror(path); return -1; }
    if (fseek(file,0,SEEK_END)) { DIAG_ERROR("bundle.size",errno,"Cannot seek %s",source->title); fclose(file); return -1; }
    long size=ftell(file);
    if (size<128 || size>32*1024*1024 || fseek(file,0,SEEK_SET)) { DIAG_ERROR("bundle.size",0,"Rejected bundle size/seek: %s size=%ld",source->title,size); fclose(file); return -1; }
    source->allocation=malloc(size);
    if (!source->allocation) { DIAG_ERROR("bundle.allocate",errno,"Cannot allocate %ld bundle bytes",size); fclose(file); return -1; }
    size_t got=fread(source->allocation,1,size,file);
    fclose(file);
    if (got!=(size_t)size) { DIAG_ERROR("bundle.read",0,"Short %s read: %zu/%ld bytes",source->title,got,size); puts("Short bundle read"); return -1; }
    REPORT_TIMER("bundle_read",read_started);
    START_TIMER(decode_started);
    DIAG_STEP("bundle.decode");
    uint8_t *data=source->allocation;
    uint32_t offset=0, plain_size=size;
    if (!memcmp(data,"RNPSHEDR",8)) {
        offset=u32(data+0x1c); plain_size=u32(data+0x24);
        if (offset>(uint32_t)size || plain_size>(uint32_t)size-offset || plain_size<128) {
            DIAG_ERROR("bundle.decode",0,"Invalid RNPS bounds: %s offset=%x length=%x size=%ld",source->title,offset,plain_size,size);
            puts("Invalid RNPS body bounds"); return -1;
        }
        if (memcmp(data+offset,magic,8)) {
            int fd=open("/dev/rnps",O_RDWR);
            if (fd<0) { DIAG_ERROR("bundle.decode_open",errno,"Cannot open /dev/rnps"); perror("/dev/rnps"); return -1; }
            struct rnps_request request={data,size,(int32_t)0x800f1225};
            int ret=ioctl(fd,0xc0105203UL,&request);
            int decode_errno=errno;
            close(fd);
            if (ret<0 || request.result) {
                DIAG_ERROR("bundle.decode",ret<0?(uint32_t)decode_errno:(uint32_t)request.result,
                           "RNPS %s ioctl=%d result=%#x errno=%d",source->title,ret,request.result,decode_errno);
                printf("RNPS decode failed ioctl=%d result=%#x\n",ret,request.result); return -1;
            }
            /* The driver may update header fields; revalidate them. */
            offset=u32(data+0x1c); plain_size=u32(data+0x24);
            if (offset>(uint32_t)size || plain_size>(uint32_t)size-offset || plain_size<128) {
                DIAG_ERROR("bundle.decode",0,"Driver returned invalid bounds for %s",source->title); return -1;
            }
        }
    }
    source->data=data+offset; source->length=plain_size;
    REPORT_TIMER("bundle_decode",decode_started);
    return 0;
}
static int load_source(struct source *source, int card_host) {
    char error[256];
    if(read_bundle(source))return -1;
    if(memcmp(source->data,magic,8)) { DIAG_ERROR("bundle.format",0,"%s is not Hermes HBC; magic=%08x",source->title,u32(source->data)); puts("Expected Hermes bytecode"); return -1; }
    size_t size=u32(source->data+32);
    if(size>source->length || size<128) { DIAG_ERROR("bundle.format",0,"Invalid HBC length %zu for %s",size,source->title); return -1; }
    source->length=size;
    START_TIMER(plan_started);
    DIAG_STEP("hermes.semantic_plan");
    DIAG_EVENT("%s HBC version=%u length=%zu",source->title,u32(source->data+8),source->length);
    printf("%s: HBC v%u length=%zu\n",source->title,u32(source->data+8),source->length);
    DIAG_SPAN(source->title,source->data,128);
    if (hbc_make_plan(source->data,source->length,card_host,&source->plan,error,sizeof(error))) {
        DIAG_ERROR("hermes.semantic_plan",0,"%s: %s",source->title,error);
        printf("Semantic discovery refused %s: %s\n",source->title,error); return -1;
    }
    REPORT_TIMER("semantic_plan",plan_started);
    for (unsigned i=0;i<source->plan.count;i++) {
        const struct hbc_patch *p=&source->plan.patches[i];
        printf("  discovered %-15s HBC+%x length=%u\n",p->name,p->offset,p->length);
    }
    return 0;
}
static int find_shellui(void) {
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0};
    size_t length=0;
    if (sysctl(mib,4,NULL,&length,NULL,0)) { DIAG_ERROR("shellui.enumerate",errno,"Cannot query process-list size"); return -1; }
    char *buf=malloc(length);
    if (!buf) { DIAG_ERROR("shellui.enumerate",errno,"Cannot allocate process list"); return -1; }
    if (sysctl(mib,4,buf,&length,NULL,0)) { DIAG_ERROR("shellui.enumerate",errno,"Cannot read process list"); free(buf); return -1; }
    int pid=-1;
    for (char *at=buf;at<buf+length;) {
        struct kinfo_proc *p=(void *)at;
        if (p->ki_structsize<=0 || p->ki_structsize>buf+length-at) break;
        at+=p->ki_structsize;
        if (!strcmp(p->ki_comm,"SceShellUI")) { pid=p->ki_pid; break; }
    }
    free(buf); return pid;
}
#include "fullscreen_fixed_locator.h"
#include "fullscreen_fast_locator.h"
static void observe_shellui(const char *phase,int previous);
static int hybrid_refresh_shellui(int *target_pid);
#define HYBRID_OBSERVE_SHELLUI observe_shellui
#include "browser_bootstrap.h"
#include "fullscreen_hybrid.h"
#if FULLSCREEN_PASSIVE_DIAGNOSTICS
_Static_assert(LOCATE_ONLY && FULLSCREEN_MAPS_ONLY && !HYBRID_AUTO_BROWSER && !TEST_HERMES_EXPORT,
               "Passive diagnosis cannot patch, bootstrap, bulk-scan or export SELF");
#endif
#if FULLSCREEN_SAFE_SCAN && TEST_HERMES_EXPORT
#include "../payloads/direct_hermes_export.h"
#endif
#if TEST_HBC_EXPORT
#include "hbc_candidate_console.h"
#endif
static int trace_request(int request, int pid, void *address, int data) {
    pid_t self=getpid();
    uint64_t auth=kernel_get_ucred_authid(self);
    uint8_t caps[16], elevated[16]; memset(elevated,0xff,sizeof(elevated));
    if (!auth || kernel_get_ucred_caps(self,caps)) return -1;
    if (kernel_set_ucred_authid(self,0x4800000000010003UL)) return -1;
    if (kernel_set_ucred_caps(self,elevated)) { kernel_set_ucred_authid(self,auth); return -1; }
    int ret=__syscall(SYS_ptrace,request,pid,address,data), saved=errno;
    int caps_ret=kernel_set_ucred_caps(self,caps);
    int auth_ret=kernel_set_ucred_authid(self,auth);
    errno=saved;
    if (caps_ret || auth_ret) puts("Warning: failed to restore payload credentials");
    return ret;
}
static int trace(int request, int pid) { return trace_request(request,pid,NULL,0); }
#include "jsc_fullscreen.h"
#include "browser_engine.h"
#include "shellui_lifecycle.h"
#include "related_processes.h"
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);
    START_TIMER(total_started);
    diag_begin(kernel_get_fw_version(),LOCATE_ONLY?"inspect":RESTORE?"restore":"apply");
    DIAG_EVENT("Payload build=%s diagnostics=2 cache=%u",DIAG_BUILD,HYBRID_CACHE_VERSION);
    printf("Payload build=%s diagnostics=2 cache=%u\n",DIAG_BUILD,HYBRID_CACHE_VERSION);
    DIAG_STEP("shellui.find");
    struct source sources[2]={{.title="NPXS40036"},{.title="NPXS40003"}};
    uint8_t previous[2][HBC_PATCH_MAX][HBC_PATCH_BYTES], check[128];
    int pid=find_shellui(), attached=0, result=1, engine=0;
#if FULLSCREEN_SAFE_SCAN && TEST_HERMES_EXPORT
    int test_export_result=0;
#endif
    diagnostic.pid=pid>0?(uint32_t)pid:0;
    DIAG_EVENT("ShellUI PID=%d",pid);
    const char *failure="ShellUI not found";
    printf("Web browser fullscreen %s fw=%08x ShellUI=%d\n",
           LOCATE_ONLY?"inspect":RESTORE?"restore":"apply",kernel_get_fw_version(),pid);
    if(pid<0) { if(!diagnostic.reason[0])DIAG_ERROR("shellui.find",0,"SceShellUI was not found"); goto finish; }
    failure="browser engine unavailable or ambiguous";
    DIAG_STEP("engine.detect");
    engine=browser_engine(pid);
    if(engine<0)goto finish;
    if(engine==BROWSER_JSC) {
        START_TIMER(jsc_started);
        result=jsc_run(pid,&attached,&failure);
        REPORT_TIMER("jsc_prepare_transaction",jsc_started);
        goto finish;
    }
    failure=FULLSCREEN_PASSIVE_DIAGNOSTICS?"Diagnostic collection; no fullscreen operation attempted":"browser discovery or validation error";
    START_TIMER(prepare_started);
    if(hybrid_prepare(&pid,sources,&attached))goto finish;
    REPORT_TIMER("prepare",prepare_started);
    if (LOCATE_ONLY) {
        puts("Discovery complete; no RAM writes; INI may be refreshed");
        result=0; goto finish;
    }
    START_TIMER(patch_started);
    if (!attached) {
        failure="cannot attach to ShellUI";
        if (trace(PT_ATTACH,pid)) { DIAG_ERROR("transaction.attach",errno,"Cannot attach to ShellUI"); perror("PT_ATTACH; no writes"); goto finish; }
        attached=1;
        int status=0;
        failure="cannot stop ShellUI";
        if (waitpid(pid,&status,0)!=pid || !WIFSTOPPED(status)) { DIAG_ERROR("transaction.stop",errno,"Cannot confirm ShellUI stop"); perror("waitpid"); goto finish; }
    }
    for (unsigned i=0;i<2;i++) {
        struct source *s=&sources[i];
        failure="live browser identity changed";
        int read_error=kernel_proc_copyout(pid,s->base,check,128);
        if (read_error || memcmp(check,s->data,128)) {
            DIAG_ERROR("transaction.identity",0,"Live HBC header changed: %s",s->title);
            if(!read_error)DIAG_BYTES("observed_hbc_header",check,32);
            puts("Live HBC identity changed; no writes"); goto finish;
        }
        for (unsigned j=0;j<s->plan.count;j++) {
            struct hbc_patch *p=&s->plan.patches[j];
            failure="unexpected browser patch bytes";
            read_error=kernel_proc_copyout(pid,s->base+p->offset,previous[i][j],p->length);
            if (read_error ||
                (memcmp(previous[i][j],p->before,p->length) && memcmp(previous[i][j],p->after,p->length))) {
                DIAG_ERROR("transaction.patch_bytes",0,"Unknown live bytes at %s/%s HBC+%x",s->title,p->name,p->offset);
                if(!read_error)DIAG_BYTES("observed_patch",previous[i][j],p->length);
                printf("Unknown live bytes %s/%s; no writes\n",s->title,p->name); goto finish;
            }
        }
    }
    for (unsigned i=0;i<2;i++) {
        struct source *s=&sources[i];
        for (unsigned j=0;j<s->plan.count;j++) {
            struct hbc_patch *p=&s->plan.patches[j];
            const uint8_t *wanted=RESTORE?p->before:p->after;
            if (kernel_proc_copyin(pid,wanted,s->base+p->offset,p->length) ||
                kernel_proc_copyout(pid,s->base+p->offset,check,p->length) || memcmp(check,wanted,p->length)) {
                failure="patch write or verification error";
                DIAG_ERROR("transaction.write",errno,"%s/%s write/readback failed; attempting rollback",s->title,p->name);
                puts("Write/readback failure: rolling back to pre-call bytes");
                for (unsigned a=0;a<2;a++) for (unsigned b=0;b<sources[a].plan.count;b++) {
                    struct hbc_patch *q=&sources[a].plan.patches[b];
                    int ret=kernel_proc_copyin(pid,previous[a][b],sources[a].base+q->offset,q->length);
                    if (!ret) ret=kernel_proc_copyout(pid,sources[a].base+q->offset,check,q->length);
                    if (ret || memcmp(check,previous[a][b],q->length)) {
                        failure="rollback verification error";
                        DIAG_ERROR("transaction.rollback",errno,"Rollback failed: %s/%s",sources[a].title,q->name);
                        puts("Rollback verification failed");
                    }
                }
                goto finish;
            }
            printf("Verified %s +%x %-15s %u bytes\n",s->title,p->offset,p->name,p->length);
        }
    }
    result=0;
    REPORT_TIMER("patch_transaction",patch_started);
finish:
    if(attached) {
        if(trace(PT_DETACH,pid)) { DIAG_ERROR("transaction.detach",errno,"Cannot detach from ShellUI"); perror("PT_DETACH"); failure="cannot detach from ShellUI"; result=1; }
        else attached=0;
    }
    if(!result && !attached && (engine==BROWSER_JSC?jsc_commit():hybrid_commit())) {
        result=2; DIAG_ERROR("cache.save",errno,"RAM operation succeeded but INI save failed");
    }
#if TEST_HBC_EXPORT
    if(result==1 && !attached && engine==BROWSER_HERMES &&
       !strcmp(diagnostic.stage,"hermes.targets_unlocated"))hbc_candidate_export(pid);
#endif
#if FULLSCREEN_SAFE_SCAN && TEST_HERMES_EXPORT
    if(!attached && engine==BROWSER_HERMES && hybrid_safe_used) {
        START_TIMER(export_started);
        /* Optional evidence only; export failure cannot change RAM results or
         * the primary failure stage. Never contact ftpsrv while attached. */
        test_export_result=direct_hermes_export(HERMES_LIBRARY_PATH,"/data/libhermes-0.11.decrypted.sprx");
        REPORT_TIMER("hermes_export",export_started);
    }
#endif
    if(!attached) {
        if(result) {
            if(engine==BROWSER_HERMES)observe_shellui("operation_failure",pid);
            observe_related_processes(pid);
            diagnostic.result=(uint32_t)result;
            diag_text(diagnostic.summary,sizeof(diagnostic.summary),result==2?"INI save failed after successful operation":failure);
            diag_text(diagnostic.cache,sizeof(diagnostic.cache),engine==BROWSER_JSC?jsc_cache_status:hybrid_cache_status);
            if(!diagnostic.reason[0])diag_error(diagnostic.stage,0,"%s",diagnostic.summary);
            diag_print(&diagnostic);
            if(diag_publish(HYBRID_CACHE_PATH))perror("Cannot save failure diagnostics");
            else printf("Failure diagnostics saved: %s\n",HYBRID_CACHE_PATH);
        }
#if TEST_HBC_LIVE_PLAN
        else if(hybrid_live_verified) {
            diagnostic.result=0;
            diag_text(diagnostic.stage,sizeof(diagnostic.stage),"test.hermes_live_plan");
            diag_text(diagnostic.reason,sizeof(diagnostic.reason),"Live semantic plan verified; associated module text retained for review");
            diag_text(diagnostic.summary,sizeof(diagnostic.summary),"Test operation succeeded; console fullscreen behavior requires observation");
            diag_text(diagnostic.cache,sizeof(diagnostic.cache),hybrid_cache_status);
            if(diag_publish(HYBRID_CACHE_PATH)) { result=2; perror("Cannot save live-plan evidence"); }
        }
#endif
#if FULLSCREEN_SAFE_SCAN && TEST_HERMES_EXPORT
        else if(test_export_result) {
            diagnostic.result=0;
            diag_text(diagnostic.stage,sizeof(diagnostic.stage),"test.hermes_export");
            diag_text(diagnostic.reason,sizeof(diagnostic.reason),"Browser operation succeeded; optional export failed or is unverified");
            diag_text(diagnostic.summary,sizeof(diagnostic.summary),"See export events and hashes; reusable profile remains valid");
            diag_text(diagnostic.cache,sizeof(diagnostic.cache),hybrid_cache_status);
            if(diag_publish(HYBRID_CACHE_PATH)) {
                result=2; perror("Cannot save test export diagnostics");
            } else puts("Optional export diagnostics saved with the reusable INI");
        }
#endif
        else if(diag_clear(HYBRID_CACHE_PATH)) {
            result=2; DIAG_ERROR("diagnostics.clear",errno,"Operation succeeded but previous failure diagnostics could not be cleared");
            perror("Cannot clear previous failure diagnostics");
        }
    } else puts("Failure diagnostics not saved: ShellUI is still attached");
    for (unsigned i=0;i<2;i++) free(sources[i].allocation);
    REPORT_TIMER("total_payload",total_started);
    printf("Result=%d; RAM patch only; /data INI=%s\n",result,engine==BROWSER_JSC?jsc_cache_status:hybrid_cache_status);
    if(!FULLSCREEN_PASSIVE_DIAGNOSTICS)notify_result(result,RESTORE,LOCATE_ONLY,failure);
    return result;
}

