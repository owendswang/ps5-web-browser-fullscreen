/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "browser_density.h"
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <machine/reg.h>
#include <ps5/kernel.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "browser_density_profiles.h"
struct density_plan {
    uintptr_t target;
    uint8_t doubled[32], before[32];
    int state;
    const struct density_layout *layout;
};
struct density_credentials {uint64_t auth;uint8_t caps[16];int saved;};

static int read_remote(pid_t pid,uintptr_t addr,void *buffer,size_t length) {
    if(addr<0x10000 || addr>0x7fffffffffffUL || length>0x7fffffffffffUL-addr)return -1;
    while(length) {
        size_t n=0x1000-(addr&0xfff);if(n>length)n=length;
        if(kernel_proc_copyout(pid,addr,buffer,n))return -1;
        addr+=n;buffer=(uint8_t *)buffer+n;length-=n;
    }
    return 0;
}
static int plan_read(pid_t pid,unsigned density,struct density_plan *plan) {
    if(density!=1 && density!=2)return -1;
    memset(plan,0,sizeof(*plan));
    uint32_t family=kernel_get_fw_version()&0xffff0000U;
    int supported=0;
    for(size_t j=0;j<sizeof(density_firmwares)/sizeof(*density_firmwares);j++)
        if(density_firmwares[j].firmware==family) {supported=1;break;}
    if(!supported) {
        if(density==1)return 0;
        puts("[density] no verified native layout for this firmware; no density writes");return -1;
    }
    uint32_t handle=0;
    if(pid<1 || kernel_dynlib_handle(pid,"ReactNative.PUI.dll.sprx",&handle))return -1;
    uintptr_t react=kernel_dynlib_mapbase_addr(pid,handle);
    if(kernel_dynlib_handle(pid,"Sce.PlayStation.PUI.dll.sprx",&handle))return -1;
    uintptr_t pui=kernel_dynlib_mapbase_addr(pid,handle);
    /* All profile RVAs are 32-bit; reject bases whose additions could wrap. */
    const uintptr_t maximum_base=0x7fffffffffffUL-UINT32_MAX-64;
    if(react<0x10000 || react>maximum_base || pui<0x10000 || pui>maximum_base)return -1;
    static const uint8_t init[]={0x48,0x8b,0xc5,0x48,0x83,0xc0,0x90};
    unsigned matches=0;
    for(size_t j=0;j<sizeof(density_firmwares)/sizeof(*density_firmwares);j++) {
        const struct density_firmware *firmware=&density_firmwares[j];
        if(firmware->firmware!=family)continue;
        const struct density_layout *layout=&density_layouts[firmware->layout];
        uint8_t bytes[64];
        if(!layout->api_length || layout->api_length>sizeof(bytes))return -1;
        if(read_remote(pid,pui+layout->api_rva,bytes,layout->api_length) ||
           memcmp(bytes,layout->api,layout->api_length))continue;
        if(layout->init_rva && (read_remote(pid,react+layout->init_rva,bytes,sizeof(init)) || memcmp(bytes,init,sizeof(init))))continue;
        struct density_plan candidate={.target=react+layout->setter_rva,.layout=layout};
        /* The legacy device setter ignores RSI; SetScaleValue uses it for ScaleBehavior. */
        /* Keep the original pop rbp; ret at +15 so an outstanding old call can
         * finish safely. The new entry bypasses that epilogue and tail-jumps. */
        uint8_t prefix[]={0x48,0x89,0xf7,0x6a,2,0x58,0xf2,0x0f,0x2a,0xc0,
                          0x6a,layout->parameter,0x5e,0xeb,2,0x5d,0xc3,0xe9};
        if(layout->original[15]!=0x5d || layout->original[16]!=0xc3 || layout->parameter>0x7f)return -1;
        int64_t delta=(int64_t)(pui+layout->api_rva)-(int64_t)(candidate.target+22);
        if(delta<INT32_MIN || delta>INT32_MAX)continue;
        int32_t relative=(int32_t)delta;
        memset(candidate.doubled,0x90,sizeof(candidate.doubled));
        memcpy(candidate.doubled,prefix,sizeof(prefix));memcpy(candidate.doubled+18,&relative,4);
        if(read_remote(pid,candidate.target,candidate.before,sizeof(candidate.before)))continue;
        if(!memcmp(candidate.before,layout->original,32))candidate.state=1;
        else if(!memcmp(candidate.before,candidate.doubled,32))candidate.state=2;
        else {
            /* Accept the previous 2x payload, then upgrade it on the next apply. */
            uint8_t legacy[32];memset(legacy,0x90,sizeof(legacy));
            const uint8_t old_prefix[]={0x48,0x89,0xf7,0xbe,0,0,0,0,0xb8,2,0,0,0,0xf2,0x0f,0x2a,0xc0,0xe9};
            uint32_t parameter=layout->parameter;
            memcpy(legacy,old_prefix,sizeof(old_prefix));memcpy(legacy+4,&parameter,4);memcpy(legacy+18,&relative,4);
            if(memcmp(candidate.before,legacy,32))continue;
            candidate.state=2;
        }
        if(matches && (plan->target!=candidate.target || memcmp(plan->doubled,candidate.doubled,32))) {
            puts("[density] ambiguous native layout; no density writes");return -1;
        }
        *plan=candidate;matches++;
    }
    if(!matches) {puts("[density] native fingerprints do not match or high-resolution initializer modified");return -1;}
    return 0;
}
int browser_density_check(pid_t pid,unsigned density) {
    struct density_plan plan;
    int result=plan_read(pid,density,&plan);
    if(!result && plan.target)printf("[density] requested=%ux current=%ux; native fingerprints verified\n",density,plan.state);
    return result;
}
static int credentials_begin(struct density_credentials *credentials) {
    pid_t self=getpid();uint8_t elevated[16];memset(elevated,0xff,sizeof(elevated));
    credentials->auth=kernel_get_ucred_authid(self);
    if(!credentials->auth || kernel_get_ucred_caps(self,credentials->caps))return -1;
    credentials->saved=1;
    if(kernel_set_ucred_authid(self,0x4800000000010003UL) || kernel_set_ucred_caps(self,elevated))return -1;
    return 0;
}
static int credentials_restore(struct density_credentials *credentials) {
    if(!credentials->saved)return 0;
    int saved_errno=errno;
    for(unsigned attempt=0;attempt<3;attempt++) {
        int caps_error=kernel_set_ucred_caps(getpid(),credentials->caps);
        int auth_error=kernel_set_ucred_authid(getpid(),credentials->auth);
        if(!caps_error && !auth_error) {credentials->saved=0;errno=saved_errno;return 0;}
    }
    errno=saved_errno;return -1;
}
static int idle(pid_t pid,const struct density_plan *plan) {
    uintptr_t target=plan->target;
    int count=__syscall(SYS_ptrace,PT_GETNUMLWPS,pid,NULL,0),ids[512];
    if(count<=0 || count>512 || __syscall(SYS_ptrace,PT_GETLWPLIST,pid,ids,count)!=count)return -1;
    for(int j=0;j<count;j++) {
        struct reg r;
        if(__syscall(SYS_ptrace,PT_GETREGS,ids[j],&r,0) || ((uintptr_t)r.r_rip>=target && (uintptr_t)r.r_rip<target+32))return -1;
    }
    return 0;
}
static int write_checked(pid_t pid,uintptr_t target,const uint8_t *data) {
    uint8_t check[32];
    return kernel_proc_copyin(pid,data,target,32) || read_remote(pid,target,check,sizeof(check)) || memcmp(data,check,sizeof(check));
}
int browser_density_apply_stopped(pid_t pid,unsigned density) {
    struct density_plan plan;
    if(plan_read(pid,density,&plan))return -1;
    if(!plan.target)return 0;
    const uint8_t *wanted=density==2?plan.doubled:plan.layout->original;
    if(!memcmp(plan.before,wanted,32))return 0;
    struct density_credentials credentials={0};
    int result=-1;const char *error="cannot acquire ptrace credentials";
    if(credentials_begin(&credentials))goto done;
    error="scale setter is active or stopped thread positions cannot be verified";
    if(idle(pid,&plan))goto done;
    error="payload credentials could not be restored";
    if(credentials_restore(&credentials))goto done;
    struct density_plan stopped;
    error="native identity changed; no density writes";
    if(plan_read(pid,density,&stopped) || stopped.target!=plan.target || stopped.layout!=plan.layout ||
       memcmp(stopped.before,plan.before,32) || memcmp(stopped.doubled,plan.doubled,32))goto done;
    error="density write failed; previous bytes restored";
    if(write_checked(pid,plan.target,wanted)) {
        if(write_checked(pid,plan.target,plan.before))error="density write failed and rollback could not be verified";
        goto done;
    }
    result=0;
done:
    if(credentials_restore(&credentials)) {result=-1;error="payload credential restore failed";}
    if(result)printf("[density] FAILED: %s\n",error);
    else printf("[density] %ux selected; 32-byte readback verified. Close and reopen browser.\n",density);
    return result;
}
