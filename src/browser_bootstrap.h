/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Launch as in ps5-payload-manager-itsPLK; return home as in ps5-web-file-mgr. */
#include "diagnostic_events.h"
int sceUserServiceInitialize(const int *);
int sceUserServiceTerminate(void);
int sceUserServiceGetForegroundUser(int *);
int sceSystemServiceLaunchWebBrowser(const char *, void *);
int sceKernelLoadStartModule(const char *, size_t, const void *, uint32_t, void *, int *);

#ifndef HYBRID_BROWSER_URL
#define HYBRID_BROWSER_URL "http://127.0.0.1:8888/"
#endif
#ifndef HYBRID_OBSERVE_SHELLUI
#define HYBRID_OBSERVE_SHELLUI(phase,pid) ((void)0)
#endif
static int hybrid_bootstrap_browser(int pid) {
    (void)pid;
    HYBRID_OBSERVE_SHELLUI("before_open",pid);
    struct { uint32_t size; int32_t user_id; } param={.size=8,.user_id=-1};
    int priority=256, initialized=sceUserServiceInitialize(&priority);
    DIAG_EVENT("Browser bootstrap: UserService initialize=%#x URL=%s",initialized,HYBRID_BROWSER_URL);
    int result=-1;
    int module=sceKernelLoadStartModule("/system_ex/common_ex/lib/libSceShellUIUtil.sprx",0,NULL,0,NULL,NULL);
    DIAG_EVENT("Browser bootstrap: ShellUIUtil load=%#x",module);
    if(module<0) { printf("Browser bootstrap: ShellUIUtil load=%#x\n",module); goto done; }
    int (*initialize)(void)=(void *)kernel_dynlib_dlsym(-1,(uint32_t)module,"sceShellUIUtilInitialize");
    int (*launch_uri)(const char *, void *)=(void *)kernel_dynlib_dlsym(-1,(uint32_t)module,"sceShellUIUtilLaunchByUri");
    DIAG_EVENT("Browser bootstrap: initialize_export=%u home_export=%u",!!initialize,!!launch_uri);
    if(!initialize || !launch_uri) { puts("Browser bootstrap: missing ShellUIUtil exports"); goto done; }
    int ret=initialize();
    DIAG_EVENT("Browser bootstrap: ShellUIUtil initialize=%#x",ret);
    if(ret<0) { printf("Browser bootstrap: ShellUIUtil initialize=%#x\n",ret); goto done; }
    ret=sceUserServiceGetForegroundUser(&param.user_id);
    DIAG_EVENT("Browser bootstrap: foreground user query=%#x",ret);
    if(ret<0) { printf("Browser bootstrap: foreground user=%#x\n",ret); goto done; }
    printf("Browser bootstrap: opening %s\n",HYBRID_BROWSER_URL);
    ret=sceSystemServiceLaunchWebBrowser(HYBRID_BROWSER_URL,NULL);
    DIAG_EVENT("Browser bootstrap: launch=%#x wait_ms=2000",ret);
    if(ret) { printf("Browser bootstrap: launch=%#x\n",ret); goto done; }
    /* These waits apply only to the once-per-invocation missing-module path. */
    usleep(2000000);
    HYBRID_OBSERVE_SHELLUI("after_open",pid);
    ret=launch_uri("pshomeui:navigateToHome?bootCondition=psButton",&param);
    DIAG_EVENT("Browser bootstrap: home=%#x wait_ms=300",ret);
    printf("Browser bootstrap: return home=%#x\n",ret);
    if(ret)goto done;
    usleep(300000);
    HYBRID_OBSERVE_SHELLUI("after_home",pid);
    result=0;
done:
    if(!initialized)sceUserServiceTerminate();
    return result;
}

