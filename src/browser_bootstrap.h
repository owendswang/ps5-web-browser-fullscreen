/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Launch as in ps5-payload-manager-itsPLK; return home as in ps5-web-file-mgr. */
int sceUserServiceInitialize(const int *);
int sceUserServiceTerminate(void);
int sceUserServiceGetForegroundUser(int *);
int sceSystemServiceLaunchWebBrowser(const char *, void *);
int sceKernelLoadStartModule(const char *, size_t, const void *, uint32_t, void *, int *);

#define HYBRID_BROWSER_URL "http://127.0.0.1:8888/"
static int hybrid_bootstrap_browser(void) {
    struct { uint32_t size; int32_t user_id; } param={.size=8,.user_id=-1};
    int priority=256, initialized=sceUserServiceInitialize(&priority);
    int result=-1;
    int module=sceKernelLoadStartModule("/system_ex/common_ex/lib/libSceShellUIUtil.sprx",0,NULL,0,NULL,NULL);
    if(module<0) { printf("Browser bootstrap: ShellUIUtil load=%#x\n",module); goto done; }
    int (*initialize)(void)=(void *)kernel_dynlib_dlsym(-1,(uint32_t)module,"sceShellUIUtilInitialize");
    int (*launch_uri)(const char *, void *)=(void *)kernel_dynlib_dlsym(-1,(uint32_t)module,"sceShellUIUtilLaunchByUri");
    if(!initialize || !launch_uri) { puts("Browser bootstrap: missing ShellUIUtil exports"); goto done; }
    int ret=initialize();
    if(ret<0) { printf("Browser bootstrap: ShellUIUtil initialize=%#x\n",ret); goto done; }
    ret=sceUserServiceGetForegroundUser(&param.user_id);
    if(ret<0) { printf("Browser bootstrap: foreground user=%#x\n",ret); goto done; }
    printf("Browser bootstrap: opening %s\n",HYBRID_BROWSER_URL);
    ret=sceSystemServiceLaunchWebBrowser(HYBRID_BROWSER_URL,NULL);
    if(ret) { printf("Browser bootstrap: launch=%#x\n",ret); goto done; }
    /* These waits apply only to the once-per-invocation missing-module path. */
    usleep(2000000);
    ret=launch_uri("pshomeui:navigateToHome?bootCondition=psButton",&param);
    printf("Browser bootstrap: return home=%#x\n",ret);
    if(ret)goto done;
    usleep(300000);
    result=0;
done:
    if(!initialized)sceUserServiceTerminate();
    return result;
}

