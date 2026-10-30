/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_NOTIFICATION_H
#define WEB_BROWSER_NOTIFICATION_H
#include <stddef.h>
#include <stdio.h>

/* Notification request ABI used by ps5-web-file-manager. */
struct fullscreen_notification {
    char unused[45];
    char message[3075];
};
_Static_assert(sizeof(struct fullscreen_notification)==3120,"Notification request ABI");
int sceKernelSendNotificationRequest(int, struct fullscreen_notification *, size_t, int);

static void notify_result(int result, int restore, int inspect, const char *failure) {
    struct fullscreen_notification request={0};
    const char *operation=inspect?"Browser inspection":restore?"Browser layout restore":"Browser fullscreen";
    if(result==1)
        snprintf(request.message,sizeof(request.message),"%s failed: %s. Diagnostics, if saved: /data/web-browser-fullscreen.ini",operation,failure);
    else if(result==2)
        snprintf(request.message,sizeof(request.message),"%s succeeded; INI update failed: /data/web-browser-fullscreen.ini",operation);
    else
        snprintf(request.message,sizeof(request.message),"%s succeeded.%s",operation,inspect?"":" Reopen the browser.");
    int ret=sceKernelSendNotificationRequest(0,&request,sizeof(request),0);
    printf("Notification: %s (send=%#x)\n",request.message,ret);
}
#endif
