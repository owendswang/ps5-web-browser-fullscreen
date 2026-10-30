/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Final-detach recovery inspired by PS5 Web File Manager's embedded wrapper. */
#ifndef WEB_BROWSER_TRACE_CLEANUP_H
#define WEB_BROWSER_TRACE_CLEANUP_H
#include "diagnostic_events.h"

/* Used only at final cleanup. Never authorize a fallback or cache commit after
 * an observed exit. An unresolved detach must retain the attached flag. */
static int trace_cleanup(int pid,int *attached) {
    if(!*attached)return 0;
    for(unsigned attempt=1;attempt<=3;attempt++) {
        if(!trace(PT_DETACH,pid)) {
            *attached=0;
            if(attempt>1)DIAG_EVENT("Final detach recovered: attempt=%u pid=%d",attempt,pid);
            return 0;
        }
        int error=errno,status=0;
        pid_t child=waitpid(pid,&status,WNOHANG);
        int wait_error=child<0?errno:0;
        DIAG_EVENT("Final detach failed: attempt=%u pid=%d errno=%d child=%d status=%#x wait_errno=%d",
                   attempt,pid,error,(int)child,status,wait_error);
        (void)wait_error;
        if(child==pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            *attached=0;
            DIAG_ERROR("transaction.tracee_exited",error,"ShellUI exited during final detach: status=%#x",status);
            errno=error;
            return -1;
        }
        /* ECHILD alone does not prove the target exited or was detached. */
        if(attempt<3)usleep(10000);
        errno=error;
    }
    DIAG_ERROR("transaction.detach",errno,"Cannot detach from ShellUI after three attempts");
    return -1;
}
#endif
