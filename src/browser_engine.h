/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_ENGINE_H
#define WEB_BROWSER_ENGINE_H
#include "diagnostic_events.h"
enum { BROWSER_HERMES=1, BROWSER_JSC=2 };
/* The firmware number never chooses the engine. When both libraries are loaded,
 * the actual RNPS bundle format resolves the ambiguity. */
static int browser_engine(int pid) {
    uint32_t handle=0;
    int hermes=!kernel_dynlib_handle(pid,"libhermes-0.11.sprx",&handle);
    int jsc=!kernel_dynlib_handle(pid,"libSceJsc.sprx",&handle);
    int engine=-1;
    if(hermes && !jsc)engine=BROWSER_HERMES;
    else if(jsc && !hermes)engine=BROWSER_JSC;
    else if(hermes && jsc) {
        struct source probe={.title="NPXS40036"};
        if(!read_bundle(&probe)) {
            if(!memcmp(probe.data,magic,8))engine=BROWSER_HERMES;
            else if(u32(probe.data)==0xfb0bd1e5)engine=BROWSER_JSC;
        }
        free(probe.allocation);
    }
    printf("Engine=%s (loaded Hermes=%d JSC=%d%s)\n",engine==BROWSER_HERMES?"Hermes":engine==BROWSER_JSC?"JSC":"unsupported",
           hermes,jsc,hermes&&jsc?"; RNPS bundle checked":"");
    DIAG_ENGINE(hermes,jsc,engine==BROWSER_HERMES?"hermes":engine==BROWSER_JSC?"jsc":"unknown");
    if(engine<0)DIAG_ERROR("engine.detect",0,"Loaded libraries and RNPS evidence did not identify a supported engine");
    return engine;
}
#endif
