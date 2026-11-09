/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RNPS_BUNDLE_FILE_H
#define RNPS_BUNDLE_FILE_H
#include <errno.h>
#include <stdio.h>

/* Update bundles are candidates, not proof of the live application's identity.
 * Only a missing file permits falling back to the packaged bundle. */
static FILE *rnps_open_bundle(const char *title, char *path, size_t capacity) {
    static const char *roots[]={"/mnt/rnps/apps", "/system_ex/rnps/apps"};
    for(unsigned i=0;i<2;i++) {
        int length=snprintf(path,capacity,"%s/%s/application.ps.bundle",roots[i],title);
        if(length<0 || (size_t)length>=capacity) { errno=ENAMETOOLONG; return NULL; }
        FILE *file=fopen(path,"rb");
        if(file || errno!=ENOENT || i==1)return file;
    }
    return NULL;
}
#endif
