/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_CACHE_FILE_H
#define WEB_BROWSER_CACHE_FILE_H
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
enum { HC_FILE_MISSING=1, HC_OPEN_FAILED, HC_BAD_FILE, HC_READ_FAILED, HC_CONTENT_REJECTED };
static inline const char *hc_load_reason(int result) {
    switch(result) {
    case 0: return "accepted";
    case HC_FILE_MISSING: return "file does not exist";
    case HC_OPEN_FAILED: return "open failed";
    case HC_BAD_FILE: return "file type or size rejected";
    case HC_READ_FAILED: return "file read failed";
    default: return "content rejected: engine, schema, fields, firmware, recipe or checksum";
    }
}
static inline int cache_file_read(const char *path, uint8_t *data, size_t capacity, size_t *length) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW);
    if(fd<0)return errno==ENOENT?HC_FILE_MISSING:HC_OPEN_FAILED;
    struct stat st; size_t at=0; int result=HC_BAD_FILE;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<=0 || (uint64_t)st.st_size>=capacity)goto done;
    result=HC_READ_FAILED;
    while(at<(size_t)st.st_size) {
        ssize_t n=read(fd,data+at,(size_t)st.st_size-at);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)goto done;
        at+=(size_t)n;
    }
    *length=at; result=0;
done:
    close(fd); return result;
}
static inline int cache_file_write(const char *path, const uint8_t *data, size_t length) {
    char temporary[512];
    int name_length=snprintf(temporary,sizeof(temporary),"%s.tmp.XXXXXX",path);
    if(name_length<0 || (size_t)name_length>=sizeof(temporary))return -1;
    int fd=mkstemp(temporary);
    if(fd<0)return -1;
    size_t at=0; int result=-1;
    while(at<length) {
        ssize_t n=write(fd,data+at,length-at);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)goto done;
        at+=(size_t)n;
    }
    if(fsync(fd))goto done;
    if(close(fd)) { fd=-1; goto done; }
    fd=-1;
    if(rename(temporary,path))goto done;
    result=0;
done: {
    int saved_errno=errno;
    if(fd>=0)close(fd);
    if(result)unlink(temporary);
    errno=saved_errno;
    return result;
}
}
#endif
