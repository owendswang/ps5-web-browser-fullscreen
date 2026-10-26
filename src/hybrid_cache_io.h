/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_HYBRID_CACHE_IO_H
#define FULLSCREEN_HYBRID_CACHE_IO_H
#include "hybrid_cache.h"
#include "cache_file.h"
static inline int hc_load(const char *path, uint32_t firmware, struct hybrid_cache *cache) {
    uint8_t data[INI_FILE_CAPACITY]; size_t length=0;
    int result=cache_file_read(path,data,sizeof(data),&length);
    return result?result:hc_decode(data,length,firmware,cache)?HC_CONTENT_REJECTED:0;
}
static inline int hc_save(const char *path, const struct hybrid_cache *cache) {
    uint8_t data[HYBRID_CACHE_CAPACITY];
    int length=hc_encode(cache,data,sizeof(data));
    return length<0?-1:cache_file_write(path,data,(size_t)length);
}
#endif

