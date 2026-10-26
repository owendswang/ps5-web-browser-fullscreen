/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_HEADER_SEARCH_H
#define FULLSCREEN_HEADER_SEARCH_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* The caller carries the final 127 bytes between adjacent successful reads.
 * Return only candidates with the entire 128-byte header available. */
static inline size_t hbc_header_next(const uint8_t *data, size_t length, size_t from) {
    static const uint8_t signature[]={0xc6,0x1f,0xbc,3,0xc1,3,0x19,0x1f};
    if (length<128 || from>length-128) return SIZE_MAX;
    size_t last=length-128;
    while (from<=last) {
        const uint8_t *candidate=memchr(data+from,signature[0],last-from+1);
        if (!candidate) break;
        size_t at=(size_t)(candidate-data);
        if (!memcmp(candidate,signature,sizeof(signature))) return at;
        from=at+1;
    }
    return SIZE_MAX;
}
#endif

