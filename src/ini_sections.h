/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_INI_SECTIONS_H
#define WEB_BROWSER_INI_SECTIONS_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define INI_FILE_CAPACITY 16384U
/* Failure diagnostics are independent of the reusable profile and its CRC. */
static inline size_t ini_profile_length(const uint8_t *data, size_t length) {
    size_t at=0;
    while(at<length) {
        size_t start=at;
        while(at<length && data[at]!='\n')at++;
        size_t end=at;
        if(at<length)at++;
        while(start<end && (data[start]==' ' || data[start]=='\t' || data[start]=='\r'))start++;
        while(end>start && (data[end-1]==' ' || data[end-1]=='\t' || data[end-1]=='\r'))end--;
        if(end-start==13 && !memcmp(data+start,"[diagnostics]",13))return start;
    }
    return length;
}
#endif
