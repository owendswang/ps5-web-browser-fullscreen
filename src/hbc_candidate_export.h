/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Bounded snapshots only. Candidate selection does not authorize writes.
 * Optional compression uses the SDK's unmodified zlib (zlib license). */
#ifndef HBC_CANDIDATE_EXPORT_H
#define HBC_CANDIDATE_EXPORT_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if TEST_HBC_EXPORT
#include <zlib.h>
#endif

#define HBC_DUMP_RAW_MAX (8U*1024*1024)
#define HBC_DUMP_GZIP_MAX (4U*1024*1024)
#define HBC_CANDIDATES_MAX 128
static inline uint32_t hbc_candidate_length(const uint8_t *header) {
    uint32_t length; memcpy(&length,header+32,4); return length;
}
static inline int hbc_candidate_header(const uint8_t header[128]) {
    static const uint8_t magic[8]={0xc6,0x1f,0xbc,3,0xc1,3,0x19,0x1f};
    uint32_t version,length;
    memcpy(&version,header+8,4); memcpy(&length,header+32,4);
    return !memcmp(header,magic,8) && version==89 && length>=128 && length<=HBC_DUMP_RAW_MAX;
}
/* Observe the entire bounded native walk, independently of the eight-header
 * diagnostic preview. Duplicate modules sharing a buffer are not ambiguity. */
static struct hbc_inventory {
    int pid;
    unsigned count,overflow,changed,unsupported;
    struct { uintptr_t base; uint8_t header[128]; } items[HBC_CANDIDATES_MAX];
} hbc_candidate_inventory;
static inline int hbc_inventory_equal(const struct hbc_inventory *a,const struct hbc_inventory *b) {
    if(a->pid!=b->pid || a->count!=b->count || a->overflow || b->overflow ||
       a->changed || b->changed || a->unsupported!=b->unsupported)return 0;
    for(unsigned i=0;i<a->count;i++) {
        unsigned j=0;
        while(j<b->count && a->items[i].base!=b->items[j].base)j++;
        if(j==b->count || memcmp(a->items[i].header,b->items[j].header,128))return 0;
    }
    return 1;
}
static inline void hbc_candidate_reset(int pid) {
    memset(&hbc_candidate_inventory,0,sizeof(hbc_candidate_inventory)); hbc_candidate_inventory.pid=pid;
}
static inline void hbc_candidate_note(uintptr_t base,const uint8_t header[128]) {
    for(unsigned i=0;i<hbc_candidate_inventory.count;i++)if(hbc_candidate_inventory.items[i].base==base) {
        if(memcmp(hbc_candidate_inventory.items[i].header,header,128))hbc_candidate_inventory.changed=1;
        return;
    }
    if(!hbc_candidate_header(header)) { hbc_candidate_inventory.unsupported++; return; }
    if(hbc_candidate_inventory.count==HBC_CANDIDATES_MAX) { hbc_candidate_inventory.overflow=1; return; }
    unsigned i=hbc_candidate_inventory.count++;
    hbc_candidate_inventory.items[i].base=base;
    memcpy(hbc_candidate_inventory.items[i].header,header,128);
}
static inline int hbc_dump_match(const uint8_t header[128],unsigned index) {
    return index<hbc_candidate_inventory.count && hbc_candidate_header(header) &&
        !memcmp(header,hbc_candidate_inventory.items[index].header,128);
}
struct hbc_dump_result { size_t raw_bytes,gzip_bytes,read_bytes; uint32_t raw_crc32; };
/* Caller validates PID/image and the complete non-device VM range. A second
 * bounded pass must match every byte. This function never writes a file. */
static inline const char *hbc_candidate_read(int (*read_memory)(void *,uintptr_t,void *,size_t),
        void *context,uintptr_t base,const uint8_t header[128],unsigned index,
        uint8_t **snapshot,struct hbc_dump_result *out) {
    *snapshot=NULL;
    memset(out,0,sizeof(*out));
    if(!hbc_dump_match(header,index) || base!=hbc_candidate_inventory.items[index].base || base<0x10000 ||
       base>=0x100000000000ULL || hbc_candidate_length(header)>0x100000000000ULL-base)
        return "candidate_identity";
    size_t length=hbc_candidate_length(header);
    if(length>HBC_DUMP_RAW_MAX)return "raw_size_limit";
    uint8_t *raw=malloc(length);
    const char *failure="allocation";
    if(!raw)goto done;
    uint8_t check[4096];
    for(unsigned pass=0;pass<2;pass++) {
        for(size_t at=0;at<length;) {
            size_t part=4096-((base+at)&4095);
            if(part>length-at)part=length-at;
            out->read_bytes+=part;
            if(read_memory(context,base+at,pass?check:raw+at,part)) { failure="memory_read"; goto done; }
            if(pass && memcmp(check,raw+at,part)) { failure="body_changed"; goto done; }
            at+=part;
        }
        if(memcmp(raw,header,128)) { failure="header_changed"; goto done; }
    }
    if(read_memory(context,base,check,128) || memcmp(check,header,128)) {
        failure="final_header_changed"; goto done;
    }
    out->read_bytes+=128;
    out->raw_bytes=length; *snapshot=raw; return NULL;
done:
    free(raw); return failure;
}
#if TEST_HBC_EXPORT
static inline const char *hbc_dump_capture(int (*read_memory)(void *,uintptr_t,void *,size_t),
        void *context,uintptr_t base,const uint8_t header[128],unsigned index,
        const char *path,struct hbc_dump_result *out) {
    uint8_t *raw=NULL,*packed=NULL;
    const char *failure=hbc_candidate_read(read_memory,context,base,header,index,&raw,out);
    if(failure)return failure;
    size_t length=out->raw_bytes; out->raw_bytes=0;
    packed=malloc(HBC_DUMP_GZIP_MAX);
    if(!packed) { failure="allocation"; goto done; }
    z_stream z={0};
    if(deflateInit2(&z,6,Z_DEFLATED,15+16,8,Z_DEFAULT_STRATEGY)!=Z_OK) { failure="gzip_init"; goto done; }
    z.next_in=raw; z.avail_in=(uInt)length;
    z.next_out=packed; z.avail_out=HBC_DUMP_GZIP_MAX;
    int compressed=deflate(&z,Z_FINISH);
    size_t packed_length=z.total_out;
    deflateEnd(&z);
    if(compressed!=Z_STREAM_END) { failure="gzip_size_or_compression"; goto done; }
    out->raw_crc32=(uint32_t)crc32(0,raw,(uInt)length);
    char temporary[256];
    int n=snprintf(temporary,sizeof(temporary),"%s.tmp-%d",path,(int)getpid());
    if(n<0 || (size_t)n>=sizeof(temporary)) { failure="path_length"; goto done; }
    int fd=open(temporary,O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0) { failure="file_open"; goto done; }
    failure=NULL;
    for(size_t at=0;at<packed_length;) {
        ssize_t wrote=write(fd,packed+at,packed_length-at);
        if(wrote<0 && errno==EINTR)continue;
        if(wrote<=0) { failure="file_write"; break; }
        at+=(size_t)wrote;
    }
    if(!failure && fsync(fd))failure="file_sync";
    if(close(fd) && !failure)failure="file_close";
    if(!failure && rename(temporary,path))failure="file_rename";
    if(failure)unlink(temporary);
    else { out->raw_bytes=length; out->gzip_bytes=packed_length; }
done:
    free(raw); free(packed); return failure;
}
#endif
#endif
