/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_HERMES_ANCHOR_H
#define FULLSCREEN_HERMES_ANCHOR_H
/* Bounded native instruction anchors and read-only object traversal.
 * No firmware table, module RVA table, heap address, or patch offset lives here.
 * Unknown compiler/object shapes return HA_UNSUPPORTED for the scan fallback.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

enum { HA_OK=0, HA_UNSUPPORTED=1, HA_MISSING=2, HA_AMBIGUOUS=-1 };
#define HA_CODE_BYTES 512U
#define HA_IMAGE_LIMIT (16UL*1024*1024)
#define HA_MODULE_BYTES 192U
struct ha_mem { unsigned length, reg, base, rip; int32_t displacement; };
struct ha_raw { unsigned object, data, size; };
struct ha_reader {
    void *context;
    int (*read)(void *, uintptr_t, void *, size_t);
    uintptr_t image_base;
    size_t bytes, calls, runtimes, modules;
    size_t read_failures;
    const char *walk_stage;
    uintptr_t first_runtime, first_owner;
    void (*observe_hbc)(void *,uintptr_t,const uint8_t *);
    void *observe_context;
    /* Optional diagnostic metadata; never consulted by target validation. */
    void (*observe_module)(void *,uintptr_t,uintptr_t,uintptr_t,uintptr_t,const uint8_t *);
    void *module_context;
};
struct ha_layout {
    uintptr_t registry_slot, vtable;
    unsigned modules, runtime, provider;
    struct ha_raw raw;
};
struct ha_target { const uint8_t *header; uintptr_t base; };
static inline uint64_t ha_u64(const void *p) { uint64_t v; memcpy(&v,p,8); return v; }
static inline uint32_t ha_u32(const void *p) { uint32_t v; memcpy(&v,p,4); return v; }
static inline int ha_pointer(uintptr_t p) {
    return p>=0x10000 && p<0x100000000000UL && !(p&7);
}
static inline int ha_image(const struct ha_reader *r, uintptr_t p, size_t n) {
    return p>=r->image_base && p-r->image_base<HA_IMAGE_LIMIT && n<=HA_IMAGE_LIMIT-(p-r->image_base);
}
static inline int ha_read(struct ha_reader *r, uintptr_t p, void *out, size_t n) {
    if (p<0x10000 || p>=0x100000000000UL || !n || n>HA_CODE_BYTES || n>0x100000000000UL-p)
        return HA_UNSUPPORTED;
    r->bytes+=n; r->calls++;
    if(r->read(r->context,p,out,n)) { r->read_failures++; return HA_UNSUPPORTED; }
    return HA_OK;
}
/* Only the complete 64-bit MOV/LEA memory forms used by these anchors.
 * This is a shape recognizer, not a general x86 decoder. SIB/address overrides
 * are intentionally unsupported; matching never executes the inspected code. */
static inline int ha_memop(const uint8_t *p, size_t n, uint8_t opcode, struct ha_mem *m) {
    if (n<3 || (p[0]&0xf8)!=0x48 || p[1]!=opcode || (p[2]>>6)==3 || (p[2]&7)==4) return 0;
    unsigned mod=p[2]>>6, rm=p[2]&7;
    *m=(struct ha_mem){.length=3,.reg=((p[2]>>3)&7)+((p[0]&4)?8:0),
                       .base=rm+((p[0]&1)?8:0)};
    if (mod==1) { if(n<4)return 0; m->length=4; m->displacement=(int8_t)p[3]; }
    else if (mod==2 || rm==5) {
        if(n<7)return 0;
        m->length=7; memcpy(&m->displacement,p+3,4); m->rip=mod==0;
    }
    return 1;
}
static inline uintptr_t ha_relative(uintptr_t instruction, unsigned length, int32_t displacement) {
    return (uintptr_t)((int64_t)instruction+length+(int64_t)displacement);
}
/* Shared by the small export window and test-only immutable-text recovery.
 * Both observed collector variants retain the same lazy guard, global slot
 * and sentinel dereference; only the temporary map-node allocation differs. */
static inline int ha_registry_at(const uint8_t *code, size_t n, uintptr_t entry,
                                 const struct ha_reader *reader, uintptr_t *slot) {
    if(n<32 || n>HA_CODE_BYTES)return HA_UNSUPPORTED;
    /* lazy guard -> test al -> conditional branch -> registry pointer */
    if (memcmp(code,"\x0f\xb6\x05",3) || code[7]!=0x84 || code[8]!=0xc0) return HA_UNSUPPORTED;
    size_t at=9;
    if (code[at]==0x74) at+=2;
    else if (at+6<=n && code[at]==0x0f && code[at+1]==0x84) at+=6;
    else return HA_UNSUPPORTED;
    struct ha_mem load;
    if (!ha_memop(code+at,n-at,0x8b,&load) || !load.rip) return HA_UNSUPPORTED;
    int32_t guard_disp; memcpy(&guard_disp,code+3,4);
    uintptr_t guard=ha_relative(entry,7,guard_disp);
    uintptr_t candidate=ha_relative(entry+at,load.length,load.displacement);
    if (guard!=candidate+8 || !ha_image(reader,candidate,16) || !ha_pointer(candidate)) return HA_UNSUPPORTED;
    size_t after=at+load.length;
    if (after+5>n || code[after]!=0xbf) return HA_UNSUPPORTED;
    unsigned allocation=ha_u32(code+after+1);
    if(allocation!=0x48 && allocation!=0x58)return HA_UNSUPPORTED;
    /* The same loaded register supplies the set's sentinel at +8. */
    unsigned uses=0;
    for (size_t j=after+5;j+6<=n;j++) {
        struct ha_mem head, first;
        if (!ha_memop(code+j,n-j,0x8b,&head) || head.rip || head.base!=load.reg || head.displacement!=8)
            continue;
        size_t next=j+head.length;
        if (ha_memop(code+next,n-next,0x8b,&first) && !first.rip &&
            first.base==head.reg && !first.displacement) uses++;
    }
    if (!uses) return HA_UNSUPPORTED;
    *slot=candidate; return HA_OK;
}
static inline int ha_registry_anchor(const uint8_t *code, size_t n, uintptr_t entry,
                                     const struct ha_reader *reader, uintptr_t *slot) {
    unsigned matches=0;
    if(n>HA_CODE_BYTES)return HA_UNSUPPORTED;
    for(size_t i=0;i+32<=n;i++)
        if(!ha_registry_at(code+i,n-i,entry+i,reader,slot))matches++;
    return matches==1?HA_OK:matches?HA_AMBIGUOUS:HA_UNSUPPORTED;
}
static inline int ha_register_cmp(const uint8_t *p, size_t n, unsigned a, unsigned b) {
    if (n<3 || (p[0]&0xf8)!=0x48 || (p[1]!=0x39 && p[1]!=0x3b) || (p[2]&0xc0)!=0xc0) return 0;
    unsigned x=((p[2]>>3)&7)+((p[0]&4)?8:0), y=(p[2]&7)+((p[0]&1)?8:0);
    return (x==a && y==b)||(x==b && y==a);
}
static inline int ha_modules_anchor(const uint8_t *code, size_t n, unsigned *offset) {
    unsigned matches=0;
    if(n>HA_CODE_BYTES)return HA_UNSUPPORTED;
    for(size_t i=0;i+14<=n;i++) {
        struct ha_mem sentinel, first;
        if(!ha_memop(code+i,n-i,0x8d,&sentinel) || sentinel.rip ||
           sentinel.displacement<0x40 || sentinel.displacement>0x10000 || (sentinel.displacement&7))continue;
        size_t at=i+sentinel.length;
        if(!ha_memop(code+at,n-at,0x8b,&first) || first.rip || first.base!=sentinel.base ||
           first.displacement!=sentinel.displacement+8 || first.reg==sentinel.reg)continue;
        at+=first.length;
        unsigned cmp=0, step=0;
        for(size_t j=at;j+5<=n && j<at+24;j++)
            if(ha_register_cmp(code+j,n-j,sentinel.reg,first.reg) &&
               ((code[j+3]>=0x70 && code[j+3]<=0x7f) ||
                (j+9<=n && code[j+3]==0x0f && (code[j+4]&0xf0)==0x80)))cmp++;
        /* A loop advances this module register through its next link. */
        for(size_t j=at;j+4<=n;j++) {
            struct ha_mem next;
            if(ha_memop(code+j,n-j,0x8b,&next) && !next.rip && next.base==first.reg &&
               next.reg==first.reg && next.displacement==8)step++;
        }
        if(!cmp || !step)continue;
        *offset=(unsigned)sentinel.displacement; matches++;
    }
    return matches==1?HA_OK:matches?HA_AMBIGUOUS:HA_UNSUPPORTED;
}
static inline int ha_raw_anchor(const uint8_t *code, size_t n, struct ha_raw *raw) {
    struct ha_mem object,data,size;
    size_t at=0;
    if(n>=4 && !memcmp(code,"\xf3\x0f\x1e\xfa",4))at=4;
    int frame=n>=at+4 && !memcmp(code+at,"\x55\x48\x89\xe5",4);
    if(frame)at+=4;
    if(!ha_memop(code+at,n-at,0x8b,&object) || object.rip || object.base!=7 || object.reg==0 || object.reg==7)
        return HA_UNSUPPORTED;
    at+=object.length;
    if(!ha_memop(code+at,n-at,0x8b,&data) || data.rip || data.base!=7 || data.reg!=0)return HA_UNSUPPORTED;
    at+=data.length;
    if(!ha_memop(code+at,n-at,0x8b,&size) || size.rip || size.base!=object.reg || size.reg!=2)return HA_UNSUPPORTED;
    at+=size.length;
    if(frame) { if(at>=n || code[at++]!=0x5d)return HA_UNSUPPORTED; }
    if(at>=n || code[at]!=0xc3 || object.displacement<8 || object.displacement>0x800 ||
       data.displacement<8 || data.displacement>0x800 || size.displacement<8 || size.displacement>0x38 ||
       ((object.displacement|data.displacement|size.displacement)&7) || object.displacement==data.displacement)
        return HA_UNSUPPORTED;
    *raw=(struct ha_raw){(unsigned)object.displacement,(unsigned)data.displacement,(unsigned)size.displacement};
    return HA_OK;
}
static inline int ha_buffer(struct ha_reader *r, uintptr_t provider, const struct ha_raw *raw,
                             uint8_t header[128], uintptr_t *buffer) {
    uintptr_t object=0; uint8_t contents[64];
    if(ha_read(r,provider+raw->data,buffer,8) || !ha_pointer(*buffer) ||
       ha_read(r,provider+raw->object,&object,8) || !ha_pointer(object) ||
       ha_read(r,object,contents,sizeof(contents)) || ha_read(r,*buffer,header,128))return HA_UNSUPPORTED;
    static const uint8_t magic[]={0xc6,0x1f,0xbc,3,0xc1,3,0x19,0x1f};
    uint64_t length=ha_u64(contents+raw->size);
    uint32_t file_length=ha_u32(header+32);
    unsigned data_links=0;
    for(unsigned i=0;i<sizeof(contents);i+=8)if(ha_u64(contents+i)==*buffer)data_links++;
    return !memcmp(header,magic,8) && file_length>=128 && file_length<=32U*1024*1024 &&
           length>=file_length && length<=32U*1024*1024 && data_links>=1?HA_OK:HA_UNSUPPORTED;
}
static inline int ha_provider_layout(struct ha_reader *r, const uint8_t module[HA_MODULE_BYTES],
                                      struct ha_layout *layout) {
    r->walk_stage="provider layout/getter";
    unsigned matches=0;
    uintptr_t previous=0;
    for(unsigned field=24;field+8<=HA_MODULE_BYTES;field+=8) {
        uintptr_t provider=ha_u64(module+field), vtable=0;
        if(provider==previous || !ha_pointer(provider) || ha_image(r,provider,8))continue;
        previous=provider;
        if(ha_read(r,provider,&vtable,8) || !ha_image(r,vtable,256) || !ha_pointer(vtable))continue;
        uint8_t table[256];
        if(ha_read(r,vtable,table,sizeof(table)))continue;
        unsigned methods=0; struct ha_raw found={0};
        for(unsigned i=0;i<sizeof(table);i+=8) {
            uintptr_t function=ha_u64(table+i); uint8_t code[32]; struct ha_raw raw;
            if(!ha_image(r,function,sizeof(code)) || ha_read(r,function,code,sizeof(code)) ||
               ha_raw_anchor(code,sizeof(code),&raw))continue;
            uintptr_t buffer=0; uint8_t header[128];
            if(ha_buffer(r,provider,&raw,header,&buffer))continue;
            if(methods && memcmp(&raw,&found,sizeof(raw)))return HA_AMBIGUOUS;
            found=raw; methods++;
        }
        if(!methods)continue;
        layout->provider=field; layout->vtable=vtable; layout->raw=found; matches++;
    }
    return matches==1?HA_OK:matches?HA_AMBIGUOUS:HA_UNSUPPORTED;
}
static inline int ha_walk(struct ha_reader *r, struct ha_layout *layout, struct ha_target *targets, size_t count) {
    uintptr_t registry=0, root[3], head[2];
    r->walk_stage="registry root";
    if(ha_read(r,layout->registry_slot,&registry,8) || !ha_pointer(registry) ||
       ha_read(r,registry,root,sizeof(root)) || !ha_pointer(root[1]) || !root[2] || root[2]>128 ||
       ha_read(r,root[1],head,sizeof(head)))return HA_UNSUPPORTED;
    uintptr_t node=head[0], prev=root[1];
    for(size_t i=0;i<root[2];i++) {
        uintptr_t entry[3], runtime=0, ends[2];
        r->walk_stage="runtime registry node";
        if(node==root[1] || !ha_pointer(node) || ha_read(r,node,entry,sizeof(entry)) || entry[1]!=prev ||
           !ha_pointer(entry[2]) || ha_read(r,entry[2],&runtime,8) || !ha_pointer(runtime) ||
           ha_read(r,runtime+layout->modules,ends,sizeof(ends)))return HA_UNSUPPORTED;
        if(!i) { r->first_runtime=runtime; r->first_owner=entry[2]; }
        uintptr_t sentinel=runtime+layout->modules, module=ends[1], previous=sentinel;
        unsigned seen=0;
        while(module!=sentinel) {
            uint8_t m[HA_MODULE_BYTES], header[128]; uintptr_t provider=0,vtable=0,buffer=0;
            r->walk_stage="module links";
            if(++seen>128 || ++r->modules>4096 || !ha_pointer(module) ||
               ha_read(r,module,m,sizeof(m)) || ha_u64(m)!=previous)return HA_UNSUPPORTED;
            if(!layout->runtime) {
                r->walk_stage="module runtime field";
                unsigned links=0;
                for(unsigned field=16;field<64;field+=8)if(ha_u64(m+field)==runtime) {layout->runtime=field;links++;}
                if(links!=1)return HA_UNSUPPORTED;
            }
            r->walk_stage="module runtime backlink";
            if(ha_u64(m+layout->runtime)!=runtime)return HA_UNSUPPORTED;
            if(!layout->vtable) { int ret=ha_provider_layout(r,m,layout); if(ret)return ret; }
            r->walk_stage="provider identity/buffer";
            provider=ha_u64(m+layout->provider);
            if(!ha_pointer(provider) || ha_read(r,provider,&vtable,8) || vtable!=layout->vtable ||
               ha_buffer(r,provider,&layout->raw,header,&buffer))return HA_UNSUPPORTED;
            if(r->observe_hbc)r->observe_hbc(r->observe_context,buffer,header);
            if(r->observe_module)r->observe_module(r->module_context,runtime,module,provider,buffer,header);
            for(size_t t=0;t<count;t++)if(!memcmp(header,targets[t].header,128)) {
                r->walk_stage="duplicate HBC identity";
                if(targets[t].base && targets[t].base!=buffer)return HA_AMBIGUOUS;
                targets[t].base=buffer;
            }
            previous=module; module=ha_u64(m+8);
        }
        r->walk_stage="module list tail";
        if(ends[0]!=previous)return HA_UNSUPPORTED;
        prev=node; node=entry[0]; r->runtimes++;
    }
    r->walk_stage="runtime registry tail";
    if(node!=root[1] || prev!=head[1])return HA_UNSUPPORTED;
    /* A completely validated graph can lack a lazily loaded browser module. */
    r->walk_stage="target HBC identity";
    for(size_t t=0;t<count;t++)if(!targets[t].base)return HA_MISSING;
    r->walk_stage="complete";
    return HA_OK;
}
/* Optional profile-export discovery. Failure does not invalidate ha_walk(). */
static inline int ha_owner_field(struct ha_reader *reader, const struct ha_layout *layout, uintptr_t *field) {
    unsigned matches=0; uint8_t block[HA_CODE_BYTES];
    for(unsigned at=0;at<0x4000;at+=sizeof(block)) {
        if(ha_read(reader,reader->first_runtime+at,block,sizeof(block)))return HA_UNSUPPORTED;
        for(unsigned i=0;i<sizeof(block);i+=8)if(ha_u64(block+i)==reader->first_owner) { *field=at+i; matches++; }
    }
    if(matches!=1)return HA_UNSUPPORTED;
    uintptr_t registry=0, root[3], node=0;
    if(ha_read(reader,layout->registry_slot,&registry,8) || ha_read(reader,registry,root,sizeof(root)) ||
       !root[2] || root[2]>128 || ha_read(reader,root[1],&node,8))return HA_UNSUPPORTED;
    for(size_t i=0;i<root[2];i++) {
        uintptr_t entry[3], runtime=0, owner=0;
        if(node==root[1] || ha_read(reader,node,entry,sizeof(entry)) ||
           ha_read(reader,entry[2],&runtime,8) || ha_read(reader,runtime+*field,&owner,8) || owner!=entry[2])return HA_UNSUPPORTED;
        node=entry[0];
    }
    return node==root[1]?HA_OK:HA_UNSUPPORTED;
}
#endif

