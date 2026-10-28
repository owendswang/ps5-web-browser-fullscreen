/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Imported, verified Hermes layouts. Bounded object traversal, no memory scan. */
#ifndef FIXED_BATCH
#define FIXED_BATCH 1
#endif
#include "fixed_profile_types.h"
#include "diagnostic_events.h"

static const struct fixed_profile *fixed;
enum { FIXED_TARGET_MISSING=1 };
static uintptr_t hermes_base;
static size_t fixed_read_bytes, fixed_read_calls;
static uint64_t fixed_u64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
static int fixed_read(int pid, uintptr_t address, void *out, size_t size) {
    if (address<0x10000 || address>=0x100000000000UL || size>0x1000 ||
        address+size<address || address+size>0x100000000000UL) return -1;
    fixed_read_bytes+=size; fixed_read_calls++;
    if (kernel_proc_copyout(pid,address,out,size)) {
        printf("Fixed pointer read failed at %lx (%zu bytes)\n",address,size); return -1;
    }
    return 0;
}
static int fixed_pointer(int pid, uintptr_t address, uintptr_t *out) {
    if (address&7) return -1;
    return fixed_read(pid,address,out,sizeof(*out));
}
static int fixed_bind(int pid, struct source *sources, const struct fixed_profile *profile) {
    fixed=profile; fixed_read_bytes=fixed_read_calls=0;
    uint32_t handle=0;
    if (kernel_dynlib_handle(pid,"libhermes-0.11.sprx",&handle) ||
        !(hermes_base=kernel_dynlib_mapbase_addr(pid,handle))) { DIAG_ERROR("hermes.module",0,"Hermes module/base unavailable"); return -1; }
    uint8_t fingerprint[32];
    if (fixed_read(pid,hermes_base+fixed->fingerprint_rva,fingerprint,sizeof(fingerprint)) ||
        memcmp(fingerprint,fixed->fingerprint,sizeof(fingerprint))) {
        DIAG_ERROR("hermes.fingerprint",0,"Native fingerprint mismatch at Hermes+%lx",fixed->fingerprint_rva);
        puts("Hermes build fingerprint mismatch; no writes"); return -1;
    }
    printf("Fixed profile %s Hermes=%lx; no bundle decoding or memory scan\n",fixed->version,hermes_base);
    for (unsigned i=0;i<2;i++) {
        sources[i].data=(uint8_t *)fixed->sources[i].header;
        sources[i].length=u32(sources[i].data+32);
        sources[i].plan=fixed->sources[i].plan;
    }
    return 0;
}
static int locate_sources(int pid, struct source *sources, size_t count) {
    uintptr_t registry=0, root[3], head[2];
    if (count!=2 || fixed_pointer(pid,hermes_base+fixed->registry_rva,&registry) ||
        fixed_read(pid,registry,root,sizeof(root)) || root[2]==0 || root[2]>128 ||
        fixed_read(pid,root[1],head,sizeof(head))) return -1;
    uintptr_t node=head[0], previous=root[1];
    size_t shape[2]={0}; uint8_t near_header[2][128]; unsigned sampled[2]={0};
    size_t modules=0, cache_hits=0;
    struct { uintptr_t address; uint8_t header[128]; } cache[32];
    unsigned cache_used=0;
    for (size_t r=0;r<root[2];r++) {
        uintptr_t entry[3], runtime=0, owner_check=0, list[2];
        if (node==root[1] || fixed_read(pid,node,entry,sizeof(entry)) || entry[1]!=previous ||
            fixed_pointer(pid,entry[2],&runtime) ||
            fixed_pointer(pid,runtime+fixed->runtime_owner_offset,&owner_check) || owner_check!=entry[2] ||
            fixed_read(pid,runtime+fixed->module_list_offset,list,sizeof(list))) return -1;
        uintptr_t sentinel=runtime+fixed->module_list_offset, module=list[1], prev=sentinel;
        unsigned n=0;
        while (module!=sentinel) {
            uintptr_t next=0, module_prev=0, runtime_check=0, provider=0, vtable=0, buffer=0, object=0;
            uint8_t header[128], contents[64];
            if (++n>128 || ++modules>4096) return -1;
            if(FIXED_BATCH) {
                uint8_t m[192], p[0x808];
                size_t ms=fixed->provider_offset>fixed->module_runtime_offset?fixed->provider_offset:fixed->module_runtime_offset;
                size_t ps=fixed->buffer_data_offset>fixed->buffer_object_offset?fixed->buffer_data_offset:fixed->buffer_object_offset;
                if(ms+8>sizeof(m) || ps+8>sizeof(p) || fixed_read(pid,module,m,ms+8))return -1;
                module_prev=fixed_u64(m); next=fixed_u64(m+8);
                runtime_check=fixed_u64(m+fixed->module_runtime_offset); provider=fixed_u64(m+fixed->provider_offset);
                if(module_prev!=prev || runtime_check!=runtime || fixed_read(pid,provider,p,ps+8))return -1;
                vtable=fixed_u64(p); buffer=fixed_u64(p+fixed->buffer_data_offset); object=fixed_u64(p+fixed->buffer_object_offset);
            } else {
                uintptr_t links[2];
                if(fixed_read(pid,module,links,sizeof(links)) ||
                   fixed_pointer(pid,module+fixed->module_runtime_offset,&runtime_check) ||
                   fixed_pointer(pid,module+fixed->provider_offset,&provider) ||
                   fixed_pointer(pid,provider,&vtable) ||
                   fixed_pointer(pid,provider+fixed->buffer_data_offset,&buffer) ||
                   fixed_pointer(pid,provider+fixed->buffer_object_offset,&object))return -1;
                module_prev=links[0]; next=links[1];
            }
            if(module_prev!=prev || runtime_check!=runtime || vtable!=hermes_base+fixed->provider_vtable_rva ||
               fixed->buffer_length_offset>56 || fixed_read(pid,object,contents,sizeof(contents)))return -1;
            unsigned cached=0;
            if(FIXED_BATCH)for(unsigned c=0;c<cache_used;c++)if(cache[c].address==buffer) {
                memcpy(header,cache[c].header,sizeof(header)); cached=1; cache_hits++; break;
            }
            if(!cached && fixed_read(pid,buffer,header,sizeof(header)))return -1;
            const uint8_t magic[]={0xc6,0x1f,0xbc,3,0xc1,3,0x19,0x1f};
            uint64_t length=fixed_u64(contents+fixed->buffer_length_offset);
            unsigned links=0;
            for(unsigned c=0;c<sizeof(contents);c+=8)if(fixed_u64(contents+c)==buffer)links++;
            if(memcmp(header,magic,8) || u32(header+32)<128 || u32(header+32)>32U*1024*1024 ||
               length<u32(header+32) || length>32U*1024*1024 || !links)return -1;
            if(FIXED_BATCH && !cached && cache_used<sizeof(cache)/sizeof(cache[0])) {
                cache[cache_used].address=buffer; memcpy(cache[cache_used].header,header,sizeof(header)); cache_used++;
            }
            for (size_t s=0;s<count;s++) {
                if(!memcmp(header+8,sources[s].data+8,4) && !memcmp(header+32,sources[s].data+32,4)) {
                    shape[s]++;
                    if(!sampled[s] && memcmp(header,sources[s].data,128)) {
                        memcpy(near_header[s],header,128); sampled[s]=1;
                    }
                }
                if(memcmp(header,sources[s].data,sizeof(header)))continue;
                if (sources[s].base && sources[s].base!=buffer) {
                    puts("Multiple matching live fixed HBC images; no writes"); return -1;
                }
                if (!sources[s].base) printf("Located %s at %lx via runtime %lx\n",sources[s].title,buffer,runtime);
                sources[s].base=buffer;
            }
            prev=module; module=next;
        }
        if (list[0]!=prev) return -1;
        previous=node; node=entry[0];
    }
    if (node!=root[1] || previous!=head[1]) return -1;
    printf("Traversed %lu runtimes / %zu modules; read %zu bytes in %zu calls\n",
           (unsigned long)root[2],modules,fixed_read_bytes,fixed_read_calls);
    printf("Fixed reads: %s; reused %zu shared HBC headers in this invocation\n",FIXED_BATCH?"batched":"scalar baseline",cache_hits);
    for (size_t s=0;s<count;s++) if (!sources[s].base) {
        DIAG_EVENT("Fixed graph target %s missing: runtimes=%lu modules=%zu expected_length=%zu same_shape=%zu",sources[s].title,(unsigned long)root[2],modules,sources[s].length,shape[s]);
        if(sampled[s])DIAG_SPAN("fixed_same_shape_header",near_header[s],128);
        printf("Expected %s HBC identity is not registered; full graph checked, no foreground filter\n",sources[s].title);
        return FIXED_TARGET_MISSING;
    }
    return 0;
}

