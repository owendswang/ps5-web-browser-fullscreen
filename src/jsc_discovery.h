/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_JSC_DISCOVERY_H
#define WEB_BROWSER_JSC_DISCOVERY_H
#include <elf.h>
#include "jsc_cache.h"
#include "diagnostic_events.h"
#ifndef JSC_LIBRARY_PATH
#define JSC_LIBRARY_PATH "/system_ex/common_ex/lib/libSceJsc.sprx"
#endif
struct jsc_padding { uintptr_t start,end; unsigned flags; };
struct jsc_context {
    int pid;
    uintptr_t base,target,state[11];
    struct jsc_padding padding[16]; unsigned padding_count;
    struct jsc_reference_profile original;
};
struct jsc_snapshot {
    uint8_t code[JSC_CODE_BYTES],constants[JSC_CONSTANT_BYTES],entry[32];
    uintptr_t enabled;
    int initialized,blank;
};
static int jsc_padding_contains(const struct jsc_context *, uintptr_t, size_t, int);
static int jsc_read(int pid, uintptr_t address, void *out, size_t size) {
    uint8_t *p=out;
    while(size) {
        size_t part=0x1000-(address&0xfff); if(part>size)part=size;
        if(kernel_proc_copyout(pid,address,p,part))return -1;
        address+=part; p+=part; size-=part;
    }
    return 0;
}
/* Header/program-header reads only. A cache never bypasses segment checks. */
static int jsc_elf(struct jsc_context *c) {
    DIAG_STEP("jsc.image");
    FILE *file=fopen(JSC_LIBRARY_PATH,"rb"); if(!file) { DIAG_ERROR("jsc.image_open",errno,"Cannot open %s",JSC_LIBRARY_PATH); perror(JSC_LIBRARY_PATH); return -1; }
    Elf64_Ehdr header; Elf64_Phdr ph[64]; int result=-1,container=0;
    long elf_offset=0;
    if(fread(&header,1,sizeof(header),file)!=sizeof(header))goto done;
    uint32_t file_magic=hc_u32(header.e_ident);
    DIAG_EVENT("JSC library file magic=%08x",file_magic);
    if(file_magic==0xeef51454U || file_magic==0x1d3d154fU) {
        /* SELF header/entry layout as documented by ps5-payload-dev/ftpsrv.
         * Only the public ELF metadata is read; no segment decryption/pager patch. */
        const uint8_t *raw=(const uint8_t *)&header;
        unsigned entries=raw[24]|(unsigned)raw[25]<<8;
        if(!entries || entries>256)goto done;
        elf_offset=32+(long)entries*32; container=1;
        if(fseek(file,elf_offset,SEEK_SET) || fread(&header,1,sizeof(header),file)!=sizeof(header))goto done;
    }
    if(memcmp(header.e_ident,ELFMAG,SELFMAG) ||
       header.e_ident[EI_CLASS]!=ELFCLASS64 || header.e_ident[EI_DATA]!=ELFDATA2LSB || header.e_machine!=EM_X86_64 ||
       header.e_phentsize!=sizeof(*ph) || !header.e_phnum || header.e_phnum>64 || header.e_phoff>0x10000 ||
       fseek(file,elf_offset+(long)header.e_phoff,SEEK_SET) || fread(ph,sizeof(*ph),header.e_phnum,file)!=header.e_phnum)goto done;
    int found=0;
    uintptr_t rva=c->target-c->base;
    for(unsigned i=0;i<header.e_phnum;i++) {
        Elf64_Phdr *p=&ph[i];
        if(p->p_type!=PT_LOAD || p->p_vaddr>0x10000000 || p->p_memsz>0x10000000-p->p_vaddr ||
           p->p_filesz>p->p_memsz || p->p_offset>0x10000000)continue;
        if((p->p_flags&PF_X) && p->p_filesz>=32 && rva>=p->p_vaddr && rva-p->p_vaddr<=p->p_filesz-32) {
            if(found++)goto done;
            if(!container && (fseek(file,(long)(p->p_offset+rva-p->p_vaddr),SEEK_SET) ||
               fread(c->original.fingerprint,1,32,file)!=32))goto done;
            c->original.entry_rva=rva;
        }
        if((p->p_flags&PF_W) || !(p->p_flags&(PF_R|PF_X)) || p->p_filesz!=p->p_memsz ||
           p->p_align<0x1000 || p->p_align>0x10000 || (p->p_align&(p->p_align-1)))continue;
        uintptr_t start=(p->p_vaddr+p->p_memsz+15)&~(uintptr_t)15;
        uintptr_t end=(p->p_vaddr+p->p_memsz+p->p_align-1)&~(p->p_align-1);
        for(unsigned j=0;j<header.e_phnum;j++)if(ph[j].p_type==PT_LOAD && ph[j].p_vaddr>=start && ph[j].p_vaddr<end)end=ph[j].p_vaddr;
        if(end>start && end-start<=0x10000) {
            if(c->padding_count==16)goto done;
            c->padding[c->padding_count++]=(struct jsc_padding){start,end,p->p_flags};
            DIAG_EVENT("JSC segment tail: +%lx..+%lx flags=%u",start,end,(unsigned)p->p_flags);
        }
    }
    if(container && found==1) {
        uint8_t live[32];
        if(jsc_read(c->pid,c->target,live,32))goto done;
        if(jsc_prologue(live))memcpy(c->original.fingerprint,live,32);
        else if(live[0]==0xe9) {
            int32_t displacement; memcpy(&displacement,live+1,4);
            int64_t cave=(int64_t)rva+5+displacement;
            uint8_t trampoline[32];
            if(cave<=0 || !jsc_padding_contains(c,(uintptr_t)cave,JSC_CODE_BYTES,1) ||
               jsc_read(c->pid,c->base+(uintptr_t)cave+0x1000,trampoline,32))goto done;
            unsigned length=jsc_prologue(trampoline);
            if(!length)goto done;
            memcpy(c->original.fingerprint,live,32);
            memcpy(c->original.fingerprint,trampoline,length);
        }
    }
    c->original.entry_length=jsc_prologue(c->original.fingerprint);
    DIAG_EVENT("JSC %s entry=+%lx prologue=%u padding_regions=%u",container?"SELF":"ELF",c->original.entry_rva,c->original.entry_length,c->padding_count);
    DIAG_BYTES("jsc_original_fingerprint",c->original.fingerprint,32);
    printf("JSC image: %s metadata; base=%lx prologue=%u padding regions=%u\n",container?"SELF":"ELF",c->base,c->original.entry_length,c->padding_count);
    if(found==1 && c->original.entry_length)result=0;
done:
    if(result)DIAG_ERROR("jsc.image",0,"ELF/SELF metadata or original entry could not be validated");
    fclose(file); return result;
}
static int jsc_bind_context(int pid, struct jsc_context *c) {
    memset(c,0,sizeof(*c)); c->pid=pid;
    uint32_t handle=0;
    if(kernel_dynlib_handle(pid,"libSceJsc.sprx",&handle)) { DIAG_ERROR("jsc.module",0,"libSceJsc.sprx is not loaded"); return -1; }
    c->base=kernel_dynlib_mapbase_addr(pid,handle);
    c->target=kernel_dynlib_dlsym(pid,handle,"JSObjectCallAsFunction");
    if(!c->base || c->target<c->base || c->target-c->base>0x10000000-32) { DIAG_ERROR("jsc.exports",0,"JSObjectCallAsFunction export/base is unavailable"); return -1; }
    c->original.firmware=kernel_get_fw_version();
    const char *names[]={"JSEvaluateScript","JSStringCreateWithUTF8CString","JSStringRelease","JSContextGetGlobalObject",
                        "JSObjectMakeFunctionWithCallback","JSObjectHasProperty","JSObjectSetProperty","JSValueMakeBoolean"};
    for(unsigned i=0;i<8;i++)if(!(c->state[i+1]=kernel_dynlib_dlsym(pid,handle,names[i]))) { DIAG_ERROR("jsc.exports",0,"Missing export: %s",names[i]); printf("JSC missing export %s\n",names[i]); return -1; }
    c->state[9]=kernel_dynlib_dlsym(pid,0x2001,"sceKernelDebugOutText");
    c->state[10]=!RESTORE;
    return jsc_elf(c);
}
static int jsc_padding_contains(const struct jsc_context *c, uintptr_t rva, size_t size, int executable) {
    for(unsigned i=0;i<c->padding_count;i++) {
        const struct jsc_padding *p=&c->padding[i];
        int flags=executable?(p->flags&PF_X):((p->flags&PF_R) && !(p->flags&PF_X));
        if(flags && rva>=p->start && rva<=p->end && size<=p->end-rva)return 1;
    }
    return 0;
}
static int jsc_validate(struct jsc_context *c, const struct jsc_reference_profile *p, struct jsc_snapshot *s) {
    uint8_t code[JSC_CODE_BYTES],constants[JSC_CONSTANT_BYTES],detour[32];
    if(jsc_profile_valid(p) || p->firmware!=c->original.firmware || p->entry_rva!=c->original.entry_rva ||
       p->entry_length!=c->original.entry_length || memcmp(p->fingerprint,c->original.fingerprint,32) ||
       !jsc_padding_contains(c,p->code_rva,JSC_CODE_BYTES,1) || !jsc_padding_contains(c,p->constants_rva,JSC_CONSTANT_BYTES,0)) {
        DIAG_ERROR("jsc.candidate",0,"Candidate rejected: identity/prologue/segment bounds; entry=+%lx code=+%lx constants=+%lx",p->entry_rva,p->code_rva,p->constants_rva); return 1;
    }
    c->state[0]=c->base+p->code_rva+0x1000;
    if(jsc_build_image(p,c->base,c->state,code,constants,detour) ||
       jsc_read(c->pid,c->target,s->entry,32) || jsc_read(c->pid,c->base+p->code_rva,s->code,sizeof(s->code)) ||
       jsc_read(c->pid,c->base+p->constants_rva,s->constants,sizeof(s->constants))) { DIAG_ERROR("jsc.memory_read",errno,"Cannot construct/read JSC candidate images"); return 1; }
    unsigned n=p->entry_length;
    if(memcmp(s->entry+n,p->fingerprint+n,32-n) ||
       (memcmp(s->entry,p->fingerprint,n) && memcmp(s->entry,detour,n))) {
        DIAG_ERROR("jsc.entry",0,"Live entry bytes do not match original or generated detour at JSC+%lx",p->entry_rva);
        DIAG_BYTES("observed_jsc_entry",s->entry,32); return 1;
    }
    memcpy(&s->enabled,s->constants+JSC_ENABLE_OFFSET,8);
    memcpy(s->constants+JSC_ENABLE_OFFSET,&c->state[10],8);
    s->initialized=s->enabled<=1 && !memcmp(s->code,code,sizeof(code)) && !memcmp(s->constants,constants,sizeof(constants));
    memcpy(s->constants+JSC_ENABLE_OFFSET,&s->enabled,8);
    s->blank=jsc_zero(s->code,sizeof(s->code)) && jsc_zero(s->constants,sizeof(s->constants));
    int rejected=!s->initialized && (!s->blank || !memcmp(s->entry,detour,n));
    if(rejected)DIAG_ERROR("jsc.storage",0,"Unknown candidate storage: code=+%lx constants=+%lx blank=%d flag_valid=%d",p->code_rva,p->constants_rva,s->blank,s->enabled<=1);
    return rejected;
}
/* Recover the readable constant image from a verified generated RIP fixup. */
static int jsc_existing(struct jsc_context *c, uintptr_t code_rva, struct jsc_reference_profile *out) {
    unsigned at=jsc_hook_constant_fixups[0]; int32_t disk,live;
    if(jsc_read(c->pid,c->base+code_rva+at,&live,4)) { DIAG_ERROR("jsc.constant_fixup",errno,"Cannot read retained hook constant fixup"); return 1; }
    memcpy(&disk,jsc_hook_blob+at,4);
    int64_t constants=(int64_t)code_rva+JSC_HOOK_CONSTANTS_DELTA+(int64_t)live-disk;
    if(constants<=0 || constants>0x10000000) { DIAG_ERROR("jsc.constant_fixup",0,"Retained hook constant fixup points outside the supported image"); return 1; }
    *out=c->original; out->code_rva=code_rva; out->constants_rva=(uintptr_t)constants;
    struct jsc_snapshot snapshot;
    return jsc_validate(c,out,&snapshot) || !snapshot.initialized;
}
static uintptr_t jsc_blank_run(const uint8_t *data, size_t length, uintptr_t start, size_t required) {
    size_t run=0;
    for(size_t i=0;i<length;i++) {
        run=data[i]?0:run+1;
        if(run>=required) {
            uintptr_t address=(start+i+1-run+15)&~(uintptr_t)15;
            if(address+required<=start+i+1)return address;
        }
    }
    return 0;
}
/* Bounded ELF tail reads only; never a ShellUI heap scan. Existing verified
 * storage is preferred even after restore, to preserve callback identities. */
static int jsc_discover(struct jsc_context *c, struct jsc_reference_profile *out) {
    uint8_t entry[32];
    if(jsc_read(c->pid,c->target,entry,32)) { DIAG_ERROR("jsc.discovery",errno,"Cannot read native entry"); return 1; }
    if(memcmp(entry,c->original.fingerprint,32)) {
        if(entry[0]!=0xe9 || memcmp(entry+c->original.entry_length,c->original.fingerprint+c->original.entry_length,32-c->original.entry_length)) {
            DIAG_ERROR("jsc.discovery",0,"Entry is neither original nor a recoverable generated detour"); return 1;
        }
        int32_t displacement; memcpy(&displacement,entry+1,4);
        int64_t code=(int64_t)c->original.entry_rva+5+displacement;
        if(code<=0 || !jsc_padding_contains(c,(uintptr_t)code,JSC_CODE_BYTES,1)) { DIAG_ERROR("jsc.discovery",0,"Entry detour points outside safe executable padding"); return 1; }
        return jsc_existing(c,(uintptr_t)code,out);
    }
    unsigned matches=0; uintptr_t blank_code=0,blank_constants=0;
    for(unsigned i=0;i<c->padding_count;i++) {
        const struct jsc_padding *p=&c->padding[i]; size_t size=p->end-p->start;
        uint8_t *data=malloc(size); if(!data) { DIAG_ERROR("jsc.discovery",errno,"Cannot allocate padding read buffer"); return 1; }
        if(jsc_read(c->pid,c->base+p->start,data,size)) { DIAG_ERROR("jsc.discovery",errno,"Cannot read segment tail at JSC+%lx",p->start); free(data); return 1; }
        if(p->flags&PF_X) {
            for(size_t at=0;at+JSC_CODE_BYTES<=size;at+=16)if(!memcmp(data+at+0x1040,"JSCFS4V4",8)) {
                struct jsc_reference_profile candidate;
                if(memcmp(data+at,jsc_hook_blob,16) || jsc_existing(c,p->start+at,&candidate)) {
                    DIAG_ERROR("jsc.retained_storage",0,"Unknown retained hook image at JSC+%lx",p->start+at);
                    free(data); puts("JSC retained hook marker has an unknown image; no relocation"); return 1;
                }
                *out=candidate; matches++;
            }
            if(!blank_code)blank_code=jsc_blank_run(data,size,p->start,JSC_CODE_BYTES);
        } else if((p->flags&PF_R) && !blank_constants)blank_constants=jsc_blank_run(data,size,p->start,JSC_CONSTANT_BYTES);
        free(data);
    }
    DIAG_EVENT("JSC discovery: retained=%u blank_code=+%lx blank_constants=+%lx",matches,blank_code,blank_constants);
    if(matches) { if(matches!=1)DIAG_ERROR("jsc.discovery",0,"Ambiguous retained hook images: %u",matches); return matches==1?0:1; }
    if(!blank_code || !blank_constants) { DIAG_ERROR("jsc.padding",0,"No safe zero padding: executable=%s readable=%s",blank_code?"yes":"no",blank_constants?"yes":"no"); return 1; }
    *out=c->original; out->code_rva=blank_code; out->constants_rva=blank_constants;
    struct jsc_snapshot snapshot; return jsc_validate(c,out,&snapshot);
}
#endif
