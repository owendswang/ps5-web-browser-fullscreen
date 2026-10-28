/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FULLSCREEN_HERMES_REGISTRY_SCAN_H
#define FULLSCREEN_HERMES_REGISTRY_SCAN_H
/* Test-only native profile recovery after a verified HBC scan. The caller loads
 * public image metadata before stopping ShellUI. Loaded immutable text is then
 * inspected read-only; no file decryption or firmware-specific address is used.
 * Recovery failure must not invalidate an otherwise verified HBC patch plan. */
#include <elf.h>
#include <stdio.h>
#include "hermes_anchor.h"
#include "diagnostic_events.h"

#define HA_CODE_RANGE_COUNT 16U
#define HA_REGISTRY_CANDIDATES 16U
#define HA_RECOVERY_PAGE 4096U
struct ha_code_range { uintptr_t rva; size_t length; };
struct ha_code_ranges { struct ha_code_range ranges[HA_CODE_RANGE_COUNT]; unsigned count; };

static inline int ha_code_ranges_load(const char *path, struct ha_code_ranges *out) {
    if(!out)return HA_UNSUPPORTED;
    memset(out,0,sizeof(*out));
    if(!path)return HA_UNSUPPORTED;
    FILE *file=fopen(path,"rb");
    if(!file) { DIAG_EVENT("Hermes recovery metadata: cannot open library"); return HA_UNSUPPORTED; }
    Elf64_Ehdr header; Elf64_Phdr ph[64];
    struct ha_code_ranges ranges={0};
    long elf_offset=0,file_size=0; int container=0,result=HA_UNSUPPORTED;
    if(fseek(file,0,SEEK_END) || (file_size=ftell(file))<0 || fseek(file,0,SEEK_SET) ||
       fread(&header,1,sizeof(header),file)!=sizeof(header))goto done;
    uint32_t magic=ha_u32(header.e_ident);
    if(magic==0xeef51454U || magic==0x1d3d154fU) {
        /* The 32-byte public SELF header is followed by 32-byte entries and the
         * embedded ELF header, as in ftpsrv's public SELF container layout. */
        const uint8_t *raw=(const uint8_t *)&header;
        unsigned entries=raw[24]|(unsigned)raw[25]<<8;
        if(!entries || entries>256)goto done;
        elf_offset=32+(long)entries*32; container=1;
        if(elf_offset>file_size || sizeof(header)>(size_t)(file_size-elf_offset) ||
           fseek(file,elf_offset,SEEK_SET) || fread(&header,1,sizeof(header),file)!=sizeof(header))goto done;
    }
    if(memcmp(header.e_ident,ELFMAG,SELFMAG) || header.e_ident[EI_CLASS]!=ELFCLASS64 ||
       header.e_ident[EI_DATA]!=ELFDATA2LSB || header.e_machine!=EM_X86_64 ||
       header.e_phentsize!=sizeof(*ph) || !header.e_phnum || header.e_phnum>64 ||
       header.e_phoff<sizeof(header) || header.e_phoff>0x10000 ||
       (uint64_t)elf_offset+header.e_phoff+(uint64_t)header.e_phnum*sizeof(*ph)>(uint64_t)file_size ||
       fseek(file,elf_offset+(long)header.e_phoff,SEEK_SET) ||
       fread(ph,sizeof(*ph),header.e_phnum,file)!=header.e_phnum)goto done;
    for(unsigned i=0;i<header.e_phnum;i++) {
        const Elf64_Phdr *p=&ph[i];
        if(p->p_type!=PT_LOAD || !(p->p_flags&PF_X) || (p->p_flags&PF_W))continue;
        if(!p->p_filesz || p->p_filesz>p->p_memsz || p->p_vaddr>=HA_IMAGE_LIMIT ||
           p->p_memsz>HA_IMAGE_LIMIT-p->p_vaddr || ranges.count==HA_CODE_RANGE_COUNT)goto done;
        if(!container && (p->p_offset>(uint64_t)file_size || p->p_filesz>(uint64_t)file_size-p->p_offset))goto done;
        /* Reject overlapping load segments, including a writable alias. */
        for(unsigned j=0;j<header.e_phnum;j++)if(j!=i && ph[j].p_type==PT_LOAD && ph[j].p_memsz) {
            if(ph[j].p_vaddr>UINT64_MAX-ph[j].p_memsz)goto done;
            if(p->p_vaddr<ph[j].p_vaddr+ph[j].p_memsz && ph[j].p_vaddr<p->p_vaddr+p->p_memsz)goto done;
        }
        ranges.ranges[ranges.count++]=(struct ha_code_range){(uintptr_t)p->p_vaddr,(size_t)p->p_filesz};
    }
    if(!ranges.count)goto done;
    *out=ranges; result=HA_OK;
done:
    fclose(file);
    DIAG_EVENT("Hermes recovery metadata: format=%s ranges=%u result=%d",container?"SELF":"ELF",out->count,result);
    return result;
}

/* Larger than ha_read's getter limit, but never crosses a page or the image. */
static inline int ha_registry_text_read(struct ha_reader *r, uintptr_t address, void *out, size_t length) {
    if(!r->read || !length || length>HA_RECOVERY_PAGE-(address&(HA_RECOVERY_PAGE-1)) ||
       !ha_image(r,address,length) || address<0x10000 || address>=0x100000000000UL ||
       length>0x100000000000UL-address)return HA_UNSUPPORTED;
    r->bytes+=length; r->calls++;
    if(r->read(r->context,address,out,length)) { r->read_failures++; return HA_UNSUPPORTED; }
    return HA_OK;
}

static inline int ha_recover_registry(struct ha_reader *reader, const struct ha_code_ranges *ranges,
                                      unsigned modules, const struct ha_target *expected, size_t count,
                                      struct ha_layout *out, uintptr_t *anchor, uint8_t fingerprint[32]) {
    if(!reader || !ranges || !out || !anchor || !fingerprint || !reader->read ||
       !ha_pointer(reader->image_base) || !ranges->count || ranges->count>HA_CODE_RANGE_COUNT ||
       modules<0x40 || modules>0x10000 || (modules&7) || !expected || count!=2 ||
       !expected[0].header || !expected[1].header || !ha_pointer(expected[0].base) ||
       !ha_pointer(expected[1].base) || expected[0].base==expected[1].base ||
       !memcmp(expected[0].header,expected[1].header,128))return HA_UNSUPPORTED;
    struct candidate { uintptr_t slot,anchor; uint8_t fingerprint[32]; } candidates[HA_REGISTRY_CANDIDATES];
    unsigned candidate_count=0,valid=0,ambiguous=0;
    uint8_t code[HA_RECOVERY_PAGE+HA_CODE_BYTES-1];
    struct ha_layout winner={0}; uintptr_t first_runtime=0,first_owner=0,winning_anchor=0;
    uint8_t winning_fingerprint[32];
    reader->walk_stage="registry recovery text";
    /* Validate all metadata before reading any text, including host-supplied
     * ranges. Unreadable text or candidate overflow makes recovery incomplete. */
    for(unsigned i=0;i<ranges->count;i++) {
        const struct ha_code_range *p=&ranges->ranges[i];
        if(p->rva>=HA_IMAGE_LIMIT || !p->length || p->length>HA_IMAGE_LIMIT-p->rva ||
           reader->image_base>0x100000000000UL-HA_IMAGE_LIMIT)return HA_UNSUPPORTED;
        for(unsigned j=0;j<i;j++)if(p->rva<ranges->ranges[j].rva+ranges->ranges[j].length &&
           ranges->ranges[j].rva<p->rva+p->length)return HA_UNSUPPORTED;
    }
    for(unsigned range=0;range<ranges->count;range++) {
        const struct ha_code_range *p=&ranges->ranges[range];
        for(size_t offset=0;offset<p->length;) {
            uintptr_t address=reader->image_base+p->rva+offset;
            size_t primary=HA_RECOVERY_PAGE-(address&(HA_RECOVERY_PAGE-1));
            if(primary>p->length-offset)primary=p->length-offset;
            size_t extra=p->length-offset-primary;
            if(extra>HA_CODE_BYTES-1)extra=HA_CODE_BYTES-1;
            if(ha_registry_text_read(reader,address,code,primary) ||
               (extra && ha_registry_text_read(reader,address+primary,code+primary,extra))) {
                DIAG_EVENT("Hermes recovery: incomplete text range=%u rva=%lx",range,p->rva+offset);
                return HA_UNSUPPORTED;
            }
            for(size_t i=0;i<primary;i++) {
                size_t length=primary+extra-i;
                if(length>HA_CODE_BYTES)length=HA_CODE_BYTES;
                uintptr_t slot=0;
                if(ha_registry_at(code+i,length,address+i,reader,&slot))continue;
                unsigned j=0;
                for(;j<candidate_count;j++)if(candidates[j].slot==slot)break;
                if(j!=candidate_count)continue;
                if(candidate_count==HA_REGISTRY_CANDIDATES) {
                    DIAG_EVENT("Hermes recovery: registry candidate limit=%u exceeded",HA_REGISTRY_CANDIDATES);
                    return HA_UNSUPPORTED;
                }
                candidates[j].slot=slot; candidates[j].anchor=address+i;
                memcpy(candidates[j].fingerprint,code+i,32); candidate_count++;
            }
            offset+=primary;
        }
    }
    for(unsigned i=0;i<candidate_count;i++) {
        struct ha_reader walk={.context=reader->context,.read=reader->read,.image_base=reader->image_base};
        struct ha_layout layout={.registry_slot=candidates[i].slot,.modules=modules};
        struct ha_target targets[2]={{.header=expected[0].header},{.header=expected[1].header}};
        int result=ha_walk(&walk,&layout,targets,2);
        reader->bytes+=walk.bytes; reader->calls+=walk.calls; reader->read_failures+=walk.read_failures;
        reader->runtimes+=walk.runtimes; reader->modules+=walk.modules;
        reader->walk_stage=walk.walk_stage;
        if(result==HA_AMBIGUOUS)ambiguous=1;
        if(result || targets[0].base!=expected[0].base || targets[1].base!=expected[1].base)continue;
        winner=layout; winning_anchor=candidates[i].anchor;
        memcpy(winning_fingerprint,candidates[i].fingerprint,32);
        first_runtime=walk.first_runtime; first_owner=walk.first_owner; valid++;
    }
    DIAG_EVENT("Hermes recovery: registry candidates=%u verified=%u ambiguous_graph=%u reads=%zu",candidate_count,valid,ambiguous,reader->calls);
    if(valid>1 || ambiguous)return HA_AMBIGUOUS;
    if(valid!=1)return HA_UNSUPPORTED;
    *out=winner; *anchor=winning_anchor; memcpy(fingerprint,winning_fingerprint,32);
    reader->first_runtime=first_runtime; reader->first_owner=first_owner;
    reader->walk_stage="registry recovery complete";
    return HA_OK;
}
#endif
