/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Test-only plans from registered HBCs and unique semantic roles. */
#ifndef HBC_LIVE_PLAN_H
#define HBC_LIVE_PLAN_H
#include "hbc_candidate_console.h"
static int hybrid_live_verified;
static void hybrid_live_evidence(void *context,const char *line) {
    (void)context; DIAG_EVENT("%s",line);
}
static int hybrid_live_prepare(int pid,struct source *sources,int *attached) {
    if(hbc_candidate_inventory.pid!=pid ||
       !anchor_last_graph.valid)return 1;
    if(hybrid_release(pid,attached))return -1;
    if(!hbc_dump_scope(pid))return 1;
    hybrid_pending=0; hybrid_discovered_valid=0; hybrid_live_verified=0;
    DIAG_EVENT("Live inventory: distinct=%u unsupported=%u overflow=%u changed=%u",
        hbc_candidate_inventory.count,hbc_candidate_inventory.unsupported,
        hbc_candidate_inventory.overflow,hbc_candidate_inventory.changed);
    if(hbc_candidate_inventory.overflow || hbc_candidate_inventory.changed) {
        DIAG_ERROR("hermes.live_inventory",0,"Incomplete or changing HBC inventory; no candidate selection"); return -1;
    }
    struct hbc_inventory original_inventory=hbc_candidate_inventory;
    unsigned hits[2]={0},selected[2]={0};
    size_t read_budget=64U*1024*1024;
    for(unsigned i=0;i<hbc_candidate_inventory.count;i++) {
        const uint8_t *header=hbc_candidate_inventory.items[i].header;
        uintptr_t base=hbc_candidate_inventory.items[i].base;
        size_t prefix_size=hbc_candidate_prefix_size(header);
        if(!prefix_size)continue;
        if(prefix_size>4U*1024*1024 || prefix_size>read_budget) {
            DIAG_ERROR("hermes.live_budget",0,"Candidate string-table read budget exceeded"); return -1;
        }
        if(!hbc_dump_range(pid,base,prefix_size)) {
            DIAG_ERROR("hermes.live_capture",0,"Candidate %u readable range unavailable",i); return -1;
        }
        uint8_t *prefix=malloc(prefix_size);
        if(!prefix) { DIAG_ERROR("hermes.live_capture",errno,"Cannot allocate candidate string table"); return -1; }
        read_budget-=prefix_size;
        int read=anchor_copy(&pid,base,prefix,prefix_size);
        int role=read || memcmp(header,prefix,128)?-1:hbc_candidate_role(prefix,prefix_size);
        free(prefix);
        if(role || i<8)DIAG_EVENT("Live candidate=%u base=%lx length=%u prefix=%zu role=%d",i,base,hbc_candidate_length(header),prefix_size,role);
        if(role<0) { DIAG_ERROR("hermes.live_identity",0,"Candidate %u unreadable, changed or ambiguous",i); return -1; }
        if(role) { selected[role-1]=i; hits[role-1]++; }
    }
    DIAG_EVENT("Live role matches: browser=%u control=%u prefix_bytes=%zu",hits[0],hits[1],64U*1024*1024-read_budget);
    if(hits[0]>1 || hits[1]>1) {
        DIAG_ERROR("hermes.live_identity",0,"Multiple registered HBCs match a browser role"); return -1;
    }
    if(hits[0]!=1 || hits[1]!=1)return 1;
    struct source live[2]={{.title=sources[0].title},{.title=sources[1].title}};
    uintptr_t expected[2];
    int result=-1;
    hybrid_pending=0; hybrid_discovered_valid=0;
    DIAG_STEP("hermes.live_semantic");
    DIAG_EVENT("Test live HBC plan: unique role candidates; full semantic analysis in RAM; dump disabled=%u",!TEST_HBC_EXPORT);
    for(unsigned i=0;i<2;i++) {
        unsigned candidate=selected[i];
        expected[i]=hbc_candidate_inventory.items[candidate].base;
        uint8_t header[128]; memcpy(header,hbc_candidate_inventory.items[candidate].header,128);
        if(!hbc_dump_scope(pid) || !hbc_dump_range(pid,expected[i],hbc_candidate_length(header))) {
            DIAG_ERROR("hermes.live_capture",0,"Candidate %s PID/image or mapped range changed",live[i].title); goto done;
        }
        struct hbc_dump_result capture;
        const char *failure=hbc_candidate_read(anchor_copy,&pid,expected[i],header,candidate,&live[i].allocation,&capture);
        if(failure) { DIAG_ERROR("hermes.live_capture",0,"Candidate %s capture refused: %s",live[i].title,failure); goto done; }
        live[i].data=live[i].allocation; live[i].length=capture.raw_bytes;
        if(hbc_candidate_role(live[i].data,live[i].length)!=(int)i+1) {
            DIAG_ERROR("hermes.live_identity",0,"Candidate role changed during capture"); goto done;
        }
        char error[160];
        if(hbc_make_plan(live[i].data,live[i].length,i==0,&live[i].plan,error,sizeof(error))) {
            DIAG_ERROR("hermes.live_semantic",0,"Candidate %s recipe rejected: %s",live[i].title,error);
            hbc_plan_failure_evidence(live[i].data,live[i].length,i==0,hybrid_live_evidence,NULL);
            goto done;
        }
        /* A lost INI must not turn already patched bytes into restore bytes. */
        for(unsigned p=0;p<live[i].plan.count;p++) {
            const struct hbc_patch *patch=&live[i].plan.patches[p];
            if(!memcmp(patch->before,patch->after,patch->length)) {
                DIAG_ERROR("hermes.live_semantic",0,"Candidate %s already modified; original bytes require a valid INI",live[i].title);
                hbc_plan_failure_evidence(live[i].data,live[i].length,i==0,hybrid_live_evidence,NULL);
                goto done;
            }
            DIAG_EVENT("Live recipe %s %s offset=%x bytes=%u",live[i].title,patch->name,patch->offset,patch->length);
        }
    }
    if(!hbc_dump_scope(pid)) { DIAG_ERROR("hermes.live_capture",0,"ShellUI scope changed after capture"); goto done; }
    /* Re-resolve the native graph under ptrace with the actual live identities.
     * Only this stopped walk and preflight may authorize the transaction. */
    if(locate_sources_fast(pid,live,2,attached) || !hybrid_discovered_valid ||
       !hbc_inventory_equal(&original_inventory,&hbc_candidate_inventory) ||
       live[0].base!=expected[0] || live[1].base!=expected[1] || hybrid_preflight(pid,live)) {
        DIAG_ERROR("hermes.live_validation",0,"Live plan graph, address, native profile or patch bytes changed"); goto done;
    }
    struct fp_source exported[2];
    for(unsigned i=0;i<2;i++)exported[i]=(struct fp_source){live[i].title,live[i].data,live[i].length,&live[i].plan};
    if(hc_from_native(&hybrid_record,&hybrid_discovered_native,exported)) {
        DIAG_ERROR("hermes.live_cache",0,"Cannot encode original live bytes and native offsets"); goto done;
    }
    struct source check[2]={{.title=live[0].title},{.title=live[1].title}};
    if(fixed_bind(pid,check,&hybrid_record.profile) || locate_sources(pid,check,2) ||
       check[0].base!=live[0].base || check[1].base!=live[1].base || hybrid_preflight(pid,check)) {
        DIAG_ERROR("hermes.live_cache",0,"Live profile failed fixed-reader round trip"); goto done;
    }
    hybrid_clear_sources(sources);
    for(unsigned i=0;i<2;i++) { sources[i]=live[i]; live[i].allocation=NULL; }
    hybrid_pending=1; hybrid_cache_status="pending (live HBC semantic plan)";
    hybrid_live_verified=1;
    DIAG_STEP("hermes.live_ready");
    DIAG_EVENT("Live HBC plan verified: 6 patch sites; fixed INI scheduled after transaction; no dump");
    puts("Plan source: test live HBC semantic discovery; verified original bytes retained for restore");
    result=0;
done:
    for(unsigned i=0;i<2;i++)free(live[i].allocation);
    return result;
}
#endif
