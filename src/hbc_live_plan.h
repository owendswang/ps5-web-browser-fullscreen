/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Test-only plans from reported live identities, never from guessed offsets. */
#include "hbc_candidate_console.h"
static int hybrid_live_verified;
static void hybrid_live_evidence(void *context,const char *line) {
    (void)context; DIAG_EVENT("%s",line);
}
static int hybrid_live_prepare(int pid,struct source *sources,int *attached) {
    if(kernel_get_fw_version()!=0x10010000 || hbc_candidate_inventory.pid!=pid ||
       !anchor_last_graph.valid)return 1;
    if(hybrid_release(pid,attached))return -1;
    if(!hbc_dump_scope(pid))return 1;
    unsigned hits[2]={hbc_candidate_inventory.items[0].matches,hbc_candidate_inventory.items[1].matches};
    if(hits[0]!=1 || hits[1]!=1) {
        DIAG_EVENT("Live HBC plan unavailable: reported identity matches=%u,%u; no guessed targets",hits[0],hits[1]);
        return 1;
    }
    struct source live[2]={{.title=sources[0].title},{.title=sources[1].title}};
    uintptr_t expected[2];
    int result=-1;
    hybrid_pending=0; hybrid_discovered_valid=0;
    DIAG_STEP("hermes.live_semantic");
    DIAG_EVENT("Test live HBC plan: two exact reported identities; semantic analysis in RAM; dump disabled=%u",!TEST_HBC_EXPORT);
    for(unsigned i=0;i<2;i++) {
        expected[i]=hbc_candidate_inventory.items[i].base;
        uint8_t header[128]; memcpy(header,hbc_candidate_inventory.items[i].header,128);
        if(!hbc_dump_scope(pid) || !hbc_dump_range(pid,expected[i],hbc_dump_specs[i].length)) {
            DIAG_ERROR("hermes.live_capture",0,"Candidate %s PID/image or mapped range changed",hbc_dump_specs[i].tag); goto done;
        }
        struct hbc_dump_result capture;
        const char *failure=hbc_candidate_read(anchor_copy,&pid,expected[i],header,i,&live[i].allocation,&capture);
        if(failure) { DIAG_ERROR("hermes.live_capture",0,"Candidate %s capture refused: %s",hbc_dump_specs[i].tag,failure); goto done; }
        live[i].data=live[i].allocation; live[i].length=capture.raw_bytes;
        char error[160];
        if(hbc_make_plan(live[i].data,live[i].length,i==0,&live[i].plan,error,sizeof(error))) {
            DIAG_ERROR("hermes.live_semantic",0,"Candidate %s recipe rejected: %s",hbc_dump_specs[i].tag,error);
            hbc_plan_failure_evidence(live[i].data,live[i].length,i==0,hybrid_live_evidence,NULL);
            goto done;
        }
        /* A lost INI must not turn already patched bytes into restore bytes. */
        for(unsigned p=0;p<live[i].plan.count;p++) {
            const struct hbc_patch *patch=&live[i].plan.patches[p];
            if(!memcmp(patch->before,patch->after,patch->length)) {
                DIAG_ERROR("hermes.live_semantic",0,"Candidate %s already modified; original bytes require a valid INI",hbc_dump_specs[i].tag);
                hbc_plan_failure_evidence(live[i].data,live[i].length,i==0,hybrid_live_evidence,NULL);
                goto done;
            }
            DIAG_EVENT("Live recipe %s %s offset=%x bytes=%u",hbc_dump_specs[i].tag,patch->name,patch->offset,patch->length);
        }
    }
    if(!hbc_dump_scope(pid)) { DIAG_ERROR("hermes.live_capture",0,"ShellUI scope changed after capture"); goto done; }
    /* Re-resolve the native graph under ptrace with the actual live identities.
     * Only this stopped walk and preflight may authorize the transaction. */
    if(locate_sources_fast(pid,live,2,attached) || !hybrid_discovered_valid ||
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
