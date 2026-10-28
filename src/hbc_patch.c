/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "hbc_patch.h"
#include "hbc_opcodes.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#if TEST_HBC_LIVE_PLAN || HBC_ENABLE_DIAGNOSTICS
#include <stdarg.h>
#endif

struct view {
    const uint8_t *data;
    size_t len;
    uint32_t functions, strings, string_table, overflow_table, overflow_count;
    uint32_t storage, storage_size;
};
struct function { uint32_t offset, size, frame; uint8_t flags; };

static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static int range(const struct view *v, size_t offset, size_t size) {
    return offset<=v->len && size<=v->len-offset;
}
static int fail(char *error, size_t n, const char *message) {
    if (n) snprintf(error, n, "%s", message);
    return -1;
}
static int init(struct view *v, const uint8_t *data, size_t len) {
    static const uint8_t magic[]={0xc6,0x1f,0xbc,3,0xc1,3,0x19,0x1f};
    if (len<128 || len>32*1024*1024 || memcmp(data, magic, 8) || u32(data+8)!=89 ||
        u32(data+32)!=len) return -1;
    memset(v, 0, sizeof(*v));
    v->data=data; v->len=len; v->functions=u32(data+40); v->strings=u32(data+52);
    v->overflow_count=u32(data+56); v->storage_size=u32(data+60);
    if (!v->functions || v->functions>200000 || !v->strings || v->strings>1000000 ||
        u32(data+44)>1000000 || u32(data+48)>v->strings || v->overflow_count>v->strings) return -1;
    size_t at=128+(size_t)v->functions*16;
    at+=(size_t)u32(data+44)*4+(size_t)u32(data+48)*4;
    if (!range(v, at, (size_t)v->strings*4)) return -1;
    v->string_table=at; at+=(size_t)v->strings*4;
    if (!range(v, at, (size_t)v->overflow_count*8)) return -1;
    v->overflow_table=at; at+=(size_t)v->overflow_count*8;
    if (!range(v, at, v->storage_size)) return -1;
    v->storage=at;
    return 0;
}
static int function(const struct view *v, uint32_t id, struct function *f) {
    if (id>=v->functions) return -1;
    const uint8_t *p=v->data+128+(size_t)id*16;
    uint32_t first=u32(p), second=u32(p+4), third=u32(p+8);
    f->offset=first&0x1ffffff; f->size=second&0x7fff; f->frame=third>>25; f->flags=p[15];
    if (f->flags&0x20) {
        uint64_t extended=((uint64_t)(third&0x1ffffff)<<16)|f->offset;
        if (extended>SIZE_MAX || !range(v, extended, 31)) return -1;
        p=v->data+(size_t)extended;
        f->offset=u32(p); f->size=u32(p+8); f->frame=u32(p+20); f->flags=p[30];
    }
    if (!f->size || !f->frame || f->frame>65536 || !range(v, f->offset, f->size)) return -1;
    return 0;
}
static int string_equal(const struct view *v, uint32_t id, const char *text) {
    if (id>=v->strings) return 0;
    uint32_t descriptor=u32(v->data+v->string_table+(size_t)id*4);
    uint32_t offset=(descriptor>>1)&0x7fffff, length=descriptor>>24;
    unsigned utf16=descriptor&1;
    if (length==255) {
        if (offset>=v->overflow_count) return 0;
        const uint8_t *p=v->data+v->overflow_table+(size_t)offset*8;
        offset=u32(p); length=u32(p+4);
    }
    if (length!=strlen(text) || offset>v->storage_size ||
        (uint64_t)length*(utf16?2:1)>v->storage_size-offset) return 0;
    const uint8_t *p=v->data+v->storage+offset;
    for (uint32_t i=0; i<length; i++) {
        if (p[i*(utf16?2:1)]!=(uint8_t)text[i] || (utf16 && p[i*2+1])) return 0;
    }
    return 1;
}
static uint32_t string_id(const struct view *v, const char *text) {
    uint32_t result=UINT32_MAX;
    for (uint32_t i=0; i<v->strings; i++) if (string_equal(v, i, text)) {
        if (result!=UINT32_MAX) return UINT32_MAX;
        result=i;
    }
    return result;
}
static unsigned operand(const uint8_t *p, unsigned offset, unsigned width) {
    unsigned value=0;
    for (unsigned i=0; i<width && i<4; i++) value|=(unsigned)p[offset+i]<<(8*i);
    return value;
}
static uint32_t string_ref(const uint8_t *p) {
    return hbc_string_widths[*p] ? operand(p,hbc_string_offsets[*p],hbc_string_widths[*p]) : UINT32_MAX;
}
static uint32_t closure_ref(const uint8_t *p) {
    return hbc_function_widths[*p] ? operand(p,hbc_function_offsets[*p],hbc_function_widths[*p]) : UINT32_MAX;
}
static int closure_opcode(unsigned op) {
    return op==HBC_CreateClosure || op==HBC_CreateClosureLongIndex;
}
static int put_opcode(unsigned op) {
    return op==HBC_PutById || op==HBC_PutByIdLong;
}
static int get_opcode(unsigned op) {
    return op==HBC_GetById || op==HBC_GetByIdShort || op==HBC_GetByIdLong;
}
static int refs(const struct view *v, const struct function *f, const uint32_t *ids, unsigned count) {
    unsigned found=0;
    for (uint32_t at=0; at<f->size;) {
        const uint8_t *p=v->data+f->offset+at;
        unsigned n=hbc_sizes[*p];
        if (!n || n>f->size-at) return 0;
        uint32_t sid=string_ref(p);
        if (sid!=UINT32_MAX) for (unsigned i=0; i<count; i++) if (sid==ids[i]) found|=1U<<i;
        at+=n;
    }
    return found==((1U<<count)-1);
}
static uint32_t method(const struct view *v, const struct function *f, uint32_t sid) {
    const uint8_t *previous=NULL;
    uint32_t result=UINT32_MAX;
    for (uint32_t at=0; at<f->size;) {
        const uint8_t *p=v->data+f->offset+at;
        unsigned n=hbc_sizes[*p];
        if (!n || n>f->size-at) return UINT32_MAX;
        if (previous && closure_opcode(*previous) && put_opcode(*p) &&
            previous[1]==p[2] && string_ref(p)==sid) {
            if (result!=UINT32_MAX) return UINT32_MAX;
            result=closure_ref(previous);
        }
        previous=p; at+=n;
    }
    return result;
}
static int contains_closure(const struct view *v, const struct function *f, uint32_t wanted) {
    for (uint32_t at=0; at<f->size;) {
        const uint8_t *p=v->data+f->offset+at;
        unsigned n=hbc_sizes[*p];
        if (!n || n>f->size-at) return 0;
        if (closure_opcode(*p) && closure_ref(p)==wanted) return 1;
        at+=n;
    }
    return 0;
}
static int add_patch(const struct view *v, struct hbc_plan *plan, const char *name,
                     const struct function *f, uint32_t within, const uint8_t *after, size_t n) {
    if (plan->count>=HBC_PATCH_MAX || n>HBC_PATCH_BYTES || within>f->size || n>f->size-within ||
        (f->flags&8)) return -1;
    struct hbc_patch *patch=&plan->patches[plan->count++];
    patch->name=name; patch->offset=f->offset+within; patch->length=n;
    memcpy(patch->before,v->data+patch->offset,n); memcpy(patch->after,after,n);
    return 0;
}
static size_t emit_id(uint8_t *out, unsigned reg, unsigned value, uint32_t sid) {
    if (sid<=255) { out[0]=HBC_PutNewOwnByIdShort; out[1]=reg; out[2]=value; out[3]=sid; return 4; }
    if (sid<=65535) { out[0]=HBC_PutNewOwnById; out[1]=reg; out[2]=value; out[3]=sid; out[4]=sid>>8; return 5; }
    out[0]=HBC_PutNewOwnByIdLong; out[1]=reg; out[2]=value;
    for (unsigned i=0;i<4;i++) out[3+i]=sid>>(8*i);
    return 7;
}

int hbc_make_plan(const uint8_t *data, size_t len, int card_host,
                  struct hbc_plan *plan, char *error, size_t error_size) {
    struct view v;
    memset(plan,0,sizeof(*plan));
    if (init(&v,data,len)) return fail(error,error_size,"Unsupported/malformed HBC (implemented format: v89)");
    const char *dimensions[]={"height","width"};
    for (unsigned d=0; d<2; d++) {
        char marker[96], minimum[96], maximum[96];
        snprintf(marker,sizeof(marker),"AC SDK: requested AC selected %s of \"",dimensions[d]);
        snprintf(minimum,sizeof(minimum),"\", clamping to min %s of \"",dimensions[d]);
        snprintf(maximum,sizeof(maximum),"\", clamping to max %s of \"",dimensions[d]);
        uint32_t ids[]={string_id(&v,marker),string_id(&v,minimum),string_id(&v,maximum)};
        for (unsigned i=0;i<3;i++) if (ids[i]==UINT32_MAX)
            return fail(error,error_size,"Selected-size clamp string anchors missing/ambiguous");
        struct function selected={0}; unsigned matches=0;
        for (uint32_t i=0;i<v.functions;i++) {
            struct function f;
            if (!function(&v,i,&f) && refs(&v,&f,ids,3)) { selected=f; matches++; }
        }
        if (matches!=1) return fail(error,error_size,"Selected-size helper is not unique");
        const uint8_t *start=data+selected.offset;
        if (selected.size<5 || start[0]!=HBC_LoadParam || start[2]!=1 || start[1]>=selected.frame)
            return fail(error,error_size,"Selected-size helper entry ABI changed");
        uint8_t replacement[]={HBC_LoadParam,start[1],1,HBC_Ret,start[1]};
        if (add_patch(&v,plan,dimensions[d],&selected,0,replacement,sizeof(replacement)))
            return fail(error,error_size,"Unsupported selected-size function structure");
    }
    if (!card_host) return 0;
    const char *render_names[]={"WebBrowserActionCard","WebViewPS","cursorEnabled"};
    const char *ctor_names[]={"hideHeader","initialUserAgent","webviewProps"};
    uint32_t render_ids[3], ctor_ids[3];
    for (unsigned i=0;i<3;i++) {
        render_ids[i]=string_id(&v,render_names[i]); ctor_ids[i]=string_id(&v,ctor_names[i]);
        if (render_ids[i]==UINT32_MAX || ctor_ids[i]==UINT32_MAX)
            return fail(error,error_size,"Browser identity anchors missing/ambiguous");
    }
    uint32_t header_sid=string_id(&v,"renderHeader"), render_sid=string_id(&v,"render");
    uint32_t mount_sid=string_id(&v,"componentDidMount");
    if (header_sid==UINT32_MAX || render_sid==UINT32_MAX || mount_sid==UINT32_MAX)
        return fail(error,error_size,"Browser lifecycle names missing/ambiguous");
    uint32_t render_id=UINT32_MAX, ctor_id=UINT32_MAX, header_id=UINT32_MAX, mount_id=UINT32_MAX;
    unsigned render_count=0, ctor_count=0, factory_count=0;
    for (uint32_t i=0;i<v.functions;i++) {
        struct function f;
        if (function(&v,i,&f)) continue;
        if (refs(&v,&f,render_ids,3)) { render_id=i; render_count++; }
        if (refs(&v,&f,ctor_ids,3)) {
            uint32_t candidate=method(&v,&f,header_sid);
            if (candidate!=UINT32_MAX) { ctor_id=i; header_id=candidate; ctor_count++; }
        }
    }
    if (render_count!=1 || ctor_count!=1)
        return fail(error,error_size,"Browser render/constructor identity is not unique");
    for (uint32_t i=0;i<v.functions;i++) {
        struct function f;
        if (function(&v,i,&f) || !contains_closure(&v,&f,ctor_id)) continue;
        uint32_t candidate=method(&v,&f,mount_sid);
        if (candidate!=UINT32_MAX && method(&v,&f,render_sid)==render_id) {
            mount_id=candidate; factory_count++;
        }
    }
    if (factory_count!=1) return fail(error,error_size,"Browser lifecycle factory is not unique");
    struct function mount, header;
    if (function(&v,mount_id,&mount) || function(&v,header_id,&header))
        return fail(error,error_size,"Invalid browser lifecycle functions");
    const uint8_t *code=data+mount.offset;
    if (mount.size<2 || *code!=HBC_LoadThisNS || code[1]>=mount.frame || mount.frame<3)
        return fail(error,error_size,"Browser mount entry ABI changed");
    unsigned this_reg=code[1]; uint32_t prefix=2;
    const char *initializers[]={"initializeSettings","checkParentalControls","getConfig"};
    for (unsigned i=0;i<3;i++) {
        uint32_t sid=string_id(&v,initializers[i]);
        if (prefix>=mount.size || sid==UINT32_MAX) return fail(error,error_size,"Mount initializer missing");
        const uint8_t *get=code+prefix; unsigned n=hbc_sizes[*get];
        if (!get_opcode(*get) || n>mount.size-prefix || get[2]!=this_reg || string_ref(get)!=sid)
            return fail(error,error_size,"Mount initializer property access changed");
        prefix+=n;
        if (mount.size-prefix<4 || code[prefix]!=HBC_Call1 || code[prefix+2]!=get[1] || code[prefix+3]!=this_reg)
            return fail(error,error_size,"Mount initializer call changed");
        prefix+=4;
    }
    unsigned obj=this_reg==0?1:0, tmp=0;
    while (tmp==obj || tmp==this_reg) tmp++;
    if (tmp>=mount.frame) return fail(error,error_size,"Mount has insufficient scratch registers");
    uint8_t replacement[HBC_PATCH_BYTES]; size_t n=0;
    replacement[n++]=HBC_NewObject; replacement[n++]=obj;
    const char *properties[]={"width","height"}; const uint32_t values[]={1920,1080};
    for (unsigned i=0;i<2;i++) {
        uint32_t sid=string_id(&v,properties[i]);
        if (sid==UINT32_MAX) return fail(error,error_size,"Size property id missing/ambiguous");
        replacement[n++]=HBC_LoadConstInt; replacement[n++]=tmp;
        for (unsigned j=0;j<4;j++) replacement[n++]=values[i]>>(8*j);
        n+=emit_id(replacement+n,obj,tmp,sid);
    }
    uint32_t resize=string_id(&v,"resize");
    if (resize==UINT32_MAX) return fail(error,error_size,"Resize property id missing/ambiguous");
    replacement[n++]=resize<=65535?HBC_LoadConstString:HBC_LoadConstStringLongIndex;
    replacement[n++]=tmp;
    for (unsigned i=0;i<(resize<=65535?2U:4U);i++) replacement[n++]=resize>>(8*i);
    replacement[n++]=HBC_GetByVal; replacement[n++]=tmp; replacement[n++]=this_reg; replacement[n++]=tmp;
    replacement[n++]=HBC_Call2; replacement[n++]=obj; replacement[n++]=tmp; replacement[n++]=this_reg; replacement[n++]=obj;
    replacement[n++]=HBC_Ret; replacement[n++]=obj;
    if (add_patch(&v,plan,"browser_mount",&mount,prefix,replacement,n))
        return fail(error,error_size,"Mount tail has insufficient space or exception handlers");
    uint8_t null_header[]={HBC_LoadConstNull,0,HBC_Ret,0};
    if (add_patch(&v,plan,"browser_header",&header,0,null_header,sizeof(null_header)))
        return fail(error,error_size,"Unsupported browser header function structure");
    return 0;
}

#if TEST_HBC_LIVE_PLAN || HBC_ENABLE_DIAGNOSTICS
struct hbc_evidence {
    void (*emit)(void *,const char *); void *context;
    unsigned lines,omitted,functions; uint32_t seen[8];
};
static void evidence_line(struct hbc_evidence *e,const char *format,...) {
    if(e->lines>=59) { e->omitted++; return; }
    char line[192]; va_list args; va_start(args,format);
    vsnprintf(line,sizeof(line),format,args); va_end(args);
    for(char *p=line;*p;p++)if((unsigned char)*p<32 || (unsigned char)*p>126)*p='?';
    e->emit(e->context,line); e->lines++;
}
static void evidence_hex(struct hbc_evidence *e,const char *label,uint32_t offset,const uint8_t *p,size_t n) {
    char hex[129]; if(n>64)n=64;
    for(size_t i=0;i<n;i++)snprintf(hex+2*i,3,"%02x",p[i]);
    hex[2*n]=0;
    evidence_line(e,"%s HBC+%x=%s",label,offset,hex);
}
static uint32_t evidence_sid(struct hbc_evidence *e,const struct view *v,const char *name) {
    uint32_t first=UINT32_MAX,count=0;
    for(uint32_t i=0;i<v->strings;i++)if(string_equal(v,i,name)) { if(!count)first=i; count++; }
    evidence_line(e,"anchor text=%s count=%u first_sid=%u",name,count,first);
    return count==1?first:UINT32_MAX;
}
static void evidence_function(struct hbc_evidence *e,const struct view *v,uint32_t id,const char *role) {
    if(id==UINT32_MAX)return;
    for(unsigned i=0;i<e->functions;i++)if(e->seen[i]==id)return;
    if(e->functions==8) { e->omitted++; return; }
    e->seen[e->functions++]=id;
    struct function f;
    if(function(v,id,&f)) { evidence_line(e,"function role=%s id=%u invalid_descriptor",role,id); return; }
    evidence_line(e,"function role=%s id=%u offset=%x size=%u frame=%u flags=%02x",role,id,f.offset,f.size,f.frame,f.flags);
    evidence_hex(e,"descriptor",128+id*16,v->data+128+(size_t)id*16,16);
    size_t n=f.size<96?f.size:96;
    for(size_t at=0;at<n;at+=64)evidence_hex(e,"code",f.offset+(uint32_t)at,v->data+f.offset+at,n-at<64?n-at:64);
    /* Unknown/truncated opcodes are evidence even when they prevent refs(). */
    for(uint32_t at=0;at<f.size;) {
        unsigned size=hbc_sizes[v->data[f.offset+at]];
        if(!size || size>f.size-at) {
            evidence_line(e,"decode_stop function=%u relative=%x opcode=%02x",id,at,v->data[f.offset+at]);
            evidence_hex(e,"fault",f.offset+at,v->data+f.offset+at,f.size-at<32?f.size-at:32); break;
        }
        at+=size;
    }
}
static uint32_t evidence_role(struct hbc_evidence *e,const struct view *v,const char *role,const uint32_t ids[3]) {
    unsigned count=0,partial=0,invalid=0; uint32_t first=UINT32_MAX,near=UINT32_MAX,bad=UINT32_MAX;
    for(uint32_t i=0;i<v->functions;i++) {
        struct function f; if(function(v,i,&f))continue;
        unsigned mask=0,decoded=1;
        for(uint32_t at=0;at<f.size;) {
            const uint8_t *p=v->data+f.offset+at; unsigned n=hbc_sizes[*p];
            if(!n || n>f.size-at) { decoded=0; invalid++; if(bad==UINT32_MAX)bad=i; break; }
            uint32_t sid=string_ref(p);
            for(unsigned k=0;k<3;k++)if(ids[k]!=UINT32_MAX && sid==ids[k])mask|=1U<<k;
            at+=n;
        }
        if(mask==7 && decoded) { if(!count)first=i; count++; }
        else if(mask) { if(!partial)near=i; partial++; }
    }
    evidence_line(e,"role=%s full=%u partial=%u decode_invalid=%u",role,count,partial,invalid);
    evidence_function(e,v,first,role);
    if(!count)evidence_function(e,v,near,"partial-anchor-match");
    if(!count)evidence_function(e,v,bad,"invalid-opcode-sample");
    return count==1?first:UINT32_MAX;
}
void hbc_plan_failure_evidence(const uint8_t *data,size_t length,int card_host,
                               void (*emit)(void *,const char *),void *context) {
    if(!emit)return;
    struct hbc_evidence e={.emit=emit,.context=context}; struct view v;
    evidence_line(&e,"HBC recipe evidence: role=%s length=%zu max_lines=60 max_functions=8",card_host?"action-card":"control-center",length);
    if(init(&v,data,length)) {
        evidence_line(&e,"HBC table/format validation failed");
        if(data && length)evidence_hex(&e,"header",0,data,length<64?length:64);
    } else {
        evidence_line(&e,"HBC tables functions=%u strings=%u string_table=%x storage=%x bytes=%u",v.functions,v.strings,v.string_table,v.storage,v.storage_size);
        const char *dimensions[2]={"height","width"};
        for(unsigned d=0;d<2;d++) {
            char a[96],b[96],c[96];
            snprintf(a,sizeof(a),"AC SDK: requested AC selected %s of \"",dimensions[d]);
            snprintf(b,sizeof(b),"\", clamping to min %s of \"",dimensions[d]);
            snprintf(c,sizeof(c),"\", clamping to max %s of \"",dimensions[d]);
            uint32_t ids[3]={evidence_sid(&e,&v,a),evidence_sid(&e,&v,b),evidence_sid(&e,&v,c)};
            evidence_role(&e,&v,dimensions[d],ids);
        }
        if(card_host) {
            const char *names[6]={"WebBrowserActionCard","WebViewPS","cursorEnabled","hideHeader","initialUserAgent","webviewProps"};
            uint32_t ids[6]; for(unsigned i=0;i<6;i++)ids[i]=evidence_sid(&e,&v,names[i]);
            uint32_t render=evidence_role(&e,&v,"browser-render",ids),ctor=evidence_role(&e,&v,"browser-constructor",ids+3);
            uint32_t header_sid=evidence_sid(&e,&v,"renderHeader"),mount_sid=evidence_sid(&e,&v,"componentDidMount"),render_sid=evidence_sid(&e,&v,"render");
            const char *init_names[4]={"initializeSettings","checkParentalControls","getConfig","resize"};
            for(unsigned i=0;i<4;i++)evidence_sid(&e,&v,init_names[i]);
            struct function f;
            if(ctor!=UINT32_MAX && header_sid!=UINT32_MAX && !function(&v,ctor,&f))
                evidence_function(&e,&v,method(&v,&f,header_sid),"browser-header");
            unsigned factories=0; uint32_t first=UINT32_MAX,mount=UINT32_MAX;
            if(ctor!=UINT32_MAX && render!=UINT32_MAX && mount_sid!=UINT32_MAX && render_sid!=UINT32_MAX)
                for(uint32_t i=0;i<v.functions;i++)if(!function(&v,i,&f) && contains_closure(&v,&f,ctor) && method(&v,&f,render_sid)==render) {
                    uint32_t candidate=method(&v,&f,mount_sid);
                    if(candidate!=UINT32_MAX) { if(!factories) { first=i; mount=candidate; } factories++; }
                }
            evidence_line(&e,"browser_factory matches=%u first=%u mount=%u",factories,first,mount);
            evidence_function(&e,&v,mount,"browser-mount");
        }
    }
    char summary[128]; snprintf(summary,sizeof(summary),"HBC evidence end: lines=%u functions=%u omitted=%u patch_authority=no",e.lines+1,e.functions,e.omitted);
    emit(context,summary);
}
#endif

