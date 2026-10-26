/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Freestanding JavaScriptCore call interception, executed in ShellUI. */
#include <stddef.h>
#include <stdint.h>
#include "jsc_patch_text.h"
struct jsc_hook_state {
    uintptr_t original, evaluate, create, release, global, make_function;
    uintptr_t has_property, set_property, boolean, debug, enabled;
};
__attribute__((used,visibility("hidden"),section(".state")))
const volatile struct jsc_hook_state jsc_state={0};

static void *enabled(void *context, void *function, void *object, size_t count, void *const *arguments, void **exception) {
    (void)function; (void)object; (void)count; (void)arguments; (void)exception;
    void *(*boolean)(void *,_Bool)=(void *)jsc_state.boolean;
    return boolean(context,jsc_state.enabled!=0);
}
static int install_toggle(void *context, void *object) {
    void *(*create)(const char *)=(void *)jsc_state.create;
    void (*release)(void *)=(void *)jsc_state.release;
    void *(*make_function)(void *,void *,void *)=(void *)jsc_state.make_function;
    _Bool (*has_property)(void *,void *,void *)=(void *)jsc_state.has_property;
    void (*set_property)(void *,void *,void *,void *,unsigned,void **)=(void *)jsc_state.set_property;
    void *name=create("__webBrowserFullscreenIsEnabled"), *exception=NULL;
    if(!name)return -1;
    if(!has_property(context,object,name)) {
        void *function=make_function(context,name,(void *)enabled);
        if(!function) { release(name); return -1; }
        set_property(context,object,name,function,14,&exception);
    }
    release(name); return exception?-1:0;
}
__attribute__((used,visibility("hidden"),section(".entry")))
void *jsc_call(void *context, void *function, void *object, size_t count, void *const *arguments, void **exception) {
    void *(*original)(void *,void *,void *,size_t,void *const *,void **)=(void *)jsc_state.original;
    void *(*create)(const char *)=(void *)jsc_state.create;
    void (*release)(void *)=(void *)jsc_state.release;
    void *(*global)(void *)=(void *)jsc_state.global;
    _Bool (*has_property)(void *,void *,void *)=(void *)jsc_state.has_property;
    void *(*evaluate)(void *,void *,void *,void *,int,void **)=(void *)jsc_state.evaluate;
    void (*debug)(int,const char *)=(void *)jsc_state.debug;
    if(context) {
        void *root=global(context), *name=create("__webBrowserFullscreenInstalledV4");
        if(root && name && !has_property(context,root,name) && !install_toggle(context,root)) {
            void *script=create(jsc_patch_script), *error=NULL;
            if(script) {
                evaluate(context,script,NULL,NULL,1,&error);
                release(script);
                if(error && debug)debug(0,"[fullscreen-jsc] runtime hook script failed\n");
            }
        }
        if(name)release(name);
    }
    return original(context,function,object,count,arguments,exception);
}
