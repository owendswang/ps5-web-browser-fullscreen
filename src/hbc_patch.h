/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef HBC_PATCH_H
#define HBC_PATCH_H
#include <stddef.h>
#include <stdint.h>

#define HBC_PATCH_MAX 4
#define HBC_PATCH_BYTES 64
struct hbc_patch {
    const char *name;
    uint32_t offset;
    uint8_t length;
    uint8_t before[HBC_PATCH_BYTES], after[HBC_PATCH_BYTES];
};
struct hbc_plan {
    unsigned count;
    struct hbc_patch patches[HBC_PATCH_MAX];
};

/* Produces no mutations. Firmware numbers and precomputed offsets are absent.
 * card_host=1 requires browser-specific mount/header evidence in addition to
 * the same selected-size helper evidence used for the control-center bundle. */
int hbc_make_plan(const uint8_t *data, size_t len, int card_host,
                  struct hbc_plan *plan, char *error, size_t error_size);
/* Read-only candidate filters. Roles: 1=browser card, 2=control center,
 * 0=unrecognized, -1=malformed/ambiguous. Never authorize a patch alone. */
size_t hbc_candidate_prefix_size(const uint8_t header[128]);
int hbc_candidate_role(const uint8_t *prefix,size_t size);
#if TEST_HBC_LIVE_PLAN || HBC_ENABLE_DIAGNOSTICS
/* Failure-only, read-only description: at most 60 ASCII lines, 191 bytes each.
 * Callback receives bounded evidence, never a replacement patch plan. */
void hbc_plan_failure_evidence(const uint8_t *data,size_t length,int card_host,
                               void (*emit)(void *,const char *),void *context);
#endif
#endif

