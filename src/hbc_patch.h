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
#endif

