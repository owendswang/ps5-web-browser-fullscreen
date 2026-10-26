/* SPDX-License-Identifier: GPL-3.0-or-later */
ENTRY(jsc_call)
SECTIONS {
    . = 0;
    .hook : {
        *(.entry)
        *(.text .text.*)
    }
    . = 0x15c500;
    jsc_constants = .;
    .constants : {
        *(.rodata .rodata.*)
        . = ALIGN(8);
        *(.state)
    }
    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
