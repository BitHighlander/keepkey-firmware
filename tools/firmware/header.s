    .syntax unified

    .section .header, "a"

    .type g_header, %object
    .size g_header, .-g_header

g_header:
    .byte 'K','P','K','Y'
    .word _codelen
    .byte 0                // sigindex1
    .byte 0                // sigindex2
    .byte 0                // sigindex3
    .byte 1                // sig_flag: Preserve
    .word 0                // meta_flags: no update after

    // Extended metadata (fw_meta_ext_t) — first 8 bytes of reserved area
    .byte 'K','K','E','X'              // ext_magic
    .byte FIRMWARE_VARIANT_ID          // variant_id (0x00=keepkey, 0x01=btconly)
    .byte MAJOR_VERSION                // ver_major
    .byte MINOR_VERSION                // ver_minor
    .byte PATCH_VERSION                // ver_patch
    . = . + 40             // rsv_remaining (rest of reserved area)

    . = . + 64             // sig1
    . = . + 64             // sig2
    . = . + 64             // sig3
