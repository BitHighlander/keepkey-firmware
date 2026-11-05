/* Freestanding research image executed by an instruction emulator, never flashed. */
ENTRY(monero_arm_start)
MEMORY
{
    FLASH (rx) : ORIGIN = 0x08060000, LENGTH = 0xA0000
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x1F800
}
SECTIONS
{
    .text : {
        *(.text.monero_arm_start)
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > FLASH
    .ARM.extab : { *(.ARM.extab*) } > FLASH
    .ARM.exidx : {
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
    } > FLASH
    .data : {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > SRAM AT > FLASH
    .bss (NOLOAD) : {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
        _end = .;
        PROVIDE(end = .);
    } > SRAM
    _stack = ORIGIN(SRAM) + LENGTH(SRAM) - 8;
    ASSERT((_stack - _ebss) >= 0x4000, "research image leaves less than 16 KiB for the stack")
}
