/*
 * Linker script for the GoTEE Rust trusted applet.
 *
 * The Secure World memory region is configured by the GoTEE supervisor
 * via the i.MX6ULZ Central Security Unit (CSU) and TrustZone Address
 * Space Controller (TZASC). The base address and size are set at boot
 * by the GoTEE firmware and must match the device tree configuration.
 *
 * Default layout (fits any GoTEE partition >= 8 MB):
 *   TEXT+RODATA:  0x90000000  (4 MB — arkworks + BN254 pairing code)
 *   DATA+BSS:    0x90400000  (256 KB)
 *   HEAP:        0x90440000  (2 MB — for arkworks allocations)
 *   STACK:       0x90640000  (64 KB, grows downward)
 *
 * The applet binary is loaded by the GoTEE supervisor at the Secure
 * World base address. Adjust ORIGIN values to match your GoTEE
 * configuration (see GoTEE device tree / imx6ulz.go).
 */

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x90000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x90400000, LENGTH = 256K
    HEAP  (rwx) : ORIGIN = 0x90440000, LENGTH = 2M
    STACK (rw)  : ORIGIN = 0x90640000, LENGTH = 64K
}

/* Entry point — called by GoTEE after world switch */
ENTRY(_start)

SECTIONS
{
    .text : ALIGN(4)
    {
        *(.text._start)
        *(.text .text.*)
    } > FLASH

    .rodata : ALIGN(4)
    {
        *(.rodata .rodata.*)
    } > FLASH

    .data : ALIGN(4)
    {
        *(.data .data.*)
    } > RAM AT > FLASH

    .bss (NOLOAD) : ALIGN(4)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    /* Heap region — used by the global allocator */
    .heap (NOLOAD) : ALIGN(4)
    {
        __heap_start = .;
        . = . + LENGTH(HEAP);
        __heap_end = .;
    } > HEAP

    /* Stack grows downward from top of STACK region */
    .stack (NOLOAD) : ALIGN(8)
    {
        . = . + LENGTH(STACK);
        __stack_top = .;
    } > STACK
}
