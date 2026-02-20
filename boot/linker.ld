OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

KERNEL_VMA = 0xffffffff80000000;

SECTIONS {
    . = KERNEL_VMA;

    .text : ALIGN(4096) {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        *(.text .text.*)
        KEEP(*(.limine_requests_end))
    }

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096) {
        *(.data .data.*)
    }

    .bss : ALIGN(4096) {
        *(COMMON)
        *(.bss .bss.*)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
    }
}
