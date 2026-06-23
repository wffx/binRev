# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

import json
from pathlib import Path

from .models import AnalysisResult

DIRECTORIES = (
    "arch/arm64/boot",
    "arch/arm64/exception",
    "arch/arm64/mmu",
    "arch/arm64/context",
    "core/cpu",
    "core/vm",
    "core/scheduler",
    "core/memory",
    "core/lifecycle",
    "security/hkip",
    "drivers/gic",
    "drivers/timer",
    "drivers/smmu",
    "platform/unknown",
    "include/hvrev",
    "recovered/asm_fallback",
    "linker",
    "tests",
    ".recovery/ida",
    ".recovery/reports",
)

MAKEFILE = """\
# Optional, unverified build scaffold.
# The constrained workflow does not assume a cross compiler and does not claim
# that recovered sources compile, link, boot, or match the original binary.
CROSS_COMPILE ?= aarch64-none-elf-
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
OBJCOPY := $(CROSS_COMPILE)objcopy
CFLAGS := -ffreestanding -fno-stack-protector -fno-builtin -mgeneral-regs-only \\
          -Wall -Wextra -Werror -O2 -Iinclude
LDFLAGS := -nostdlib -T linker/hypervisor.ld

C_SRCS := $(shell find arch core security drivers platform recovered -name '*.c')
S_SRCS := $(shell find arch recovered -name '*.S')
OBJS := $(C_SRCS:.c=.o) $(S_SRCS:.S=.o)

.PHONY: all clean
all: build/Image

build/Image: build/hypervisor.elf
\t$(OBJCOPY) -O binary $< $@

build/hypervisor.elf: $(OBJS) linker/hypervisor.ld
\t@mkdir -p build
\t$(LD) $(LDFLAGS) -o $@ $(OBJS)

clean:
\trm -rf build $(OBJS)
"""

LINKER = """\
ENTRY(_start)
SECTIONS
{
    . = HV_LOAD_ADDRESS;
    .text : ALIGN(0x1000) { KEEP(*(.text.boot)) *(.text .text.*) }
    .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
    .data : ALIGN(0x1000) { *(.data .data.*) }
    .bss (NOLOAD) : ALIGN(0x1000) {
        __bss_start = .;
        *(.bss .bss.* COMMON)
        __bss_end = .;
    }
}
"""

BOOT = """\
/* Recovered scaffold. This is not claimed to be the original entry sequence. */
.section .text.boot, "ax"
.global _start
.type _start, %function
_start:
    ldr x0, =__boot_stack_top
    mov sp, x0
    bl hv_main
1:
    wfe
    b 1b

.section .bss.stack, "aw", %nobits
.align 12
__boot_stack:
    .skip 0x4000
__boot_stack_top:
"""

HEADER = """\
#ifndef HVREV_TYPES_H
#define HVREV_TYPES_H
#include <stdint.h>
#include <stddef.h>

enum recovery_confidence {
    RECOVERY_CONFIRMED,
    RECOVERY_INFERRED_C,
    RECOVERY_ASM_FALLBACK,
    RECOVERY_STUBBED,
    RECOVERY_UNRESOLVED,
};

struct hv_vcpu_context {
    uint64_t x[31];
    uint64_t sp_el1;
    uint64_t elr_el2;
    uint64_t spsr_el2;
};

struct hv_vm {
    uint16_t vmid;
    uint16_t vcpu_count;
    uint32_t state;
    uint64_t vttbr_el2;
};

#endif
"""

MAIN_C = """\
#include "hvrev/types.h"

__attribute__((noreturn)) void hv_main(void)
{
    /*
     * Deliberately explicit stub: recovered subsystems are added only after
     * their behavior is supported by binary evidence.
     */
    for (;;) {
        __asm__ volatile("wfe");
    }
}
"""

INVARIANTS = """\
# Security invariants

- A VM mapping must never resolve to another VM's owned page.
- Guest mappings must not grant write access to Hypervisor/HKIP protected pages.
- vCPU context ownership must remain bound to exactly one VM.
- A physical interrupt may only be injected into its configured VM/vCPU.
- VM destruction must release VMID, Stage-2 mappings, IRQ routes and CPU bindings.

These are review targets. A checked box requires binary evidence and a documented
static path audit. Under the constrained workflow no executable test is assumed.
"""

RECOVERY_STATUS = """\
# Recovery status

This repository was generated from one ARM64 `Image` using static analysis.

It is **not** claimed to:

- reproduce the original source tree;
- compile or link successfully;
- boot or behave equivalently;
- identify the exact SoC or peripheral implementation;
- prove the Hypervisor secure.

`Makefile` and linker files are unverified organizational scaffolding. Every
recovered function must retain its original address, evidence, confidence and
known unknowns.
"""


def create_repository(root: Path, result: AnalysisResult) -> None:
    for directory in DIRECTORIES:
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "Makefile").write_text(MAKEFILE, encoding="utf-8")
    linker = LINKER.replace("HV_LOAD_ADDRESS", f"0x{result.base:x}")
    (root / "linker/hypervisor.ld").write_text(linker, encoding="utf-8")
    (root / "arch/arm64/boot/start.S").write_text(BOOT, encoding="utf-8")
    (root / "include/hvrev/types.h").write_text(HEADER, encoding="utf-8")
    (root / "core/lifecycle/main.c").write_text(MAIN_C, encoding="utf-8")
    (root / "tests/SECURITY_INVARIANTS.md").write_text(INVARIANTS, encoding="utf-8")
    (root / "RECOVERY_STATUS.md").write_text(RECOVERY_STATUS, encoding="utf-8")
    (root / ".recovery/function-map.json").write_text(
        json.dumps([item.to_dict() for item in result.functions], indent=2),
        encoding="utf-8",
    )
    (root / ".recovery/address-map.json").write_text(
        json.dumps(
            {
                "selected_base": result.base,
                "selected_base_hex": f"0x{result.base:x}",
                "entry": result.entry,
                "entry_hex": f"0x{result.entry:x}",
                "candidates": [item.to_dict() for item in result.base_candidates],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
