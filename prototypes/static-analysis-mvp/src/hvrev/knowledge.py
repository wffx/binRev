# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SysReg:
    name: str
    op0: int
    op1: int
    crn: int
    crm: int
    op2: int
    subsystem: str
    description: str

    @property
    def encoding(self) -> int:
        return (
            (self.op0 << 14)
            | (self.op1 << 11)
            | (self.crn << 7)
            | (self.crm << 3)
            | self.op2
        )


SYSREGS = (
    SysReg("HCR_EL2", 3, 4, 1, 1, 0, "cpu", "Hypervisor configuration"),
    SysReg("SCTLR_EL2", 3, 4, 1, 0, 0, "boot", "EL2 system control"),
    SysReg("TCR_EL2", 3, 4, 2, 0, 2, "memory", "EL2 translation control"),
    SysReg("TTBR0_EL2", 3, 4, 2, 0, 0, "memory", "EL2 translation base"),
    SysReg("VTCR_EL2", 3, 4, 2, 1, 2, "memory", "Stage-2 translation control"),
    SysReg("VTTBR_EL2", 3, 4, 2, 1, 0, "memory", "Stage-2 translation base and VMID"),
    SysReg("VBAR_EL2", 3, 4, 12, 0, 0, "exception", "EL2 exception vectors"),
    SysReg("ESR_EL2", 3, 4, 5, 2, 0, "exception", "EL2 exception syndrome"),
    SysReg("FAR_EL2", 3, 4, 6, 0, 0, "exception", "EL2 fault address"),
    SysReg("HPFAR_EL2", 3, 4, 6, 0, 4, "memory", "Stage-2 fault IPA"),
    SysReg("ELR_EL2", 3, 4, 4, 0, 1, "context", "Exception link register"),
    SysReg("SPSR_EL2", 3, 4, 4, 0, 0, "context", "Saved program status"),
    SysReg("SP_EL1", 3, 4, 4, 1, 0, "context", "Guest stack pointer"),
    SysReg("CNTHCTL_EL2", 3, 4, 14, 1, 0, "timer", "Counter/timer trap control"),
    SysReg("CNTVOFF_EL2", 3, 4, 14, 0, 3, "timer", "Virtual counter offset"),
    SysReg("CNTV_CTL_EL0", 3, 3, 14, 3, 1, "timer", "Virtual timer control"),
    SysReg("MPIDR_EL1", 3, 0, 0, 0, 5, "cpu", "CPU affinity"),
    SysReg("TPIDR_EL2", 3, 4, 13, 0, 2, "cpu", "EL2 per-CPU pointer"),
    SysReg("ICH_HCR_EL2", 3, 4, 12, 11, 0, "interrupt", "GIC virtual interface control"),
    SysReg("ICH_VMCR_EL2", 3, 4, 12, 11, 7, "interrupt", "GIC virtual machine control"),
    SysReg("ICH_MISR_EL2", 3, 4, 12, 11, 2, "interrupt", "GIC maintenance status"),
    SysReg("ICC_SRE_EL2", 3, 4, 12, 9, 5, "interrupt", "GIC system register enable"),
    SysReg("ICC_IAR1_EL1", 3, 0, 12, 12, 0, "interrupt", "Interrupt acknowledge"),
    SysReg("ICC_EOIR1_EL1", 3, 0, 12, 12, 1, "interrupt", "Interrupt end-of-interrupt"),
)

SYSREG_BY_ENCODING = {item.encoding: item for item in SYSREGS}

SUBSYSTEM_HINTS = {
    "boot": ("SCTLR_EL2", "VBAR_EL2"),
    "cpu": ("HCR_EL2", "MPIDR_EL1", "TPIDR_EL2"),
    "memory": ("VTCR_EL2", "VTTBR_EL2", "HPFAR_EL2", "TCR_EL2", "TTBR0_EL2"),
    "context": ("ELR_EL2", "SPSR_EL2", "SP_EL1"),
    "interrupt": (
        "ICH_HCR_EL2",
        "ICH_VMCR_EL2",
        "ICH_MISR_EL2",
        "ICC_SRE_EL2",
        "ICC_IAR1_EL1",
        "ICC_EOIR1_EL1",
    ),
    "timer": ("CNTHCTL_EL2", "CNTVOFF_EL2", "CNTV_CTL_EL0"),
}
