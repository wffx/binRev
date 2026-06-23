# S04：ARM64 EL2 架构语义

## 核心目标

S04 把 S03 找到的匿名函数、数据和调用关系，解释成 ARM64 EL2 层面的启动、异常、
上下文和系统寄存器行为。

一句话概括：

> S04 把“无符号汇编结构”转换为“具有 ARM64 EL2 架构含义的程序模型”。

## S03 与 S04 的区别

S03 只描述程序结构：

```text
0x80100000 是函数候选
0x80100120 调用了 0x80102000
0x80300000 是函数指针表候选
```

S04 描述架构含义：

```text
0x80100000 是启动入口候选
0x80102000 写入 VBAR_EL2
0x80103000 保存 ELR_EL2 和 SPSR_EL2
0x80104000 写入 VTTBR_EL2 后执行 TLBI 和屏障
```

S04 不确认 VM create、scheduler 或 HKIP 等高级业务语义。

## 具体需要做什么

### 1. 恢复启动流程

从 Image entry 追踪：

- 栈初始化
- BSS 或内存清理
- 当前异常级检查
- primary/secondary CPU 分支
- EL2 系统寄存器初始化
- 异常向量安装
- 主控制循环或 Guest transition 候选

形成：

```text
entry
  → stack/memory setup
  → per-CPU setup
  → EL2 initialization
  → vector installation
  → main loop / guest transition candidate
```

### 2. 恢复异常模型

通过 `VBAR_EL2` 写入定位向量表，分析：

- 16 个 128-byte vector slot
- 同步异常
- IRQ、FIQ、SError
- 公共寄存器保存
- 异常分发
- handler 或终止路径
- context restore
- `ERET`

### 3. 恢复上下文布局

根据 `STP/LDP`、`MRS/MSR`、固定偏移和保存/恢复对称性推断：

- `x0-x30`
- `ELR_EL2`
- `SPSR_EL2`
- `SP_EL1`
- timer 状态
- 虚拟中断状态
- per-CPU 字段

字段初始使用：

```text
field_0x00
field_0x08
field_0x10
```

不能直接套用 Linux、KVM 或其他开源实现的结构体。

### 4. 标注系统寄存器

重点索引：

```text
HCR_EL2
SCTLR_EL2
TCR_EL2
TTBR0_EL2
VTCR_EL2
VTTBR_EL2
VBAR_EL2
ESR_EL2
FAR_EL2
HPFAR_EL2
CNTHCTL_EL2
CNTVOFF_EL2
ICH_*
ICC_*
```

每次访问记录：

- 地址
- 读或写
- 值的来源
- 调用路径
- 前后屏障
- 架构效果候选

### 5. 标注架构事件

识别：

- `HVC`
- `SMC`
- `ERET`
- `TLBI`
- `DMB/DSB/ISB`
- `WFI/WFE`

例如：

```text
MSR VTTBR_EL2
  → TLBI
  → DSB
  → ISB
  → ERET
```

S04 可以描述为“Stage-2 地址空间切换候选”，但不能直接命名为 `vm_switch()`。

## 输入

```text
S03/program-model.json
S03/functions.jsonl
S03/data-objects.jsonl
S03/call-graph.json
S03/indirect-targets.jsonl
S03/unresolved-regions.jsonl
S03/ida-stage.i64
S03 Evidence/Decision/Unknown indexes
```

## Skills

```text
recover-arm64-boot-flow -----------------+
recover-arm64-exception-model -----------+→ recover-arm64-context-layout
recover-el2-architecture-semantics ------+→ integrate-el2-architecture-model
                                            → review
                                            → human gate
                                            → reviewed IDA transaction
                                            → checkpoint
```

## 产物

```text
S04/
├── boot-model.json
├── exception-model.json
├── context-layouts.jsonl
├── sysreg-accesses.jsonl
├── architecture-events.jsonl
├── architecture-model.json
├── ida-stage.i64
└── records/
```

## 不做什么

- 不恢复 VM 配置格式。
- 不确认调度器。
- 不确认 IRQ 到 VM 的路由。
- 不恢复完整 Stage-2 内存管理业务。
- 不确认 HKIP。
- 不生成最终源码。
- 不把系统寄存器访问单独作为高级业务函数命名依据。

## 完成标准

可以进入 S05：

- 启动主路径可追踪，或缺失部分已登记 Unknown。
- 异常向量到 handler/终止路径可追踪。
- 关键 EL2 系统寄存器访问已建立索引。
- context save/restore 的主要字段偏移已恢复。
- HVC、SMC、ERET、TLBI 和屏障已标注。
- 架构行为与业务语义仍保持分离。
