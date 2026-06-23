# S05：运行时基础对象模型

## 核心目标

S05 在 S04 架构行为之上恢复 Hypervisor 最基础的运行时对象：

- 物理 CPU
- per-CPU 数据
- vCPU
- VM 引用
- Guest context
- VMID
- Stage-2 根页表
- 页面所有权与共享状态

一句话概括：

> S05 回答 CPU、vCPU、VM、Stage-2 地址空间和页面分别是什么、如何引用、资源归谁。

## S04 与 S05 的区别

S04 观察到：

```text
读取 MPIDR_EL1
通过 TPIDR_EL2 获取指针
写入 VTTBR_EL2
保存 ELR_EL2/SPSR_EL2
```

S05 将它们组织为对象关系：

```text
TPIDR_EL2 → current physical CPU
CPU.current_vcpu → current vCPU
vCPU.owner_vm → owning VM
vCPU.context → Guest register context
VM.stage2_root → Stage-2 root table
VM.vmid → VMID used by VTTBR_EL2
page.owner_vm → page ownership
```

## 具体需要做什么

### 1. 恢复物理 CPU/per-CPU 对象

依据：

- `MPIDR_EL1`
- `TPIDR_EL2`
- CPU affinity 提取
- CPU index 计算
- 固定 stride 的 per-CPU 访问
- secondary CPU 初始化
- CPU online/state mask

### 2. 恢复 vCPU 对象

依据：

- Guest 通用寄存器保存/恢复
- `ELR_EL2`、`SPSR_EL2`、`SP_EL1`
- timer 和虚拟中断状态
- 调度相关重复引用
- VM 或 Stage-2 地址空间关联

候选关系：

```text
vCPU
├── context
├── execution state candidate
├── affinity/cpu binding candidate
├── owning VM candidate
└── timer/interrupt state candidate
```

### 3. 区分物理 CPU 与 vCPU

- CPU 是物理执行资源。
- vCPU 是 VM 的虚拟执行对象。
- 一个 CPU 可以在不同时间运行不同 vCPU。
- 一个 vCPU 应当关联一个 VM。
- Guest context 通常属于 vCPU，而不是物理 CPU。

S05 必须避免把 per-CPU 数据和 vCPU context 合并为同一结构。

### 4. 恢复 Stage-2 地址空间

依据：

- `VTCR_EL2`
- `VTTBR_EL2`
- VMID
- descriptor 位操作
- 多级 table walk
- map/unmap/protect
- `TLBI`
- `DSB/ISB`
- `HPFAR_EL2` fault IPA

候选模型：

```text
VM
├── VMID
├── Stage-2 root
├── IPA range candidate
├── owned pages
└── shared pages
```

### 5. 恢复内存操作

候选操作：

```text
candidate_stage2_walk
candidate_stage2_map
candidate_stage2_unmap
candidate_stage2_protect
candidate_stage2_fault
candidate_stage2_tlb_flush
```

候选名称必须同时由 descriptor、页表层级、寄存器、TLBI/屏障和调用关系支持。

### 6. 建立所有权关系

重点关系：

```text
CPU.current_vcpu
vCPU.owner_vm
VM.vcpu_list
VM.stage2_root
VM.vmid
page.owner_vm
page.shared_state
```

无法确认时必须写入 Unknown，不得用“常见 Hypervisor 设计”补齐。

## 输入

```text
S03/program-model.json
S03/functions.jsonl
S03/data-objects.jsonl
S03/indirect-targets.jsonl
S04/architecture-model.json
S04/context-layouts.jsonl
S04/sysreg-accesses.jsonl
S04/architecture-events.jsonl
S04/ida-stage.i64
S03/S04 Evidence/Decision/Unknown indexes
```

## Skills

```text
recover-hypervisor-cpu-vcpu-model ---------+
recover-hypervisor-stage2-memory-model ----+→ integrate-hypervisor-runtime-model
                                             → review
                                             → human ownership/type gate
                                             → reviewed IDA transaction
                                             → checkpoint
```

## 产物

```text
S05/
├── cpu-vcpu-model.json
├── stage2-memory-model.json
├── runtime-object-model.json
├── types.jsonl
├── resource-ownership.jsonl
├── ida-stage.i64
└── records/
```

## 不做什么

- 不恢复 VM 配置格式。
- 不恢复 runqueue 和调度策略。
- 不恢复 IRQ route。
- 不建立完整 VM 生命周期。
- 不确认 HKIP。
- 不判断安全漏洞。
- 不生成最终源码。

## 完成标准

可以进入 S06：

- CPU 和 vCPU 没有被混为同一对象。
- vCPU context 的主要关联可以描述或明确为 Unknown。
- Stage-2 root 和 VMID 有架构证据支持的候选。
- map/unmap/protect 路径有 descriptor、TLBI 或调用证据。
- CPU、vCPU、VM、VMID、页表和页面之间的关系已经形成统一模型。
- 所有冲突解释进入 Decision Log，没有被强行合并。
