## S05：VM 服务模型

### 目标

在基础对象模型之上恢复 VM 配置、共核调度和中断虚拟化/直通。

### 输入

- `S04/runtime-object-model.json`
- `S04/types.jsonl`
- `S04/resource-ownership.jsonl`
- `S04/cpu-vcpu-model.json`
- `S04/stage2-memory-model.json`
- `S04/function-clusters.json`
- `S02/program-model.json`
- `S02/functions.jsonl`
- `S02/call-graph.json`
- `S02/data-objects.jsonl`
- `S03/architecture-model.json`
- `S03/sysreg-accesses.jsonl`
- `S03/context-layouts.jsonl`
- `S03/architecture-events.jsonl`
- `S04/ida-stage.i64`
- `S04/evidence-index.json`、`decision-index.json`、`unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S05/vm-config-model.json` | 内嵌 VM/vCPU/memory/device/IRQ 配置候选 |
| `S05/scheduler-model.json` | runqueue、状态、迁移、world switch |
| `S05/interrupt-model.json` | physical IRQ、vIRQ、VM/vCPU route |
| `S05/service-model.json` | 三类服务的统一对象关系 |
| `S05/state-machines.jsonl` | 调度与中断状态候选 |
| `S05/type-candidates.json` | S06 类型传播的候选类型定义 |
| `S05/struct-layouts.jsonl` | 结构体字段偏移候选 |
| `S05/ida-change-proposal.json` | scheduler/interrupt/vm-config 函数重命名提案 |
| `S05/ida-stage.i64` | VM 服务 checkpoint |
| `S05/records/<producer>.*.jsonl` | 四个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
S04 runtime model
  +-> recover-hypervisor-vm-config -----------+
  +-> recover-hypervisor-scheduler -----------+-> integrate-hypervisor-service-model
  +-> recover-hypervisor-interrupt-routing ---+   -> review-stage-output
                                                   -> human service-model gate
                                                   -> apply-reviewed-ida-changes
                                                   -> snapshot-ida-analysis-state
                                                   -> validate-artifact-contract
                                                   -> orchestrate-hypervisor-recovery
```

- 三个 Worker 并行，只读取 accepted S04 runtime model。
- Integration Skill 解析 VM/vCPU/device/IRQ 对象引用和状态冲突。
- Scheduler 与 interrupt Worker 可引用 architecture events，但不能修改 S05 ownership。
- 人工门禁确认安全关键 route、runqueue 和配置结构。

### 退出条件

- **accepted**：三类服务模型均完成或显式标记 absent/unknown；集成引用不冲突；关键未知项有影响范围。
- **rework**：配置对象与 runtime type 不一致、调度 ownership 冲突、IRQ route 目标不稳定或 S05 被否定。
- **blocked**：VM/vCPU 基础引用不足，无法把服务行为绑定到任何运行时对象。

### 边界

- VM 配置只来自 Image 内嵌对象，不假设外部配置文件。
- 调度模型不提前命名生命周期状态。
- 中断模型不在无证据时确认具体 GIC/SMMU 型号。
- 三个 Worker 不得修改基础 ownership；冲突回退 S05。
