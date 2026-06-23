# S06：VM 服务模型

## 核心目标

S06 在 S05 的 CPU、vCPU、VM 和 Stage-2 对象基础上，恢复 Hypervisor 如何：

1. 配置 VM；
2. 调度 vCPU 共享物理 CPU；
3. 将物理中断路由并注入目标 VM/vCPU。

一句话概括：

> S06 恢复 Hypervisor 的服务运行层：VM 如何配置、vCPU 如何运行、IRQ 如何送达。

## S05 与 S06 的区别

S05 恢复对象和 ownership：

```text
CPU → current_vcpu
vCPU → owner_vm
VM → vmid + stage2_root
```

S06 恢复对象如何协作：

```text
配置数据如何创建或初始化 VM？
调度器如何选择 next_vcpu？
physical IRQ 如何映射到 vIRQ 和目标 vCPU？
```

## 具体需要做什么

### 1. 恢复 VM 配置模型

从 Image 内部的数据和初始化代码识别：

- VM 数量候选
- vCPU 数量
- CPU affinity
- IPA/内存区域
- device
- IRQ 配置
- shared memory
- 配置校验

候选结构：

```text
VM config
├── vm_id candidate
├── vcpu_count
├── memory_regions[]
├── irq_routes[]
├── devices[]
└── cpu_affinity
```

因为输入只有 `Image`，不能假设存在外部配置文件。

### 2. 恢复共核调度模型

识别：

- runqueue
- runnable、blocked、running 状态候选
- previous/next vCPU
- 时间片和 timer
- reschedule flag
- vCPU wake/block
- CPU affinity
- vCPU migration
- world switch
- 锁和屏障

候选调度路径：

```text
timer/IRQ
  → set reschedule
  → select next_vcpu
  → save previous context
  → update CPU.current_vcpu
  → restore next context
  → ERET
```

S06 只恢复静态可见机制，不保证完整恢复真实运行策略。

### 3. 恢复中断虚拟化与直通

识别：

- `ICH_*`、`ICC_*`
- GIC 风格 MMIO 候选
- physical IRQ 到 virtual IRQ 的映射
- IRQ 与 VM/vCPU 的绑定
- interrupt injection
- maintenance interrupt
- EOI
- route create/update/delete
- MSI/LPI 和 SMMU 候选

候选关系：

```text
physical_irq
  → irq_route
      ├── target_vm
      ├── target_vcpu
      └── virtual_irq
  → inject
  → guest handles IRQ
  → EOI
```

没有充分证据时，只能使用 candidate/unknown 名称。

### 4. 合并三类服务

集成时检查：

- 配置中的 VM/vCPU 是否存在于 S05。
- 调度器选择的 vCPU 是否属于对应 VM。
- IRQ route 的 target VM/vCPU 是否有效。
- CPU affinity 是否与调度绑定一致。
- 配置、调度和中断是否对同一字段产生冲突解释。

冲突必须进入 Decision/Unknown，不得强行统一。

## 输入

```text
S05/runtime-object-model.json
S05/types.jsonl
S05/resource-ownership.jsonl
S05/cpu-vcpu-model.json
S05/stage2-memory-model.json
S03/program-model.json
S03/call-graph.json
S04/architecture-model.json
S04/context-layouts.jsonl
S04/architecture-events.jsonl
S05/ida-stage.i64
S05 Evidence/Decision/Unknown indexes
```

## Skills

```text
recover-hypervisor-vm-config -----------+
recover-hypervisor-scheduler -----------+→ integrate-hypervisor-service-model
recover-hypervisor-interrupt-routing ---+  → review
                                             → human service-model gate
                                             → reviewed IDA transaction
                                             → checkpoint
```

## 产物

```text
S06/
├── vm-config-model.json
├── scheduler-model.json
├── interrupt-model.json
├── service-model.json
├── state-machines.jsonl
├── ida-stage.i64
└── records/
```

## 不做什么

- 不恢复完整 VM create/start/pause/destroy 生命周期。
- 不恢复完整错误回滚和资源销毁。
- 不确认 HKIP。
- 不判断系统是否存在安全漏洞。
- 不在无证据时确认具体 GIC/SMMU 型号。
- 不生成最终代码仓。

## 完成标准

可以进入 S07：

- VM 配置候选可以关联 S05 的 VM/vCPU 对象。
- 调度路径可以识别 previous/next vCPU，或明确登记 Unknown。
- IRQ route 至少关联 IRQ、目标对象和写入路径候选。
- 三类模型之间没有未解释的对象或 ownership 冲突。
- 无证据的硬件型号、策略和状态保持 candidate/unknown。
