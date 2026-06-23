# IDA Tool Contract

本文档是 [workflow.md](../workflow.md) 的 IDA Tool Contract，不是独立 Workflow。约束是：外部分析工具只有 IDA；不使用 MCP、调试器、仿真器、其他反编译器或交叉编译器。

Stage 与 Skill 的规范映射见 [skill-architecture.md](../skill-architecture.md)。IDA 修改格式见 [artifact-contracts.md](artifact-contracts.md)。

## 1. IDA 使用边界

允许：

- IDA AArch64 processor module
- IDA disassembly、CFG、xref、segment、function、enum、struct 和 type 功能
- IDAPython
- 当前 IDA 安装中实际存在的反编译功能

不假设：

- Hex-Rays 必然可用
- 调试器能够运行目标
- IDA 能自动识别正确 base、函数、类型或 MMIO
- 任何第三方 IDA 插件或 MCP server 可用

IDA 是可变共享状态，必须遵循：

- 每个 accepted Stage 保存一个 IDA checkpoint。
- Producer Skill 只能提出 change proposal。
- 只有 `apply-reviewed-ida-changes` 能提交审核后的修改。
- 每次提交保存 before/after snapshot 和 transaction record。
- 下游 Stage 只能读取 accepted checkpoint。

## 2. Stage 映射

| 主流程阶段 | IDA 的职责 |
|---|---|
| S00–S01 | 不修改 IDA |
| S02 | 装载、确认地址空间、保存 baseline |
| S03 | 恢复程序结构并保存 checkpoint |
| S04 | 写入已审核架构语义并保存 checkpoint |
| S05 | 写入已审核 CPU/vCPU/Stage-2 类型与名称 |
| S06 | 写入已审核 config/scheduler/interrupt 模型 |
| S07 | 写入已审核 lifecycle/HKIP 模型 |
| S08 | 只读 IDA accepted checkpoint，生成恢复仓 |
| S09 | 只读审计；发现错误时回退上游 |
| S10 | 冻结 final IDA checkpoint |

---

## S02：装载和确认地址空间

### 装载

由 `prepare-ida-image-database` 将唯一 `input/Image` 作为 AArch64
little-endian binary 装载。任何 synthetic ELF 只能是可选的内部派生物，
不能成为新的案例输入或跳过地址空间审查。

### 检查

1. 核对 Image base 候选。
2. 检查 entry 附近是否为有效 AArch64 指令。
3. 检查 `ADRP`、直接分支和绝对指针落点。
4. 检查 2 KiB 对齐的异常向量候选。
5. 将 appended data 保持为 data/unknown。
6. 不要因为 IDA 自动分析成功就确认 base。

### 基线快照

`snapshot-ida-analysis-state` 使用 IDAPython 保存：

- `stages/S02/ida-baseline.i64`
- `stages/S02/ida-baseline-snapshot.json`
- 对应 `.meta.json`

具体 IDAPython 实现不是 Workflow Contract 的一部分。

---

## S03：恢复代码、数据和函数

### 函数创建优先级

按以下顺序创建：

1. Image entry
2. 异常向量 slot 的直接目标
3. 已确认函数中的直接 `BL` 目标
4. 函数指针表中的候选目标
5. jump table 的 case target
6. 剩余未决区域

### 每次创建前检查

- 地址是否 4-byte 对齐
- 前一函数是否 tail-call 到此处
- 该位置是否可能为 literal pool 或 inline data
- 是否有入边 xref
- 是否存在合理返回或 noreturn 路径

### 数据恢复

优先标记：

- 字符串
- 绝对指针表
- 函数指针表
- 固定 stride 数组
- 只读位掩码和 descriptor 表
- 可写状态对象

无法区分代码和数据时保留 undefined，不要强行转换。

### 函数记录

在函数注释中记录：

```text
[confidence]
[boundary evidence]
[callers/callees]
[global xrefs]
[indirect-call status]
[open questions]
```

---

## S04：恢复架构骨架

### 启动与异常

1. 从 entry 向前推进，不使用业务命名。
2. 查找 `MSR VBAR_EL2` 并回溯向量地址。
3. 验证 16 个 128-byte vector slot。
4. 恢复公共寄存器保存和恢复代码。
5. 建立异常类型到 handler 的映射。

### 系统寄存器

对每个关键 `MRS/MSR` 添加 repeatable comment：

```text
register
read/write
constructed value
caller
possible architectural effect
```

重点包括：

```text
HCR_EL2 SCTLR_EL2 TCR_EL2 TTBR0_EL2
VTCR_EL2 VTTBR_EL2 VBAR_EL2
ESR_EL2 FAR_EL2 HPFAR_EL2
CNTHCTL_EL2 CNTVOFF_EL2
ICH_* ICC_*
```

### 上下文类型

1. 从 save/restore 指令成对恢复字段 offset。
2. 先创建 `unknown_context`。
3. 字段使用 `field_0xNN`。
4. 多条独立路径一致后，升级为 `trap_frame` 或 `vcpu_context` 候选。

如果反编译器可用，用于辅助观察数据流；最终结论仍以指令和 xref 为准。

---

## S05–S07：恢复业务模型

保持与主 Workflow 相同依赖：

### S05 CPU 与 vCPU

- 从 `MPIDR_EL1`、`TPIDR_EL2` 和 per-CPU stride 建立对象关系。
- 恢复当前 CPU、当前 vCPU 和所属 VM 指针候选。

### S05 Stage-2 内存

- 从 `VTCR_EL2`、`VTTBR_EL2`、descriptor 位操作和 TLBI 建立函数集合。
- 给页表 walk、map、unmap、protect 使用候选名，直到调用与数据证据闭合。

### S06 VM 配置

- 从固定数组、对象初始化和校验路径恢复内嵌配置模型。
- 不假设存在外部配置文件。

### S06 调度

- 追踪 runqueue、状态写入、timer/IRQ 唤醒、previous/next context。
- 将 world-switch 与普通函数分开处理。

### S06 中断直通

- 追踪 `ICH_*`、IRQ route 表和注入/EOI 路径。
- 具体 GIC/SMMU 型号不明时使用 `gic_candidate`、`smmu_candidate`。

### S07 VM 生命周期

- 对全部 VM 状态写入点建立 xref 集合。
- 使用 `state_0xN`，直到每个状态的前置条件和资源效果清晰。

### S07 HKIP

- 追踪保护区、权限变化、完整性元数据和 violation path。
- hash/checksum 只作为支持证据，不能单独确认 HKIP。

### 命名要求

推荐：

```text
candidate_stage2_map
candidate_irq_inject
candidate_vm_destroy
unknown_state_transition_3
```

只有两类以上独立证据闭合后，才移除 `candidate_`。

---

## S08：导出到静态代码仓

S08 只读 `stages/S07/ida-stage.i64` 和 accepted snapshot。不得在代码仓
合成过程中修改 IDA。

代码仓中的每个函数应保留：

- IDA address
- IDA name
- boundary confidence
- prototype confidence
- xref 摘要
- 原始字节范围
- 系统寄存器/MMIO 证据
- 未决问题

无反编译器时：

- 普通逻辑使用手工 C-like 伪代码。
- 控制和数据关系不清时不生成 C。
- 异常入口、world-switch 和原子序列使用符号化 `.S`。

---

## S09：静态一致性与安全审计

### 静态一致性

在 IDA 中对照恢复代码检查：

- 所有分支是否有对应语义
- error/noreturn 路径是否遗漏
- 间接调用是否明确标记
- 结构 offset 和访问宽度是否一致
- 系统寄存器、TLBI 和 barrier 顺序是否一致

### 安全审计

为以下对象建立全部写入点/xref 视图：

- Stage-2 descriptor
- page owner/share state
- HKIP permission state
- vCPU owner/current VM
- IRQ route
- VMID
- CPU binding
- VM lifecycle state

存在未解析间接调用或未决数据时，结论保持 `unknown`。

---

## S10：最终 IDA 交付

保存：

- 未修改基线 IDB
- 最终 IDB
- 阶段快照
- 自定义 enum、struct、prototype
- 函数和模块映射
- 未解析 indirect call、jump table 和数据区
- 安全审计的 xref 集合

不要为了界面整洁删除 `candidate`、`unknown` 或置信度注释。

## 3. IDA 自动化边界

以下操作必须人工审核：

- base 与 entry 确认
- 异常向量确认
- 大范围函数创建
- 全局结构体应用
- VM、vCPU、page owner、IRQ route 等安全关键类型
- candidate 升级为 confirmed
- 安全结论从 unknown 升级为 supported/violated
