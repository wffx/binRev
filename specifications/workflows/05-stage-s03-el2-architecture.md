## S03：ARM64 EL2 架构语义

### 目标

恢复启动、异常、上下文、系统寄存器和同步原语，不使用高级业务名称污染基础模型。

### 输入

- `S01/ida-baseline.i64`
- `S01/address-space.json`
- `S02/stage-manifest.json`
- `S02/program-model.json`
- `S02/functions.jsonl`
- `S02/data-objects.jsonl`
- `S02/data-islands.jsonl`
- `S02/code-data-boundary-audit.json`
- `S02/call-graph.json`
- `S02/indirect-targets.jsonl`
- `S02/unresolved-regions.jsonl`
- `S02/unresolved-regions*.jsonl`
- `S02/unknown-index.json`
- `S02/evidence-index.json`
- `S02/decision-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S03/boot-model.json` | entry、初始化、secondary CPU 路径 |
| `S03/exception-model.json` | vector slot、handler、dispatch、return |
| `S03/context-layouts.jsonl` | trap/vCPU/per-CPU 字段偏移候选 |
| `S03/sysreg-accesses.jsonl` | MRS/MSR 位置和语义 |
| `S03/architecture-events.jsonl` | HVC/SMC/ERET/TLBI/barrier/wait |
| `S03/architecture-model.json` | 上述模型的集成索引，含 `s04_readiness` 和 `rename_proposal_summary` |
| `S03/ida-change-proposal.json` | 架构锚点函数重命名提案（`candidate_` 前缀，证据来自 sysreg/boot/exception 分析） |
| `S03/ida-stage.i64` | 架构语义 checkpoint |
| `S03/records/<producer>.*.jsonl` | 五个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
S03 program model
  +-> recover-arm64-boot-flow -----------+
  +-> recover-arm64-exception-model -----+-> recover-arm64-context-layout
  +-> recover-el2-architecture-semantics +-> integrate-el2-architecture-model
                                            -> review-stage-output
                                            -> human architecture gate
                                            -> apply-reviewed-ida-changes
                                            -> snapshot-ida-analysis-state
                                            -> validate-artifact-contract
                                            -> orchestrate-hypervisor-recovery
```

- Boot、exception 和 architecture-semantics Worker 可并行读取 S03。
- Context layout 必须等待 boot/exception 的 save/restore 根路径。
- 新增 `integrate-el2-architecture-model` 作为唯一 architecture model Owner。
- `integrate-el2-architecture-model` 产出 `ida-change-proposal.json`，包含架构锚点函数（boot/exception/sysreg/MMU）的 `candidate_` 前缀重命名提案。命名规则详见对应 SKILL.md。
- 集成后才允许写入 IDA 架构名称、类型和注释（由 `apply-reviewed-ida-changes` 执行）。
- S03 输出必须标记 `s04_readiness`：若本 Stage accepted 且无 blocking unresolved，标记为 ready；否则标记为 blocked_by_s03，下游 S04 只能以 forward-test 模式运行。
- forward-test S04 可以消费 S03 的非 accepted 产物用于调测，但不得生成 accepted `S03/ida-stage.i64`。

### 退出条件

- **accepted**：启动和异常主路径可追踪或明确未知；关键 sysreg/event 已索引；context 保持 offset-first。
- **rework**：vector 误识别、save/restore 不对称、系统寄存器解码错误，或 S03 函数边界被否定。
- **blocked**：无法定位任何 EL2/exception/guest-transition 根路径，致使业务模型没有架构锚点；或 S03 仍存在阻塞性 code/data/blob unresolved，导致 S04 无法获得干净程序结构输入。

### 边界

- 只输出 ARM64/EL2 架构语义，不确认 VM config、scheduler、interrupt route 或 HKIP 业务归属。
- 系统寄存器访问只能确认架构动作，不能单独确认高级函数名。
- 不得把 S03 blocking unresolved blob 内的代码片段升级为 S04 architecture root；只能记录为 S03 rework 依赖。
- Context 字段先使用 offset 名；不得依据常见开源结构直接套型。
- 通用 ARM 规范知识可用，目标特定签名和源码不可用。
