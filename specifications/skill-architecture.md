# Skill 架构与职责

本文件属于规范层；实际 Skill 包统一位于仓库根目录的 `skills/`。

本文档定义 Workflow 中的 Skill 拆分。此处是 Skill 规格，不代表已经创建对应 Skill 目录。

完整 Skill 描述和唯一目标见 [skill-catalog.md](skill-catalog.md)。本文档重点定义拓扑、依赖、输出所有权和创建顺序。

## 1. Skill 设计规则

每个 Skill 必须：

1. 只处理一个稳定的专业目标。
2. 只读取 Stage Contract 声明的 Artifact。
3. 不把聊天上下文当作输入。
4. 不直接覆盖上游 Artifact。
5. 输出完整 Artifact，而不是仅返回自然语言结论。
6. 为每个推断写 Evidence ID。
7. 将不确定性写入 Unknown Registry。
8. 涉及 IDA 修改时先产生 proposal，审核后再提交 transaction。
9. 不调用约束之外的工具。
10. 不自行推进 Workflow Stage。

Skill 的 `SKILL.md` 应保持简洁。详细 ARM64、IDA 和 Artifact schema 放入 `references/`；重复且确定的转换以后再放入 `scripts/`。当前阶段优先定义合同，不创建脚本。

## 2. Orchestrator Skill

### `orchestrate-hypervisor-recovery`

职责：

- 读取 `workflow-state.json`。
- 校验当前 Stage 的输入。
- 选择并调用 Stage Skills。
- 管理可并行 Skill 和集成 Skill。
- 调用 `review-stage-output`。
- 根据 review 更新 `accepted/rework/blocked`。
- 失效传播和回退。
- 记录 `workflow-trace.jsonl`。

禁止：

- 自行分析汇编或命名函数。
- 修改 IDA。
- 修改 Producer Skill 输出内容。
- 绕过 Stage 门禁。

## 3. 公共治理 Skills

### `validate-artifact-contract`

- 校验 schema、case ID、Image SHA-256、producer、source artifacts 和 hash。
- 输出 `artifact-validation.json`。

### `review-stage-output`

- 独立读取 Stage 输入、输出和验收条件。
- 检查证据、过度推断、冲突和未知项。
- 输出 `stage-review.json`，结论只能是：
  - `accept`
  - `rework`
  - `block`

### `apply-reviewed-ida-changes`

- 只接收已审核的 `ida-change-proposal.json`。
- 在 IDA 中事务化应用。
- 输出 before/after、失败动作和 IDA checkpoint。
- 不负责提出业务名称或类型。

## 4. Stage Skills

## S00 Skills

### `initialize-hypervisor-recovery-case`

输入：

- `input/Image`
- `case-request.json`

输出：

- `case-manifest.json`
- 初始 `evidence.jsonl`

### `enforce-recovery-constraints`

输入：

- `case-manifest.json`
- `case-request.json`

输出：

- `constraint-profile.json`
- 初始 `unknowns.jsonl`

### `analyze-arm64-image-layout`

输入：

- `Image`
- Case/constraint Artifact

输出：

- `image-header.json`
- `embedded-candidates.json`
- layout Evidence

### `classify-binary-regions`

输入：

- `Image`
- `image-header.json`
- `embedded-candidates.json`

输出：

- `region-map.json`
- `string-index.jsonl`
- unknown regions

## S01 Skills

### `prepare-ida-image-database`

输入：

- `Image`
- `region-map.json`

输出：

- IDA baseline
- initial snapshot
- IDA load proposal

### `resolve-arm64-load-address`

输入：

- IDA baseline snapshot
- Image layout Artifact

输出：

- `address-space.json`
- base/entry Evidence
- Decision candidates

### `snapshot-ida-analysis-state`

输入：

- 当前 IDA database
- accepted IDA transactions

输出：

- versioned `.i64`
- normalized JSON snapshot

## S02 Skills

### `recover-ida-functions`

输出函数边界、直接调用和边界置信度。

### `recover-binary-data-objects`

输出字符串、表、数组、状态对象和 code/data 冲突。

### `recover-indirect-control-flow`

输出 jump table、function pointer table、间接调用候选和 unresolved targets。

### `integrate-program-structure`

合并前三项并检测边界冲突，输出统一 `program-model.json`。

## S03 Skills

### `recover-arm64-boot-flow`

恢复 entry、早期初始化、secondary CPU 和主控制转移。

### `recover-arm64-exception-model`

恢复 vector slots、handler、dispatch、保存/恢复和返回路径。

### `recover-arm64-context-layout`

恢复 trap/vCPU/per-CPU context 的 offset-first 类型。

### `recover-el2-architecture-semantics`

恢复 sysreg、HVC/SMC、TLBI、barrier、timer 和 GIC architecture events。

### `integrate-el2-architecture-model`

合并 boot、exception、context 和 architecture event，检测地址、字段和控制流冲突，输出统一 architecture model。

## S04 Skills

### `recover-hypervisor-cpu-vcpu-model`

恢复 CPU、per-CPU、vCPU、context 和 affinity 关系。

### `recover-hypervisor-stage2-memory-model`

恢复 VMID、VTTBR、descriptor、map/unmap/protect、fault 和 ownership 候选。

### `integrate-hypervisor-runtime-model`

合并 CPU/vCPU 与 memory 模型；检查 ownership、context 和 VMID 冲突。

## S05 Skills

### `recover-hypervisor-vm-config`

恢复 Image 内嵌配置对象及其初始化/校验路径。

### `recover-hypervisor-scheduler`

恢复 runqueue、状态、选择、迁移和 world switch。

### `recover-hypervisor-interrupt-routing`

恢复 IRQ/vIRQ、VM/vCPU route、注入、EOI 和 teardown。

### `integrate-hypervisor-service-model`

合并配置、调度和中断对象；检查引用一致性。

## S06 Skills

### `recover-hypervisor-vm-lifecycle`

恢复 VM 状态、资源创建、错误回滚和销毁。

### `recover-hypervisor-hkip-model`

恢复保护对象、权限变化、完整性数据和 violation path。

### `integrate-hypervisor-security-lifecycle`

合并生命周期与 HKIP，检查 page/VMID/IRQ/CPU binding 的状态转换。

## S07 Skills

### `synthesize-hypervisor-repository`

只根据 accepted 模型生成目录、C-like/C 候选和符号化 `.S`。

### `generate-recovery-source-map`

把每个生成文件、符号和字段映射到地址、字节范围和 Evidence。

### `index-recovery-evidence`

生成 recovery index、unresolved index 和置信度汇总。

## S08 Skills

### `audit-recovery-static-consistency`

检查恢复仓与 CFG、xref、类型 offset、sysreg 和 barrier 的一致性。

### `audit-hypervisor-security-invariants`

审计跨 VM 映射、HKIP 写保护、vCPU ownership、IRQ route 和资源释放。

### `assess-recovery-coverage`

统计已分析区域、函数、间接调用、类型和模块覆盖率。

### `integrate-recovery-audit`

合并 findings，生成 rework plan 和 audit summary。

## S09 Skills

### `package-hypervisor-recovery-delivery`

冻结 accepted Artifact，生成 hash 清单和 workflow trace。

### `write-hypervisor-recovery-report`

基于交付 Artifact 编写最终报告，不产生新技术结论。

## 5. Skill 并行与依赖

```text
S00 -> S01 -> S02 -> S03 -> S04
                           |
                           v
              +--------------------------+
S04           | CPU/vCPU      Stage-2    |  parallel
              +------------+-------------+
                           |
                           v integrate
              +--------------------------+
S05           | Config Scheduler IRQ     |  parallel
              +------------+-------------+
                           |
                           v integrate
              +--------------------------+
S06           | Lifecycle      HKIP      |  partial parallel
              +------------+-------------+
                           |
                           v integrate
S07 -> S08(parallel audits -> integrate) -> S09
```

并行 Skill 不得直接读取彼此未接受的工作目录；它们只能通过集成 Skill 合并。

## 6. Artifact 输出所有权

每个 Artifact 只能有一个 Owner Skill：

| Owner Skill | 独占输出 |
|---|---|
| `orchestrate-hypervisor-recovery` | `workflow/workflow-state.json`、各 Stage `stage-manifest.json`、最终 `workflow-trace.jsonl` |
| `validate-artifact-contract` | 各 Stage `artifact-validation.json` |
| `review-stage-output` | 各 Stage `stage-review.json` |
| `apply-reviewed-ida-changes` | IDA transaction result、before/after snapshot 引用 |
| `initialize-hypervisor-recovery-case` | `S00/case-manifest.json`、对应 records 分片 |
| `enforce-recovery-constraints` | `S00/constraint-profile.json`、对应 records 分片 |
| `analyze-arm64-image-layout` | `S00/image-header.json`、`S00/embedded-candidates.json` |
| `classify-binary-regions` | `S00/region-map.json`、`S00/string-index.jsonl` |
| `prepare-ida-image-database` | S01 IDA load proposal |
| `resolve-arm64-load-address` | `S01/address-space.json` |
| `snapshot-ida-analysis-state` | 所有 Stage 的 `.i64` 与 normalized snapshot |
| `recover-ida-functions` | `S02/functions.jsonl` |
| `recover-binary-data-objects` | `S02/data-objects.jsonl`、`S02/data-islands.jsonl`、`S02/code-data-boundary-audit.json`、`S02/unresolved-regions.jsonl` |
| `recover-indirect-control-flow` | `S02/indirect-targets.jsonl` |
| `integrate-program-structure` | `S02/program-model.json`、`S02/call-graph.json`、`S02/code-data-boundary-audit.json` |
| `recover-arm64-boot-flow` | `S03/boot-model.json` |
| `recover-arm64-exception-model` | `S03/exception-model.json` |
| `recover-arm64-context-layout` | `S03/context-layouts.jsonl` |
| `recover-el2-architecture-semantics` | `S03/sysreg-accesses.jsonl`、`S03/architecture-events.jsonl` |
| `integrate-el2-architecture-model` | `S03/architecture-model.json` |
| `recover-hypervisor-cpu-vcpu-model` | `S04/cpu-vcpu-model.json` |
| `recover-hypervisor-stage2-memory-model` | `S04/stage2-memory-model.json` |
| `integrate-hypervisor-runtime-model` | `S04/runtime-object-model.json`、`S04/types.jsonl`、`S04/resource-ownership.jsonl` |
| `recover-hypervisor-vm-config` | `S05/vm-config-model.json` |
| `recover-hypervisor-scheduler` | `S05/scheduler-model.json` |
| `recover-hypervisor-interrupt-routing` | `S05/interrupt-model.json` |
| `integrate-hypervisor-service-model` | `S05/service-model.json`、`S05/state-machines.jsonl` |
| `recover-hypervisor-vm-lifecycle` | `S06/lifecycle-model.json` |
| `recover-hypervisor-hkip-model` | `S06/hkip-model.json` |
| `integrate-hypervisor-security-lifecycle` | `S06/security-lifecycle-model.json`、`S06/resource-transitions.jsonl` |
| `synthesize-hypervisor-repository` | `S07/recovered-repository/` |
| `generate-recovery-source-map` | `S07/source-map.jsonl` |
| `index-recovery-evidence` | `S07/recovery-index.json`、`S07/unresolved-index.jsonl` |
| `audit-recovery-static-consistency` | `S08/static-consistency.json` |
| `audit-hypervisor-security-invariants` | `S08/security-invariants.json` |
| `assess-recovery-coverage` | `S08/coverage.json` |
| `integrate-recovery-audit` | `S08/findings.jsonl`、`S08/rework-plan.json`、`S08/audit-summary.json` |
| `package-hypervisor-recovery-delivery` | `S09/delivery-manifest.json`、冻结仓和 workflow trace |
| `write-hypervisor-recovery-report` | `S09/final-report.md`、final unknown/decision 汇总 |

Evidence、Decision 和 Unknown 使用 append-only 分片：每个 Producer 写
`Sxx/records/<skill-name>.evidence.jsonl`、
`Sxx/records/<skill-name>.decisions.jsonl`、
`Sxx/records/<skill-name>.unknowns.jsonl`，由集成 Skill 生成 Stage 索引，避免并行写冲突。

## 7. Skill 输入规则

- Worker Skill：读取 Stage accepted 输入和自己的明确参考资料。
- Integration Skill：额外读取同 Stage Worker 输出；不得读取未声明草稿。
- Reviewer Skill：读取 Stage 必需输入、全部候选输出、Stage Contract。
- IDA Apply Skill：只读取 reviewed proposal 和 accepted base snapshot。
- Delivery Skill：只读取 accepted Artifact，不重新分析二进制。

## 8. 创建顺序

实际创建 Skill 时按以下顺序实施：

1. 公共治理 Skills。
2. S00–S01 基础闭环 Skills。
3. S02 程序结构 Skills。
4. S03 EL2 架构语义 Skills。
5. S04–S06 领域 Skills。
6. S07–S09 合成与审计 Skills。
7. 最后创建 Orchestrator Skill。

先用真实 Artifact 契约验证单个 Skill，再启用 Orchestrator 自动推进。
