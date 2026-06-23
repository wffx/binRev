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

## S01 Skills

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

## S02 Skills

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

## S03 Skills

### `recover-ida-functions`

输出函数边界、直接调用和边界置信度。

### `recover-binary-data-objects`

输出字符串、表、数组、状态对象和 code/data 冲突。

### `recover-indirect-control-flow`

输出 jump table、function pointer table、间接调用候选和 unresolved targets。

### `integrate-program-structure`

合并前三项并检测边界冲突，输出统一 `program-model.json`。

## S04 Skills

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

## S05 Skills

### `recover-hypervisor-cpu-vcpu-model`

恢复 CPU、per-CPU、vCPU、context 和 affinity 关系。

### `recover-hypervisor-stage2-memory-model`

恢复 VMID、VTTBR、descriptor、map/unmap/protect、fault 和 ownership 候选。

### `integrate-hypervisor-runtime-model`

合并 CPU/vCPU 与 memory 模型；检查 ownership、context 和 VMID 冲突。

## S06 Skills

### `recover-hypervisor-vm-config`

恢复 Image 内嵌配置对象及其初始化/校验路径。

### `recover-hypervisor-scheduler`

恢复 runqueue、状态、选择、迁移和 world switch。

### `recover-hypervisor-interrupt-routing`

恢复 IRQ/vIRQ、VM/vCPU route、注入、EOI 和 teardown。

### `integrate-hypervisor-service-model`

合并配置、调度和中断对象；检查引用一致性。

## S07 Skills

### `recover-hypervisor-vm-lifecycle`

恢复 VM 状态、资源创建、错误回滚和销毁。

### `recover-hypervisor-hkip-model`

恢复保护对象、权限变化、完整性数据和 violation path。

### `integrate-hypervisor-security-lifecycle`

合并生命周期与 HKIP，检查 page/VMID/IRQ/CPU binding 的状态转换。

## S08 Skills

### `synthesize-hypervisor-repository`

只根据 accepted 模型生成目录、C-like/C 候选和符号化 `.S`。

### `generate-recovery-source-map`

把每个生成文件、符号和字段映射到地址、字节范围和 Evidence。

### `index-recovery-evidence`

生成 recovery index、unresolved index 和置信度汇总。

## S09 Skills

### `audit-recovery-static-consistency`

检查恢复仓与 CFG、xref、类型 offset、sysreg 和 barrier 的一致性。

### `audit-hypervisor-security-invariants`

审计跨 VM 映射、HKIP 写保护、vCPU ownership、IRQ route 和资源释放。

### `assess-recovery-coverage`

统计已分析区域、函数、间接调用、类型和模块覆盖率。

### `integrate-recovery-audit`

合并 findings，生成 rework plan 和 audit summary。

## S10 Skills

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
S05           | CPU/vCPU      Stage-2    |  parallel
              +------------+-------------+
                           |
                           v integrate
              +--------------------------+
S06           | Config Scheduler IRQ     |  parallel
              +------------+-------------+
                           |
                           v integrate
              +--------------------------+
S07           | Lifecycle      HKIP      |  partial parallel
              +------------+-------------+
                           |
                           v integrate
S08 -> S09(parallel audits -> integrate) -> S10
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
| `analyze-arm64-image-layout` | `S01/image-header.json`、`S01/embedded-candidates.json` |
| `classify-binary-regions` | `S01/region-map.json`、`S01/string-index.jsonl` |
| `prepare-ida-image-database` | S02 IDA load proposal |
| `resolve-arm64-load-address` | `S02/address-space.json` |
| `snapshot-ida-analysis-state` | 所有 Stage 的 `.i64` 与 normalized snapshot |
| `recover-ida-functions` | `S03/functions.jsonl` |
| `recover-binary-data-objects` | `S03/data-objects.jsonl`、`S03/unresolved-regions.jsonl` |
| `recover-indirect-control-flow` | `S03/indirect-targets.jsonl` |
| `integrate-program-structure` | `S03/program-model.json`、`S03/call-graph.json` |
| `recover-arm64-boot-flow` | `S04/boot-model.json` |
| `recover-arm64-exception-model` | `S04/exception-model.json` |
| `recover-arm64-context-layout` | `S04/context-layouts.jsonl` |
| `recover-el2-architecture-semantics` | `S04/sysreg-accesses.jsonl`、`S04/architecture-events.jsonl` |
| `integrate-el2-architecture-model` | `S04/architecture-model.json` |
| `recover-hypervisor-cpu-vcpu-model` | `S05/cpu-vcpu-model.json` |
| `recover-hypervisor-stage2-memory-model` | `S05/stage2-memory-model.json` |
| `integrate-hypervisor-runtime-model` | `S05/runtime-object-model.json`、`S05/types.jsonl`、`S05/resource-ownership.jsonl` |
| `recover-hypervisor-vm-config` | `S06/vm-config-model.json` |
| `recover-hypervisor-scheduler` | `S06/scheduler-model.json` |
| `recover-hypervisor-interrupt-routing` | `S06/interrupt-model.json` |
| `integrate-hypervisor-service-model` | `S06/service-model.json`、`S06/state-machines.jsonl` |
| `recover-hypervisor-vm-lifecycle` | `S07/lifecycle-model.json` |
| `recover-hypervisor-hkip-model` | `S07/hkip-model.json` |
| `integrate-hypervisor-security-lifecycle` | `S07/security-lifecycle-model.json`、`S07/resource-transitions.jsonl` |
| `synthesize-hypervisor-repository` | `S08/recovered-repository/` |
| `generate-recovery-source-map` | `S08/source-map.jsonl` |
| `index-recovery-evidence` | `S08/recovery-index.json`、`S08/unresolved-index.jsonl` |
| `audit-recovery-static-consistency` | `S09/static-consistency.json` |
| `audit-hypervisor-security-invariants` | `S09/security-invariants.json` |
| `assess-recovery-coverage` | `S09/coverage.json` |
| `integrate-recovery-audit` | `S09/findings.jsonl`、`S09/rework-plan.json`、`S09/audit-summary.json` |
| `package-hypervisor-recovery-delivery` | `S10/delivery-manifest.json`、冻结仓和 workflow trace |
| `write-hypervisor-recovery-report` | `S10/final-report.md`、final unknown/decision 汇总 |

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
2. S00–S04 基础 Skills。
3. S05–S07 领域 Skills。
4. S08–S10 合成与审计 Skills。
5. 最后创建 Orchestrator Skill。

先用真实 Artifact 契约验证单个 Skill，再启用 Orchestrator 自动推进。
