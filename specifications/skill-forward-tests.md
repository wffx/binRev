# Skill Forward Test Results

本文档记录正式 Skill 创建后的前向验证结果。Forward-test 只验证 Skill 是否能按约束执行，不把测试样本当成目标项目事实。

## G02-A：S00-S02 基础闭环 Skills

### 测试样本

| 项 | 值 |
|---|---|
| Raw binary | `tests/xen` |
| IDB | `tests/xen.i64` |
| Raw size | `2883696` |
| Raw SHA-256 | `ffa8cc5a4c2b088608de40cc7cef7521a8257c5d4708baa0c02d6f46e6c71ba7` |
| 测试边界 | 非目标样本，只验证 IDA MCP 通路和非目标格式处理 |

### S00/S01 边界验证

`tests/xen` 的文件头检查结果：

| 检查项 | 结果 |
|---|---|
| first4 | `7f454c46` |
| ELF magic | `true` |
| ARM64 Image magic offset `0x38` | `0x80` |
| ARM64 Image expected magic | `0x644d5241` |
| `analyze-arm64-image-layout` 期望状态 | `incompatible` |

结论：

- `initialize-hypervisor-recovery-case` 可以对该样本生成唯一 case 身份和 SHA-256。
- `enforce-recovery-constraints` 应把该样本标为 forward-test 样本，不得把它当成目标 ARM64 Image。
- `analyze-arm64-image-layout` 应输出 `format_status: incompatible`。
- `classify-binary-regions` 可输出保守 region map，但不能强行解释为 ARM64 Image 布局。

### IDA MCP 只读验证

使用：

```text
D:\Program Files\IDA Professional 9.3\ida-mcp.exe serve --read-only
```

通过 JSON-RPC 执行：

- `initialize`
- `open_idb`
- `idb_meta`
- `analysis_status`
- `list_functions`
- `disasm_by_name`
- `close_idb`

结果：

| 检查项 | 结果 |
|---|---|
| MCP server | `rmcp 1.7.0` |
| `open_idb` | success |
| file type | `ELF` |
| processor | `MetaPC (disassemble all opcodes)` |
| bits | `32` |
| function count | `2519` |
| analysis running | `false` |
| auto state | `AU_NONE` |
| IDA input SHA-256 | `ffa8cc5a4c2b088608de40cc7cef7521a8257c5d4708baa0c02d6f46e6c71ba7` |

前 5 个函数：

| Address | Name | Size |
|---|---|---:|
| `0x200000` | `start` | 5 |
| `0x201b7c` | `sub_201B7C` | 3 |
| `0x202088` | `nullsub_5` | 1 |
| `0x20318e` | `sub_20318E` | 19 |
| `0x2031a1` | `nullsub_6` | 1 |

`start` 反汇编片段：

```text
0x200000: jmp near ptr start_0
0x200005: align 4
0x200008: dd 1BADB002h, 3, 0E4524FFBh, ...
```

结论：

- `prepare-ida-image-database` 的 IDA MCP transport 路径可用。
- `snapshot-ida-analysis-state` 所需的 metadata、analysis status、function summary 和 disassembly evidence 可由 IDA MCP 读取。
- `resolve-arm64-load-address` 对该样本应输出 `decision_status: not_applicable`，因为 IDA processor 为 MetaPC，不是 ARM64/AArch64。

### 已知限制

- 当前 Codex 会话未暴露原生 `mcp__ida__...` 工具命名空间，因此本次验证使用 `ida-mcp.exe serve --read-only` 的 JSON-RPC 适配路径。
- 沙箱内 `open_idb` 超时；沙箱外只读验证成功。后续自动化需要记录 transport 与权限上下文。
- 该样本不能验证 ARM64 EL2 语义、Image header 解析、ADRP 闭合度或异常向量恢复。

## G02-B：S03 程序结构 Skills

### 测试样本

| 项 | 值 |
|---|---|
| Raw binary | `tests/xen_arm64` |
| IDB | `tests/xen_arm64.i64` |
| Raw size | `1048592` |
| Raw SHA-256 | `778090a16c51b1e6445643aa88c6564d938fcdb46138c387c87dbec1ec42569f` |
| IDB SHA-256 after S03 | `0f6673e176e99bc24231952207a00dbe0f8d697d58da6e49883337cc9bbeb325` |

### 验证范围

本轮验证覆盖以下 S03 skills：

- `recover-ida-functions`
- `recover-binary-data-objects`
- `recover-indirect-control-flow`
- `integrate-program-structure`

### IDA MCP 写回验证

用户授权后，S03 对 `tests/xen_arm64.i64` 执行了候选级写回：

| Address | IDA name |
|---:|---|
| `0x188` | `candidate_image_entry_dispatch` |
| `0x198` | `candidate_boot_cpu_entry` |
| `0x1EC` | `candidate_currentel_wait_path` |
| `0x238` | `candidate_el2_mmu_control_init` |
| `0x5C4` | `candidate_ttbr0_el2_sctlr_switch` |
| `0x6C4` | `candidate_ttbr0_el2_sctlr_update` |

约束：

- 仅写入候选名和 repeatable comments。
- 未修改 bytes、segments、function boundaries、types 或 prototypes。
- 所有候选名保留 `candidate_` 前缀。

### 本地产物

S03 中间产物已保存到：

```text
cases/xen_arm64-778090a1/stages/S03/
```

核心产物：

- `functions.jsonl`
- `data-objects.jsonl`
- `indirect-targets.jsonl`
- `call-graph.json`
- `program-model.json`
- `ida-change-proposal.json`
- `ida-change-transactions.jsonl`
- `ida-stage-snapshot.json`

### 验证结果

- S03 JSON/JSONL 产物解析通过。
- IDA MCP 重开验证确认 6 个候选名与 repeatable comments 已持久化。
- 技能 `SKILL.md` frontmatter 轻量检查通过。
- 官方 `quick_validate.py` 因当前 Python 环境缺少 `PyYAML` 未能运行；本轮未安装额外依赖。

### Oracle 分支比对结果

新增匹配符号 oracle：

| 项 | 值 |
|---|---|
| Oracle binary | `tests/xen-syms_arm64` |
| Oracle SHA-256 | `e863bbb8886e6af7b3f1a1a382d257cd4ce4cd16642cfcf891a2679e1c00e61f` |
| Oracle 用途 | validation-only，不进入生产证据链 |
| 选中分支 | `S03-BRANCH-BOOT-MMU-0001` |
| 范围 | `0x160-0x754` |

关键偏差：

| Offset | 当前 S03 | Oracle | 结论 |
|---:|---|---|---|
| `0x160` | 未建函数 | `real_start` | missed branch root |
| `0x188` | `candidate_image_entry_dispatch` | `real_start` 内部块 | false function start |
| `0x198` | `candidate_boot_cpu_entry` | `init_secondary` | 泛化命名且 size 偏差 |
| `0x1EC` | `candidate_currentel_wait_path` | `check_cpu_mode` | 边界匹配，命名可细化 |
| `0x238` | `candidate_el2_mmu_control_init` | `cpu_init` | 命名过于局部化 |
| `0x368` | `sub_368` | `create_page_tables` | 边界匹配但未命名 |
| `0x5C4` | `candidate_ttbr0_el2_sctlr_switch` | `enable_mmu` | 命名过于局部化且 size 偏差 |
| `0x6C4` | `candidate_ttbr0_el2_sctlr_update` | `relocate_xen` + `switch_ttbr_id @ 0x708` | merged functions |

结论：

- S03 写回机制验证通过。
- S03 结构恢复质量不满足进入 S04 的要求。
- 生产 S03 产物状态保持 `review_required`。
- G02-B skill/workflow 调测状态标记为 `rework`，不代表真实逆向 workflow 引入符号 oracle。
- 后续 S03 必须先完成一个函数分支样本的边界质量审计，再允许 IDA proposal 进入写回。

### S03-RW1 boundary-first proposal score

S03-RW1 使用 target-only 证据重新建模 `0x160-0x754` 分支，并只生成新的 IDA proposal，没有写入 IDB。

validation-only oracle score 存放在：

- `cases/xen_arm64-778090a1/validation/S03/oracle-rework-01-score.json`

结果摘要：

- branch-start coverage: `8/16` -> `14/16`
- exact boundary-start match: `3/16` -> `14/16`
- known false function start: `1` -> `0`
- 仍需人工审计：`0x298`、`0x6BC` fail/wait 块是否提升为函数，以及 `0x27C`、`0x65C` 的 chunk/label 策略。

### 已知限制

- `BR X1 @ 0x294` 与 `BR X0 @ 0x650` 仍未解析。
- 早期函数 tail chunk 归属需要 S04 boot-flow 审计。
- 字符串中出现 Xen-like 词汇只作为字符串证据，不作为同源或最终函数名确认。

### S03 hard gate update

人工审计更新：S03 必须在进入 S04 前修复所有 IDA 可见的 bit/data/data-island 未识别问题。

这意味着：

- S03 accepted 不再允许携带结构性 code/data boundary unknown。
- `0x308-0x368`、`0x754-0x7E8` 这类 data island 必须由 S03 分类并形成 IDA data-definition proposal。
- 无法在固定约束内分类的区域必须使 S03 保持 `rework` 或 `blocked`，不能下传到 S04。
- S04 boot-slice forward-test 只能作为调测材料，不能作为生产推进依据，直到 S03-RW2 完成。

S03-RW2 当前扫描结果：

| 类别 | 数量 | 处理 |
|---|---:|---|
| `alignment_padding` | 510 | 可进入 data-definition proposal |
| `data_island_or_padding` | 470 | 可进入 data-definition proposal |
| `pointer_table_or_literal_pool` | 2 | 可进入 data-definition proposal |
| `unowned_code_gap` | 8 | 阻塞，需函数边界恢复 |
| `mixed_unowned_code_and_data` | 28 | 阻塞，需函数/子范围审计 |

当前 `ida-data-definition-proposal-rework-02.json` 包含 982 个完整 action，但 S03 仍为 `rework_required`，因为还有 36 个结构阻塞项不能通过 data-definition 自动修复。

## G02-C：S04 EL2 架构语义 Skills

### 创建结果

已创建：

- `recover-arm64-boot-flow`
- `recover-arm64-exception-model`
- `recover-arm64-context-layout`
- `recover-el2-architecture-semantics`
- `integrate-el2-architecture-model`

### IDA MCP 规则验证

只读 IDA MCP 连接被定义为 Skill 的正常分析动作，不需要单独人工确认。

写入 IDA 仍需要 reviewed proposal、人工 mutation gate 和 transaction record。

实际验证时，并行 `probe` 同一个 `.i64` 会触发 IDA database error code `4`，因此同一 IDB 的 IDA MCP 读取应串行调度。

### Boot-slice forward-test

测试范围：`0x160-0x754`

生产状态：`forward_test_deferred_by_s03_rework`，不是 S04 accepted。

当前 S03 门禁状态：

- `S03/stage-manifest.json` 状态为 `rework_required`。
- `S03-RW1`、`S03-RW2` 和部分 `S03-RW3` 已在 IDA 中写回并读回验证。
- `S03-RW4` 将剩余结构问题显式记录为 12 个 blocking `unresolved-code-data-blob`，见 `cases/xen_arm64-778090a1/stages/S03/unresolved-regions-rw4.jsonl`。
- 因此 S04 只能作为 skill/workflow forward-test，`s05_readiness` 必须为 `blocked_by_s03_rework`。

主要输出：

- `cases/xen_arm64-778090a1/stages/S04/boot-model.json`
- `cases/xen_arm64-778090a1/stages/S04/sysreg-accesses.jsonl`
- `cases/xen_arm64-778090a1/stages/S04/architecture-events.jsonl`
- `cases/xen_arm64-778090a1/stages/S04/architecture-model.json`
- `cases/xen_arm64-778090a1/stages/S04/ida-change-proposal.json`
- `cases/xen_arm64-778090a1/reports/g02-c-s04-summary.md`

验证结论：

- S04 boot/MMU/sysreg 语义可以从 target-only IDA evidence 中恢复。
- `0x160`、`0x198`、`0x238`、`0x5C4`、`0x708` 形成可解释的 boot/MMU 架构锚点。
- exception vector 与完整 context layout 未在该 slice 中恢复，必须保留 Unknown。
- S04 proposal 不得在 S03 accepted 前应用。
- `/tests/xen-syms_arm64.i64` 只允许作为调测阶段的 forward-test/oracle score，不得成为真实 S04 Skill 输入或生产 evidence。

## G03-A：S05 Runtime Object Skills

### 创建结果

已创建：

- `recover-hypervisor-cpu-vcpu-model`
- `recover-hypervisor-stage2-memory-model`
- `integrate-hypervisor-runtime-model`

### 当前验证状态

生产执行状态：`blocked_by_upstream`。

原因：

- S03 当前为 `rework_required`。
- S04 当前为 `forward_test_deferred_by_s03_rework`，且 `s05_readiness` 为 `blocked_by_s03_rework`。
- S03-RW4 仍有 12 个 blocking `unresolved-code-data-blob`，不能作为 runtime ownership 的干净输入。

因此本轮只完成 S05 Skill 契约开发，不运行 S05 实际恢复，也不生成 `S05/runtime-object-model.json`。

## G03-B：S06/S07 Domain Skills

### 创建结果

已创建 S06：

- `recover-hypervisor-vm-config`
- `recover-hypervisor-scheduler`
- `recover-hypervisor-interrupt-routing`
- `integrate-hypervisor-service-model`

已创建 S07：

- `recover-hypervisor-vm-lifecycle`
- `recover-hypervisor-hkip-model`
- `integrate-hypervisor-security-lifecycle`

### 当前验证状态

生产执行状态：`blocked_by_upstream`。

原因：

- S03-RW5 已清理 12 个 RW4 blocking blobs，但 S03 仍是 `review_required_after_rw5`，还未 accepted。
- 现有 S04 forward-test 产物是在 S03-RW5 前生成的，已标记为 stale，需要基于 RW5 后 IDB 重跑。
- S05 runtime object model 尚未基于 accepted S04 生成。

因此本轮只完成 S06/S07 Skill 契约开发，不运行真实 S06/S07 恢复。

## G02-C-RW5：S04 rerun after S03-RW5

### 验证结果

S03-RW5 清理 12 个 blocking blob 后，重新运行 S04 exception/context forward-test。

新增/更新产物：

- `cases/xen_arm64-778090a1/stages/S04/s04-rw5-vector-exception-scan.json`
- `cases/xen_arm64-778090a1/stages/S04/exception-model.json`
- `cases/xen_arm64-778090a1/stages/S04/context-layouts.jsonl`
- `cases/xen_arm64-778090a1/stages/S04/architecture-model.json`
- `cases/xen_arm64-778090a1/stages/S04/records/recover-arm64-exception-model.rw5.*.jsonl`

验证发现：

- `0x52800-0x54800` 形成 64 个 `0x80` 大小 vector slots。
- `0x56000-0x56800` 中识别出 17 个 branch veneers。
- 识别出 14 个 handler save stubs，其中多个包含 GPR pair saves 以及 `ELR_EL2`、`SPSR_EL2`、`ESR_EL2` 读取。
- S04 status 更新为 `forward_test_review_required_after_s03_rw5`。

Skill 优化：

- `recover-arm64-exception-model` 现在会消费 S03 `embedded-vector-*` 非阻塞分类。
- `recover-arm64-context-layout` 现在允许从 handler labels / embedded fragments 中提取 context-layout seed。
- `integrate-el2-architecture-model` 区分 `blocked_by_s03_rework` 与 `forward_test_review_required_after_s03_rw5`。

限制：

- S03 仍为 `review_required_after_rw5`，不是 accepted。
- S04-RW5 新模型还需要 review，因此 S05 仍不得消费为 production input。

## G04/G05：S08-S10 and Orchestrator Skills

### 创建结果

已创建 S08：

- `synthesize-hypervisor-repository`
- `generate-recovery-source-map`
- `index-recovery-evidence`

已创建 S09：

- `check-recovered-code-consistency`
- `check-hypervisor-security-invariants`
- `compute-recovery-coverage`
- `integrate-static-audit-report`

已创建 S10：

- `generate-final-recovery-report`
- `package-recovery-deliverable`

已创建 Orchestrator：

- `orchestrate-hypervisor-recovery`

当前验证状态：`blocked_by_upstream`。这些 skills 只做契约校验，真实执行需等待 S03-S07 accepted。

## G02-B/G02-C review gate update

After S03-RW5:

- S03 integrated review was generated.
- `S03/artifact-validation.json` result: `pass`.
- `S03/stage-review.json` result: `accept`.
- S03 status is now `accepted`.
- Remaining S03 uncertainties `U-S03-0001`, `U-S03-0002`, and `U-S03-0004` were downgraded to accepted-risk in `S03/accepted-risk-rw6.jsonl` because they are boot/runtime-address handoff dependencies, not program-structure blockers.

After S04-RW5:

- `S04/artifact-validation.json` result: `pass`.
- `S04/stage-review.json` result: `accept`.
- S04 status is now `accepted`.
- `U-S04-RW5-EXC-0001` remains accepted-risk: S05 may consume exception context seeds, but must not assume complete exception dispatch semantics.

## G03-A-RW1：S05 seed forward-test

With S03 and S04 accepted, S05 seed recovery was run read-only against `tests/xen_arm64.i64`.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-seed-scan.json`
- `cases/xen_arm64-778090a1/stages/S05/cpu-vcpu-model.json`
- `cases/xen_arm64-778090a1/stages/S05/stage2-memory-model.json`
- `cases/xen_arm64-778090a1/stages/S05/runtime-object-model.json`
- `cases/xen_arm64-778090a1/stages/S05/types.jsonl`
- `cases/xen_arm64-778090a1/stages/S05/resource-ownership.jsonl`

Seed scan summary:

- `TPIDR_EL2`: 2083 hits
- `MPIDR_EL1`: 3 hits
- `VTTBR_EL2`: 14 hits
- `VTCR_EL2`: 4 hits
- `HCR_EL2`: 22 hits
- `HPFAR_EL2`: 4 hits
- `FAR_EL2`: 8 hits
- `ESR_EL2`: 18 hits
- `TLBI`: 15 hits

Current S05 status: `forward_test_review_required`.

Skill optimization from this run:

- CPU/vCPU recovery must aggregate dense `TPIDR_EL2` sites by function/base/data target instead of emitting thousands of object candidates.
- Stage-2 recovery should prioritize `VTCR_EL2`/`VTTBR_EL2` clusters, use `HPFAR/FAR/ESR` as fault-path anchors, and treat `TLBI` as supporting evidence only when linked to page-table or VTTBR changes.
- S05 seed anchors do not make S06 ready; ownership/type integration is still required.

## G03-A-RW2: S05 runtime-anchor clustering

S05 was re-run as a runtime-clustering pass against `tests/xen_arm64.i64` using IDA read-only state. This pass does not use `tests/xen-syms_arm64.i64`; symbolized binaries remain validation-only and must not become production skill inputs.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-runtime-clusters-rw1.json`
- `cases/xen_arm64-778090a1/stages/S05/ida-change-proposal.json`
- `cases/xen_arm64-778090a1/stages/S05/records/*rw1*.jsonl`

Runtime cluster summary:

- 2152 sysreg/TLBI hits were grouped into 532 function clusters.
- True `HCR_EL2` was separated from `ICH_HCR_EL2`.
- `ICH_HCR_EL2` clusters were routed to S06 interrupt/vCPU-interface recovery, not Stage-2 memory recovery.
- Diagnostic-heavy fault/register-dump functions were downgraded before handler or ownership claims.

Current S05 status: `review_required_runtime_anchor_clusters`.

Current S06 gate: `blocked_until_s05_runtime_ownership_review`.

Skill optimization from this run:

- Prefer function-level runtime clusters over raw sysreg hit lists.
- Keep cluster-derived relationships as `review_only_links` until concrete dataflow or ownership evidence is recovered.
- Do not create final CPU/vCPU/VM/Stage-2 ownership links from architectural sysreg anchors alone.

## G03-A-RW3: S05 dataflow slices

S05 was advanced from runtime clustering to local dataflow slicing. The pass targeted 7 `VTTBR_EL2`/`VTCR_EL2` Stage-2 candidates, the top 8 `TPIDR_EL2` clusters, and 3 `MPIDR_EL1` CPU-affinity anchors.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-rw2-dataflow-slices.json`
- `cases/xen_arm64-778090a1/stages/S05/artifact-validation-rw2.json`
- `cases/xen_arm64-778090a1/stages/S05/ida-change-proposal-rw2.json`
- `cases/xen_arm64-778090a1/stages/S05/records/*rw2*.jsonl`

Dataflow findings:

- `0x58220`, `0x58970`, and `0x58e80` construct/write VTTBR from a root/base value shifted left by 12.
- `0x58f40` and `0x59970` look like VTTBR save/switch/restore paths and use object offset `0x28`.
- `0x58eb0` exposes a review-only offset chain `0x18 -> 0x228` that reaches the VTTBR source.
- `0x67410` was downgraded from Stage-2 root candidate to observer/diagnostic because RW2 found only `MRS VTTBR_EL2`.
- Top `TPIDR_EL2` clusters mostly use TPIDR as an index/offset in `[base, TPIDR]` accesses, so they seed per-CPU variable tables rather than final vCPU/current-context ownership.

Current S05 status: `review_required_dataflow_slices`.

Current S06 gate: `blocked_until_s05_dataflow_ownership_review`.

Skill optimization from this run:

- Slice each `MSR VTTBR_EL2, Xt` backward before claiming Stage-2 root semantics.
- Downgrade read-only VTTBR functions unless caller dataflow proves a switch/control role.
- Treat VTTBR field offsets and TPIDR-indexed variable access as review-only seeds until owner/lifetime evidence is recovered.

## G03-A-RW4: S05 owner/base traces

S05 was advanced from local dataflow slicing to caller/base-root tracing. The pass targeted Stage-2 VTTBR seed functions and top TPIDR indexed-variable clusters.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-rw3-owner-base-trace.json`
- `cases/xen_arm64-778090a1/stages/S05/artifact-validation-rw3.json`
- `cases/xen_arm64-778090a1/stages/S05/ida-change-proposal-rw3.json`
- `cases/xen_arm64-778090a1/stages/S05/records/*rw3*.jsonl`

Owner/base findings:

- `0x5d2e0` calls both `0x58e80` and `0x58eb0`, so it is promoted to a review-only Stage-2 lifetime cluster candidate.
- `0x58f40` and `0x59970` remain review-only Stage-2 switch/restore service candidates, with stable local fields `0x20`, `0x28`, and `0x41`.
- TPIDR indexed-base roots split into global-table seeds and runtime table/object-load seeds.
- No production CPU/vCPU/VM/Stage-2 ownership link was emitted.

Current S05 status: `review_required_owner_base_traces`.

Current S06 gate: `blocked_until_s05_owner_lifetime_review`.

Skill optimization from this run:

- Shared caller clusters are lifetime/service seeds, not final owner proof.
- TPIDR base-root classes must remain review-only until table identity and lifecycle are recovered.
- S06 may forward-test from these clusters, but production S06 remains gated by S05 ownership.

## G03-A-RW5: S05 lifecycle edge scan

S05 was advanced from owner/base-root tracing to lifecycle-edge tracing. The pass targeted `0x5d2e0`, the `0x58f40/0x59970` caller families, and the VTTBR seed functions.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-rw4-lifecycle-edges.json`
- `cases/xen_arm64-778090a1/stages/S05/artifact-validation-rw4.json`
- `cases/xen_arm64-778090a1/stages/S05/ida-change-proposal-rw4.json`
- `cases/xen_arm64-778090a1/stages/S05/records/*rw4*.jsonl`

Lifecycle findings:

- `0x5d2e0` writes preparation fields `0x338/0x340/0x348` and then calls the VTTBR activation path `0x58eb0`; it also calls `0x58e80`.
- `0x5a294` writes `0x18/0x20/0x28` and then calls `0x58f40` and `0x64a80`, so it becomes a review-only switch-object setup/reset edge.
- `0x58f40` and `0x59970` read `0x20/0x28` and clear `0x41`, so `0x41` is a review-only switch/state flag candidate.
- The in-target graph contains 14 edges across the Stage-2 lifecycle/service target set.
- No production owner link was emitted.

Current S05 status: `review_required_lifecycle_edges`.

Current S06 gate: `blocked_until_s05_lifecycle_owner_review`.

Skill optimization from this run:

- Lifecycle ordering and field writes improve confidence but still do not prove owner identity.
- S05 must keep lifecycle edges review-only until owner object, VMID relationship, and teardown path are connected.

## G03-A-RW6: S05 teardown scan

S05 was advanced from lifecycle-edge tracing to teardown/rollback candidate discovery. The pass watched lifecycle offsets `0x18/0x20/0x28/0x41/0x338/0x340/0x348/0x350/0x388` and Stage-2/TLBI side effects.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-rw5-teardown-scan.json`
- `cases/xen_arm64-778090a1/stages/S05/artifact-validation-rw5.json`
- `cases/xen_arm64-778090a1/stages/S05/ida-change-proposal-rw5.json`
- `cases/xen_arm64-778090a1/stages/S05/records/*rw5*.jsonl`

Teardown findings:

- 901 watched functions were scanned; 30 teardown-like candidates were found.
- Direct S05 switch cleanup remains `0x58f40` and `0x59970`, both clearing field `0x41` during VTTBR switch.
- Several high-score external candidates contain zero stores, barriers, and rollback/error/remove strings, but they are not yet argument/root matched to the `0x5d2e0` or `0x5a294` owner path.
- No symmetric setup→teardown owner closure was proven.

Current S05 status: `review_required_teardown_scan`.

Current S06 gate: `blocked_until_s05_teardown_owner_match`.

Skill optimization from this run:

- Teardown scans provide candidate discovery and negative evidence, not ownership closure.
- High teardown scores must not override missing owner identity.
- The next useful step is owner argument/root matching between setup/activation paths and teardown-like candidates.

## G03-A-RW7: S05 owner-root matching

S05 was advanced from teardown candidate discovery to owner/root matching. The pass compared setup stores in `0x5d2e0`, `0x5a294`, `0x58f40`, and `0x59970` against RW5 teardown-like candidates across lifecycle offsets `0x18/0x20/0x28/0x41/0x338/0x340/0x348/0x350/0x388`.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-rw6-owner-root-match.json`
- `cases/xen_arm64-778090a1/stages/S05/artifact-validation-rw6.json`
- `cases/xen_arm64-778090a1/stages/S05/ida-change-proposal-rw6.json`
- `cases/xen_arm64-778090a1/stages/S05/records/*rw6*.jsonl`

Owner-root findings:

- 9 setup records and 31 teardown records were compared.
- 45 weak matches were found by same offset or same lifecycle field family.
- 0 exact root-signature matches were found.
- Therefore no production `ownership_links` were emitted.

Current S05 status: `review_required_owner_root_match`.

Current S06 gate: `blocked_until_s05_owner_root_closure`.

Skill optimization from this run:

- Same offset or same lifecycle field family is only a review hint; it is not symmetric teardown proof.
- Exact root-signature matching or caller argument propagation is required before a teardown path can close ownership.
- Even exact owner/root closure should still be checked against VMID/resource identity before S06 production use.
- Forward-test oracle databases such as `tests/xen-syms_arm64.i64` may guide skill improvement during development, but must not become production evidence.

## G03-A-RW8: S05 caller argument propagation

S05 was advanced from local owner/root matching to caller argument propagation. The pass traced X0-X3 at callsites for setup targets `0x5d2e0`, `0x5a294`, `0x58f40`, and `0x59970`, then compared them against RW5 teardown-like targets.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-rw7-caller-arg-propagation.json`
- `cases/xen_arm64-778090a1/stages/S05/artifact-validation-rw7.json`
- `cases/xen_arm64-778090a1/stages/S05/ida-change-proposal-rw7.json`
- `cases/xen_arm64-778090a1/stages/S05/records/*rw7*.jsonl`

Caller argument findings:

- 11 setup callsites and 68 teardown callsites were compared.
- 17 exact caller-argument root matches were found.
- 6 weak same-caller matches were found.
- These matches are still review-only because the strongest roots are same-helper callsites, global address literals, stack reloads, or service-local switch helpers rather than proven VM/Stage-2 lifecycle owners.
- No production `ownership_links` were emitted.

Current S05 status: `review_required_caller_argument_propagation`.

Current S06 gate: `blocked_until_s05_owner_lifetime_closure`.

Skill optimization from this run:

- Caller argument matching is stronger than offset-only matching, but still needs root classification.
- Same-helper, same-caller, global-constant, address-literal, and stack-reload roots must not be promoted without lifecycle-boundary evidence.
- Oracle IDBs must first prove address/sample compatibility; if oracle names do not resolve for the target EAs, the oracle contributes no validation conclusion.

## G03-A-RW9: S05 root-class classification

S05 was advanced from caller argument propagation to root-class classification. The pass consumed `s05-rw7-caller-arg-propagation.json` and separated common roots into object-like, service-local, global/constant, stack-local, and ambiguous buckets.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S05/s05-rw8-root-classification.json`
- `cases/xen_arm64-778090a1/stages/S05/artifact-validation-rw8.json`
- `cases/xen_arm64-778090a1/stages/S05/ida-change-proposal-rw8.json`
- `cases/xen_arm64-778090a1/stages/S05/records/*rw8*.jsonl`

Root-class findings:

- 23 caller-root matches were classified.
- `object_like_count`: 0
- `service_local_count`: 13
- `global_or_constant_count`: 3
- `stack_local_count`: 1
- `ambiguous_count`: 6
- `production_ownership_ready_count`: 0

Current S05 status: `review_required_root_classification`.

Current S06 gate: `blocked_until_s05_object_like_owner_root`.

Skill optimization from this run:

- Exact caller-argument matches are not enough; root class must be object-like before lifecycle checks.
- `object_like_count == 0` is a hard S06 production block.
- Service-local, global/constant, stack-local, and ambiguous roots must remain review queues.

## G02-B-RW9: S03 data-island point visibility

Manual IDA review reported that previously discussed addresses `0x308` and `0x760` still appeared unfixed in `tests/xen_arm64.i64`.

Readback findings:

- `0x308` is a data item head: `qword_308`, range `0x308-0x310`, `is_data=true`, `is_unknown=false`.
- `0x760` is not an independent head. It is a tail inside the owning item `0x75c-0x764`, displayed by IDA as `DCQ 0x20000000000000`.
- Therefore the structural boundary was mostly fixed, but S03 validation missed a human-visibility requirement: reported addresses that land inside data item tails need explicit owning-head mapping and visible classification comments.

Applied local IDA fix:

- `cases/xen_arm64-778090a1/stages/S03/s03-rw9-point-visibility-audit.json`
- `cases/xen_arm64-778090a1/stages/S03/ida-transaction-s03-rw9-point-visibility-20260625.json`

Skill optimization from this run:

- `is_unknown=false` is not enough to claim a reported data-island point is fixed.
- Data-island readback must include `item_head`, `item_end`, head/tail status, classification, and visible IDA comment/name.
- Tail addresses in literal pools should be explained as part of their owning item, not reclassified as unresolved code/data.

## G02-B-RW10: S03 text-middle code-first correction

Manual workflow correction: for this target, the main `.text` body should be recovered as assembly as far as possible. Except for binary header/tail appendices or clearly external non-text ranges, middle `.text` should not remain as `DCQ`/`DCD`/`qword` data islands.

Actions applied to `tests/xen_arm64.i64`:

- Scanned `.text` data items under a code-first policy.
- Split prior data items into 4-byte words.
- Converted decodable words into ARM64 code.
- Converted undecodable words into explicit `.inst`/`instruction_fallback` blockers instead of qword data islands.

New artifacts:

- `cases/xen_arm64-778090a1/stages/S03/s03-rw10-text-data-codefirst-dryrun.json`
- `cases/xen_arm64-778090a1/stages/S03/s03-rw10-text-codefirst-apply.json`
- `cases/xen_arm64-778090a1/stages/S03/s03-rw10-inst-fallback-visibility.json`
- `cases/xen_arm64-778090a1/stages/S03/artifact-validation-rw10.json`
- `cases/xen_arm64-778090a1/stages/S03/unresolved-regions-rw10.jsonl`
- `cases/xen_arm64-778090a1/stages/S03/ida-transaction-s03-rw10-text-codefirst-20260625.json`

Readback highlights:

- `0x308` is now an ARM64 code item.
- `0x760` is now an ARM64 code item.
- 9010 decodable words were converted to code.
- 181302 undecodable words remain as `.inst` fallback blockers.

Superseded current S03 status after S03-RW14: `accepted` with `accepted-risk-rw14.jsonl`.

Downstream impact:

- Previous S03 `accepted` state is invalidated by this stricter policy.
- S04/S05 artifacts produced from the previous S03 acceptance are stale until S03-RW10 is reviewed.

Skill optimization from this run:

- S03 must be code-first for the main `.text` body.
- `literal_pool`, `pointer_table`, and `constant_table` are no longer acceptable default explanations for middle `.text`.
- `.inst` fallback is assembly recovery evidence, but it is not automatically accepted; it must be counted and reviewed.

## G02-B-RW11: Oracle mapping to `xen-syms_arm64.i64`

After manual IDA repair, `tests/xen_arm64.i64` was mapped against `tests/xen-syms_arm64.i64` as a validation-only oracle.

New artifacts:

- `validation/oracle/xen_arm64-to-xen-syms-map.json`
- `validation/oracle/oracle-match-report.json`
- `validation/oracle/oracle-name-diff.json`

Mapping summary:

- Target functions: 2047
- Oracle functions: 2227
- Oracle named functions: 2201
- Total matches: 1921
- High-confidence matches: 1790
- High-confidence matches with oracle names: 1787
- Dominant address delta: `0xa0000200000`
- Main match kind: `full_function_hash_size`

Boundary rule:

- Oracle mapping is validation-only. It may be used to measure skill/workflow error and choose rework priorities.
- Oracle names must not be imported into production `functions.jsonl`, IDA names, evidence IDs, or accepted Stage conclusions.
## G02-B/S03-RW12-RW13 oracle-assisted `.inst` fallback repair

本节记录一次调测闭环：`tests/xen-syms_arm64.i64` 被当作 validation-only oracle，用来修复 `tests/xen_arm64.i64` 中 S03 阶段剩余的 `.inst fallback` / bit-data 可见性问题。

边界声明：

- 该 oracle 只用于本地测试、workflow/skill 调优和 IDB 读回验证。
- 真实逆向场景仍然只有无符号目标二进制和 IDA；不得把 oracle 名称、符号表或源码关系固化进生产 Skill。
- 本次允许对 `tests/xen_arm64.i64` 进行 oracle-assisted repair，是用户明确授权的 lab 修复动作。

核心产物：

- `validation/oracle/xen_arm64-to-xen-syms-map.json`
- `validation/oracle/oracle-match-report.json`
- `validation/oracle/oracle-word-state-diff.json`
- `cases/xen_arm64-778090a1/stages/S03/s03-rw12-oracle-assisted-repair.json`
- `cases/xen_arm64-778090a1/stages/S03/s03-rw13-oracle-code-candidates-apply.json`
- `cases/xen_arm64-778090a1/stages/S03/artifact-validation-rw13.json`

Oracle map 摘要：

| 指标 | 值 |
|---|---:|
| target functions | 2047 |
| oracle functions | 2227 |
| total matches | 1921 |
| high-confidence matches | 1790 |
| named high-confidence matches | 1787 |
| dominant address delta | `0xa0000200000` |

RW12 结果：

| 指标 | 值 |
|---|---:|
| functions considered | 2225 |
| functions created | 31 |
| functions existing | 2081 |
| created code words | 6988 |
| fallback words fixed or covered | 12672 |
| oracle comments | 1954 |

RW13 收敛结果：

| 轮次 | oracle-code candidates | created code words | already code words | failed |
|---:|---:|---:|---:|---:|
| 1 | 2286 | 2065 | 221 | 0 |
| 2 | 232 | 12 | 220 | 0 |
| 3 | 8 | 6 | 2 | 0 |

第三轮读回后，`validation/oracle/oracle-word-state-diff.json` 仍保留 6 个 residual oracle-code candidates：

| target | oracle | oracle function |
|---:|---:|---|
| `0x2c8` | `0xa00002002c8` | `efi_xen_start` |
| `0x1d708` | `0xa000021d708` | `offline_page` |
| `0x67854` | `0xa0000267854` | `do_bug_frame` |
| `0xb7a30` | `0xa00002b7a30` | `setup_pagetables` |
| `0xb7f54` | `0xa00002b7f54` |  |
| `0xc0c90` | `0xa00002c0c90` | `start_xen` |

当前状态：

- S03-RW14 根据用户决策将这 6 个 residual 转为 explicit `accepted-risk`，S03 状态推进为 `accepted`。
- 进入 S04/S05 时必须携带 `S03/accepted-risk-rw14.jsonl` provenance；任何直接依赖这些地址的结论仍需降级为 `inferred` 或 `unresolved`。
- 本次最后的 targeted IDA inspect 被工具状态阻塞：`idat` batch 返回 `License not yet accepted, cannot run in batch mode`，IDA MCP 返回 `Transport closed`。

回灌到 Skill/Workflow 的经验：

- `recover-ida-functions` 增加 validation-only oracle convergence check 规则。
- `recover-binary-data-objects` 增加 oracle-assisted `.inst fallback` repair 收敛规则。
- `workflow.md` 增加 S03 forward-test oracle addendum。

S03-RW14 downstream sync：

- `cases/xen_arm64-778090a1/stages/S03/stage-manifest.json` 状态为 `accepted`，但包含 `residual_policy.status = accepted-risk`。
- `cases/xen_arm64-778090a1/stages/S04/stage-manifest.json` 保持 `accepted`，`s05_readiness = ready_with_accepted_risks`。
- `cases/xen_arm64-778090a1/stages/S05/stage-manifest.json` 不再被 S03 residual 阻塞；当前活动 gate 仍是 S05 自身的 `blocked_until_s05_object_like_owner_root`。
