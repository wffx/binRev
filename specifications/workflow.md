# AI Native ARM64 EL2 Hypervisor 逆向恢复工作流

本文档定义规范性 Workflow。实现脚本、IDA 数据库和具体 Skill 都必须服从该 Workflow，不能反向决定流程。

详细 Skill 职责见 [skill-architecture.md](skill-architecture.md)，Artifact 字段和目录契约见 [artifact-contracts.md](contracts/artifact-contracts.md)。

## 1. 设计原则

### 1.1 Workflow、Stage、Skill、Artifact 分层

- **Workflow**：维护全局状态、Stage 顺序、门禁和回退。
- **Stage**：定义一次有边界的状态转换，只描述目标、输入、输出和验收。
- **Skill**：执行 Stage 内的专业任务；一个 Stage 可以调用一个或多个 Skill。
- **Artifact**：Skill 间唯一允许的交接介质，必须落盘、版本化并带来源。

AI 不得依赖聊天记忆、未落盘推断或其他 Skill 的隐式上下文。任何会影响后续结论的信息都必须写入 Artifact。

### 1.2 固定约束

- 唯一案例输入是一个 little-endian ARM64 boot executable `Image`。
- 样本特定知识只有文件格式与 Hypervisor 业务背景。
- 外部逆向工具只有 IDA；允许 IDAPython，Hex-Rays 可选。
- 不使用外部源码、符号、日志、DTB、平台资料、动态环境或其他逆向工具。
- Skill 可携带通用 ARM64/EL2、Image 格式和逆向方法知识，但不得携带目标特定源码或签名库。
- 交付是静态恢复代码仓和证据，不承诺可编译、可运行、行为等价或安全证明。

### 1.3 Stage 状态机

每个 Stage 只能处于以下状态：

```text
pending -> in_progress -> review_required -> accepted
                          |                  |
                          v                  v
                        rework <---------- rework

in_progress/review_required -> blocked
```

- `accepted`：满足 Stage 出口，可以进入下一 Stage。
- `rework`：输出存在可修正问题，回到当前或上游 Stage。
- `blocked`：缺少当前约束下不可获得的必要证据；必须保留未知项，不能猜测补齐。
- 未知项可以非阻塞；只有破坏下游前提的未知项才阻止 Stage 接受。

### 1.4 通用 Stage 门禁

每个 Stage 接受前必须同时满足：

1. 所有必需输入通过 schema、case ID 和 Image SHA-256 校验。
2. 所有必需输出存在且通过 schema 校验。
3. 每个结论引用 Evidence ID。
4. 每个未知项写入 Unknown Registry。
5. 所有 IDA 修改存在 proposal、review 和 transaction record。
6. Reviewer Skill 已产生 `stage-review.json`。
7. Orchestrator 已更新 `workflow-state.json`。

每个 Stage 和 Skill 还有三个全局必需输入，不在后续表格中重复：

- `stages/S00/case-manifest.json`
- `stages/S00/constraint-profile.json`
- `workflow/workflow-state.json`

每个 Stage 还必须产生以下公共输出，不在各 Stage 表格中重复：

| Artifact | Owner Skill |
|---|---|
| `Sxx/stage-manifest.json` | `orchestrate-hypervisor-recovery` |
| `Sxx/artifact-validation.json` | `validate-artifact-contract` |
| `Sxx/stage-review.json` | `review-stage-output` |
| `Sxx/records/<producer>.evidence.jsonl` | 对应 Producer Skill；文件必须存在，可为空 |
| `Sxx/records/<producer>.decisions.jsonl` | 对应 Producer Skill；文件必须存在，可为空 |
| `Sxx/records/<producer>.unknowns.jsonl` | 对应 Producer Skill；文件必须存在，可为空 |
| `Sxx/evidence-index.json` | 当前 Stage 的 Integration Skill；无 Integration Skill 时由 Orchestrator 生成 |
| `Sxx/decision-index.json` | 当前 Stage 的 Integration Skill；无 Integration Skill 时由 Orchestrator 生成 |
| `Sxx/unknown-index.json` | 当前 Stage 的 Integration Skill；无 Integration Skill 时由 Orchestrator 生成 |

### 1.5 Stage Contract 强制模板

每个 Stage 必须按以下顺序定义，缺少任何一项即视为合同不完整：

```text
### 目标
### 输入
### 产物
### Skill 路由编排
### 退出条件
### 边界
```

- **目标**：只描述本 Stage 完成的一次状态转换。
- **输入**：列出具体 Artifact 路径、版本要求和 accepted checkpoint；不得只写“上游结果”。
- **产物**：列出具体路径、内容和唯一 Owner Skill。
- **Skill 路由编排**：明确串行、并行、依赖、Integration、Review、人工门禁、IDA commit 和 checkpoint。
- **退出条件**：分别定义 `accepted`、`rework`、`blocked`。
- **边界**：明确不属于本 Stage 的分析、禁止证据、禁止工具和不可声明的结论。

## 2. 全局 Workflow

| Stage | 名称 | 执行 Skill 数 | 主要出口 |
|---|---|---:|---|
| S00 | Case 初始化与边界锁定 | 2 | Case manifest、constraint profile |
| S01 | Image 格式与内容布局 | 2 | Image layout、region map、内嵌候选 |
| S02 | IDA 基线与地址空间 | 3 | IDA baseline、address-space decision |
| S03 | 程序结构恢复 | 4 | Function/data model、call graph、unresolved regions |
| S04 | ARM64 EL2 架构语义 | 5 | Boot/exception/context/architecture model |
| S05 | 运行时基础对象模型 | 3 | CPU/vCPU model、Stage-2 memory model |
| S06 | VM 服务模型 | 4 | VM config、scheduler、interrupt model |
| S07 | 生命周期与 HKIP | 3 | Lifecycle model、HKIP model、resource transitions |
| S08 | 静态代码仓合成 | 3 | Recovered repository、source map、recovery index |
| S09 | 静态一致性与安全审计 | 4 | Consistency audit、security findings、coverage |
| S10 | 收敛与交付 | 2 | Delivery manifest、final report、final unknown registry |

`review-stage-output` 是所有 Stage 的公共 Reviewer Skill，不计入上表的专业 Skill 数。

## 3. Stage 定义

## S00：Case 初始化与边界锁定

### 目标

建立唯一 Case 身份，锁定输入、允许知识、工具和禁止假设。

### 输入

| Artifact | 要求 |
|---|---|
| `input/Image` | 唯一用户输入文件 |
| `case-request.json` | 只含格式、字节序和业务背景 |

### 产物

| Artifact | 内容 |
|---|---|
| `S00/case-manifest.json` | Case ID、Image SHA-256、大小、路径 |
| `S00/constraint-profile.json` | 允许/禁止输入、工具和结论 |
| `workflow/workflow-state.json` | 初始 Stage 状态 |
| `S00/records/initialize-hypervisor-recovery-case.evidence.jsonl` | 输入哈希与已知事实 |
| `S00/records/enforce-recovery-constraints.unknowns.jsonl` | 初始未知项 |

### Skill 路由编排

```text
initialize-hypervisor-recovery-case
  -> enforce-recovery-constraints
  -> validate-artifact-contract
  -> review-stage-output
  -> human gate
  -> orchestrate-hypervisor-recovery
```

- `initialize-hypervisor-recovery-case` 固化文件、哈希和 Case ID。
- `enforce-recovery-constraints` 只能读取 Case manifest 与原始请求。
- 两个 Producer 串行执行，避免约束绑定到未固定的 Case。
- 本 Stage 不调用 IDA。

### 退出条件

- **accepted**：唯一输入 SHA-256 固定；约束声明完整；Review 建议 `accept`；人工门禁通过。
- **rework**：请求字段超出允许背景、哈希/路径不一致或约束缺项。
- **blocked**：输入不可读、不是单一文件，或用户要求保留与固定边界冲突的外部输入。

### 边界

- 只建立 Case，不解析 Image 内容和业务实现。
- 不得解析业务实现。
- 不得引入第二个样本或外部目标知识。
- 不得把业务背景标为二进制事实。
- 不启动 IDA，不创建函数，不生成代码仓。

## S01：Image 格式与内容布局

### 目标

仅根据 `Image` 本身恢复文件头、区域和内嵌对象候选。

### 输入

- `S00/case-manifest.json`
- `S00/constraint-profile.json`
- `input/Image`

### 产物

| Artifact | 内容 |
|---|---|
| `S01/image-header.json` | ARM64 Image 头字段及校验 |
| `S01/region-map.json` | 文件偏移范围、区域类别、置信度 |
| `S01/embedded-candidates.json` | 内嵌 DTB/压缩/配置/签名候选 |
| `S01/string-index.jsonl` | 字符串及文件偏移 |
| `S01/records/analyze-arm64-image-layout.evidence.jsonl` | magic、熵、头部和边界观察 |
| `S01/records/classify-binary-regions.unknowns.jsonl` | 无法分类区域 |

### Skill 路由编排

```text
analyze-arm64-image-layout
  -> classify-binary-regions
  -> validate-artifact-contract
  -> review-stage-output
  -> orchestrate-hypervisor-recovery
```

- Header 与内嵌候选必须先完成，region classifier 才能运行。
- 本 Stage 为只读分析，不调用 IDA。
- Reviewer 检查每个文件字节是否被 region map 覆盖。

### 退出条件

- **accepted**：每个字节属于一个已知或 `unknown` region；header 和 region map 无重叠/空洞错误。
- **rework**：边界重叠、遗漏字节、文件大小与记录不一致，或候选对象缺少结构证据。
- **blocked**：文件头无法读取且无法以 raw payload 继续分类。

### 边界

- 只描述文件偏移和字节特征，不推断加载虚拟地址。
- 内嵌 DTB/压缩/配置/签名只能标为 candidate，除非结构完整校验。
- 高熵不等于加密/压缩，字符串不等于业务事实。
- 不创建 IDA 数据库，不命名函数。

## S02：IDA 基线与地址空间

### 目标

在 IDA 中建立可追溯基线，确认或保留 Image base、entry 和 segment 候选。

### 输入

- `S01/image-header.json`
- `S01/region-map.json`
- `S01/embedded-candidates.json`
- `S01/evidence-index.json`
- `S01/unknown-index.json`
- `input/Image`

### 产物

| Artifact | 内容 |
|---|---|
| `S02/ida-baseline.i64` | 未加入业务语义的 IDA 基线 |
| `S02/ida-baseline-snapshot.json` | segment、function、xref、处理器信息 |
| `S02/address-space.json` | base/entry/segment 候选与结论 |
| `S02/ida-change-transactions.jsonl` | 已执行 IDA 变更 |
| `S02/records/resolve-arm64-load-address.evidence.jsonl` | ADRP、branch、pointer、vector 证据 |
| `S02/records/resolve-arm64-load-address.decisions.jsonl` | base/entry 候选决定 |
| `S02/records/resolve-arm64-load-address.unknowns.jsonl` | 未决地址与 segment |

### Skill 路由编排

```text
prepare-ida-image-database
  -> resolve-arm64-load-address
       -> [candidate iteration if needed]
  -> review-stage-output
  -> human base/entry gate
  -> apply-reviewed-ida-changes
  -> snapshot-ida-analysis-state
  -> validate-artifact-contract
  -> orchestrate-hypervisor-recovery
```

- IDA database 创建与 load-address 分析串行。
- 多个 base candidate 使用独立临时数据库或可回滚 snapshot，禁止在同一状态上叠加。
- 只有人工审核后的 address-space decision 可写入基线。
- Snapshot 是本 Stage 最后一个 Producer 动作。

### 退出条件

- **accepted**：processor/endianness 确认；base 为 `confirmed` 或可供下游显式传播的候选集合；IDA baseline 可重载。
- **rework**：xref 大量越界、候选 base 评分证据冲突、entry 不可解释或 segment 与 S01 冲突。
- **blocked**：没有任何候选地址空间可产生稳定反汇编；此时保留 raw-offset 模式并停止依赖虚拟地址的下游 Stage。

### 边界

- 仅建立地址空间和中性 IDA baseline，不加入业务函数名或安全语义。
- IDA 是唯一外部工具；Hex-Rays 输出不能作为 base 的唯一证据。
- 所有 IDA 修改必须经过 proposal/review/transaction。
- 不能因为 ARM64 Image 头存在就假设 Linux 内核虚拟地址布局。

## S03：程序结构恢复

### 目标

恢复代码/数据边界、函数、调用图、跳转表、函数指针和未决区域。

### 输入

- `S02/ida-baseline.i64`
- `S02/ida-baseline-snapshot.json`
- `S02/address-space.json`
- `S01/region-map.json`
- `S01/evidence-index.json`
- `S01/unknown-index.json`
- `S02/evidence-index.json`
- `S02/decision-index.json`
- `S02/unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S03/program-model.json` | 统一程序结构模型 |
| `S03/functions.jsonl` | 函数边界、置信度、调用关系 |
| `S03/data-objects.jsonl` | 表、数组、字符串、状态对象候选 |
| `S03/data-islands.jsonl` | 仅限 header/tail/明确非 text 区的外部数据、alignment/padding、嵌入 blob；主 `.text` 中间不得默认保留 literal pool/qword |
| `S03/code-data-boundary-audit.json` | 全量 code/data/bit 未识别区域审计、text code-first 审计和剩余阻塞项 |
| `S03/call-graph.json` | 直接调用图 |
| `S03/indirect-targets.jsonl` | 间接调用/跳转候选 |
| `S03/unresolved-regions.jsonl` | 未解析代码/数据区域，包括 `.text` 中不可解码的 `instruction_fallback` |
| `S03/branch-sample.json` | 至少一个代表性函数分支样本，包含 root、范围、节点、直接边、间接边和选择理由 |
| `S03/ida-stage.i64` | Stage 接受时的 IDA checkpoint |
| `S03/records/<producer>.*.jsonl` | 四个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
                     +-> recover-ida-functions --------+
S02 accepted IDA ----+                                  |
                     +-> recover-binary-data-objects ---+-> recover-indirect-control-flow
                                                        -> integrate-program-structure
                                                        -> branch-sample validation
                                                        -> review-stage-output
                                                        -> human structure gate
                                                        -> apply-reviewed-ida-changes
                                                        -> snapshot-ida-analysis-state
                                                        -> validate-artifact-contract
                                                        -> orchestrate-hypervisor-recovery
```

- Function 与 data-object Worker 可并行，均从同一 accepted S02 snapshot 开始。
- `recover-binary-data-objects` 必须执行全量 code/data boundary 扫描，覆盖 IDA 中所有 code-bearing segment 内的未识别 bit/data、literal pool、pointer table、constant table、alignment/padding 和嵌入数据岛。
- 对主 `.text` body 执行 code-first 策略：除 binary header/tail appendix 或明确非 text 区外，中间区域不得以 `DCQ`/`DCD`/`qword` data island 作为最终状态。可解码 4-byte word 必须恢复为 ARM64 code；不可解码 word 必须成为 `.inst`/`instruction_fallback` blocker，或经过显式人工审核后作为 accepted-risk。
- Indirect-control-flow Skill 等待函数边界与 data-island/data-object 候选输出。
- Integration Skill 解决 code/data 冲突并产生唯一 program model。
- S03 必须至少选择一个代表性函数分支样本，而不是只验证孤立函数命名。
- S03 必须通过 `code-data-boundary-audit`；所有 IDA 可见 bit/data 无法识别问题必须修复为已分类 data/code/padding/blob，或使 S03 停在 `rework/blocked`，不得带入 S04。
- S03 的 `code-data-boundary-audit` 必须报告 `.text` 中 qword/data item 数量、已恢复 code word 数量和 `.inst fallback` 数量。只要存在未审核 `.inst fallback` 或中间 `.text` data island，S03 不得 accepted。
- 对用户报告或抽样的 data-island 地址，S03 必须做 point-level readback：若地址是 data item tail，产物必须记录 owning `item_head/item_end`、分类和 head 上的可读注释/名称。`is_unknown=false` 不能单独作为“已修复”的验收依据。
- 若调测阶段存在符号 oracle 或 symbolized IDB，比对报告必须放在 `validation/oracle/` 或 validation/forward-test 区域，并且所有映射标记为 `validation_only`；oracle 名称不得进入 S03 正式 functions/data/call graph 证据。
- IDA 变更只在集成模型通过 Review 后提交。

### 退出条件

- **accepted**：可达直接代码形成调用图；函数边界和 code/data 边界冲突已消解；主 `.text` body 已按 code-first 策略恢复为 ARM64 code 或经审核的 `.inst` fallback；所有 IDA 可见 bit/data/data-island 未识别问题已结构化分类并形成已审核/已应用的 IDA proposal；用户报告/抽样 data-island 点具备 head/tail readback 解释；间接目标有候选集或 Unknown；至少一个代表性函数分支通过边界质量审计。
- **rework**：函数重叠、数据被误识别为代码、代码被误识别为数据、literal pool/pointer table/constant table/alignment 未分类、jump table 破坏 CFG、代表性函数分支出现 false function start / boundary miss / merged functions，或 accepted address-space 被新证据否定。
- **blocked**：entry/主要可达代码无法建立稳定边界，或存在当前约束下无法分类的 bit/data/code-data 区域，导致 S04 无法获得干净程序结构输入。

### 边界

- 只恢复程序结构，不赋予 CPU/VM/调度/HKIP 等业务语义。
- 不允许“所有 branch target 即函数”或用反编译美观度决定边界。
- 间接调用不能被忽略；无法解析时必须进入 Unknown Registry。
- S03 的 Unknown 不能用来绕过 bit/data 修复门禁；会污染 S04/S05 的 code/data boundary unknown 必须阻塞或 rework。
- Worker 不能直接修改共享 IDA baseline。
- IDA 写回成功不是 S03 接受条件；必须有分支级结构质量证据。
- forward-test oracle 是调测验证材料，不得污染真实目标的 functions/data/call graph 证据，也不得成为生产 workflow 的必需输入。

## S04：ARM64 EL2 架构语义

### 目标

恢复启动、异常、上下文、系统寄存器和同步原语，不使用高级业务名称污染基础模型。

### 输入

- `S02/address-space.json`
- `S03/stage-manifest.json`
- `S03/program-model.json`
- `S03/functions.jsonl`
- `S03/data-objects.jsonl`
- `S03/data-islands.jsonl`
- `S03/code-data-boundary-audit.json`
- `S03/call-graph.json`
- `S03/indirect-targets.jsonl`
- `S03/unresolved-regions.jsonl`
- `S03/unresolved-regions*.jsonl`
- `S03/ida-stage.i64`
- `S03/evidence-index.json`
- `S03/decision-index.json`
- `S03/unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S04/boot-model.json` | entry、初始化、secondary CPU 路径 |
| `S04/exception-model.json` | vector slot、handler、dispatch、return |
| `S04/context-layouts.jsonl` | trap/vCPU/per-CPU 字段偏移候选 |
| `S04/sysreg-accesses.jsonl` | MRS/MSR 位置和语义 |
| `S04/architecture-events.jsonl` | HVC/SMC/ERET/TLBI/barrier/wait |
| `S04/architecture-model.json` | 上述模型的集成索引 |
| `S04/ida-stage.i64` | 架构语义 checkpoint |
| `S04/records/<producer>.*.jsonl` | 五个 Producer 的 Evidence、Decision、Unknown 分片 |

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
- 集成后才允许写入 IDA 架构名称、类型和注释。
- S04 入口必须先读取 `S03/stage-manifest.json` 与所有 `S03/unresolved-regions*.jsonl`；若 S03 不是 `accepted`，或仍存在 `blocking: true` 的 code/data/blob unresolved，S04 只能作为 `forward_test_deferred_by_s03_rework` 运行。
- forward-test S04 可以产生证据和 proposal 用于调测 workflow，但不得生成 accepted `S04/ida-stage.i64`，不得将 `s05_readiness` 标为 ready。

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

## S05：运行时基础对象模型

### 目标

恢复 CPU/vCPU 与 Stage-2 memory 两个基础模型，并建立对象所有权关系。

### 输入

- `S03/stage-manifest.json`
- `S03/program-model.json`
- `S03/functions.jsonl`
- `S03/data-objects.jsonl`
- `S03/indirect-targets.jsonl`
- `S03/unresolved-regions*.jsonl`
- `S04/stage-manifest.json`
- `S04/architecture-model.json`
- `S04/context-layouts.jsonl`
- `S04/sysreg-accesses.jsonl`
- `S04/architecture-events.jsonl`
- `S04/ida-stage.i64`
- `S03/evidence-index.json`、`decision-index.json`、`unknown-index.json`
- `S04/evidence-index.json`、`decision-index.json`、`unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S05/cpu-vcpu-model.json` | CPU、per-CPU、vCPU、context ownership |
| `S05/stage2-memory-model.json` | VMID、VTTBR、descriptor、map/unmap/protect |
| `S05/runtime-object-model.json` | CPU/vCPU/memory 的交叉关系 |
| `S05/types.jsonl` | 结构、字段和 enum 候选 |
| `S05/resource-ownership.jsonl` | 对象所有权与共享关系 |
| `S05/ida-stage.i64` | 运行时基础模型 checkpoint |
| `S05/records/<producer>.*.jsonl` | 三个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
S03 program + S04 architecture
  +-> recover-hypervisor-cpu-vcpu-model ------+
  +-> recover-hypervisor-stage2-memory-model -+-> integrate-hypervisor-runtime-model
                                                -> review-stage-output
                                                -> human ownership/type gate
                                                -> apply-reviewed-ida-changes
                                                -> snapshot-ida-analysis-state
                                                -> validate-artifact-contract
                                                -> orchestrate-hypervisor-recovery
```

- CPU/vCPU 与 Stage-2 Worker 并行，使用同一 S04 checkpoint。
- 两个 Worker 不读取彼此草稿，避免循环推断。
- Integration Skill 负责统一 VM、vCPU、CPU、VMID、page ownership 引用。
- 安全关键类型与 ownership 需要人工门禁。
- S05 入口必须确认 S03 与 S04 均为 `accepted`；若 S04 为 `forward_test_deferred_by_s03_rework` 或 `s05_readiness.status != ready`，S05 只能输出 `blocked_by_upstream`，不得产生 S06 可消费模型。
- S05 不得使用 S03 blocking unresolved blob 内的片段确认 CPU/vCPU、VMID、Stage-2 root 或 page ownership。
- S05 必须区分 teardown candidate discovery 与 owner closure。teardown/rollback/free/remove/unmap-like 函数只能作为候选；只有 setup/activate 与 teardown 路径能通过 exact root signature 或 caller argument propagation 指向同一 owner 对象时，才允许考虑生成 S06 可消费 ownership。
- 若只有相同 offset、相同 lifecycle field family、zero-store、barrier、TLBI 或 rollback 字符串，而没有共同 root，则状态必须保持 `review_required_owner_root_match`，并将 S06 gate 设为 `blocked_until_s05_owner_root_closure`。
- 若 caller argument propagation 出现共同 root，但 root 属于全局常量、地址字面量、栈重载、同一 helper callsite 或 service-local switch helper，状态必须保持 `review_required_caller_argument_propagation`；只有 object-like root 继续通过 VMID/resource identity 与 lifecycle-boundary 检查后，才能进入 S06-ready ownership。
- S05 integration 必须输出 root-class 统计；当 `object_like_count == 0` 时，S06 gate 固定为 `blocked_until_s05_object_like_owner_root`，不得由 exact caller match 数量、score 或同 caller 关系覆盖。

### 退出条件

- **accepted**：CPU/vCPU 和 Stage-2 模型均存在；交叉引用一致；setup/activate/teardown 的 owner-root 闭合已证明或不影响下游消费；无法确定关系已登记 Unknown。
- **rework**：context owner、VMID、页所有权或 descriptor 解释冲突；新证据否定 S04 context。
- **blocked**：无法识别 vCPU/context 或 Stage-2 根对象，导致 S06 无法关联服务对象；setup/teardown 只有 weak owner-root match、service-local caller argument match，或 root classification 中无 object-like root，导致资源生命周期无法闭合；或上游 S03/S04 未 accepted，导致 runtime ownership 无法安全建立。

### 边界

- 只恢复运行时基础对象和 ownership，不恢复调度策略、VM 配置格式、IRQ route 或生命周期名称。
- 不得用业务背景直接命名结构字段。
- 具体页表粒度、VMID 位宽和 descriptor 含义必须有指令证据。
- 两个并行 Worker 不能互相强化未经集成验证的假设。

## S06：VM 服务模型

### 目标

在基础对象模型之上恢复 VM 配置、共核调度和中断虚拟化/直通。

### 输入

- `S05/runtime-object-model.json`
- `S05/types.jsonl`
- `S05/resource-ownership.jsonl`
- `S05/cpu-vcpu-model.json`
- `S05/stage2-memory-model.json`
- `S03/program-model.json`
- `S03/call-graph.json`
- `S04/architecture-model.json`
- `S04/context-layouts.jsonl`
- `S04/architecture-events.jsonl`
- `S05/ida-stage.i64`
- `S05/evidence-index.json`、`decision-index.json`、`unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S06/vm-config-model.json` | 内嵌 VM/vCPU/memory/device/IRQ 配置候选 |
| `S06/scheduler-model.json` | runqueue、状态、迁移、world switch |
| `S06/interrupt-model.json` | physical IRQ、vIRQ、VM/vCPU route |
| `S06/service-model.json` | 三类服务的统一对象关系 |
| `S06/state-machines.jsonl` | 调度与中断状态候选 |
| `S06/ida-stage.i64` | VM 服务 checkpoint |
| `S06/records/<producer>.*.jsonl` | 四个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
S05 runtime model
  +-> recover-hypervisor-vm-config -----------+
  +-> recover-hypervisor-scheduler -----------+-> integrate-hypervisor-service-model
  +-> recover-hypervisor-interrupt-routing ---+   -> review-stage-output
                                                   -> human service-model gate
                                                   -> apply-reviewed-ida-changes
                                                   -> snapshot-ida-analysis-state
                                                   -> validate-artifact-contract
                                                   -> orchestrate-hypervisor-recovery
```

- 三个 Worker 并行，只读取 accepted runtime model。
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

## S07：生命周期与 HKIP

### 目标

恢复资源生命周期、错误回滚和 HKIP 保护状态，并整合跨子系统转换。

### 输入

- `S05/runtime-object-model.json`
- `S05/resource-ownership.jsonl`
- `S05/types.jsonl`
- `S06/service-model.json`
- `S06/vm-config-model.json`
- `S06/scheduler-model.json`
- `S06/interrupt-model.json`
- `S06/state-machines.jsonl`
- `S04/architecture-model.json`
- `S04/architecture-events.jsonl`
- `S06/ida-stage.i64`
- `S05/evidence-index.json`、`decision-index.json`、`unknown-index.json`
- `S06/evidence-index.json`、`decision-index.json`、`unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S07/lifecycle-model.json` | create/load/start/pause/reset/destroy 候选 |
| `S07/hkip-model.json` | 保护对象、权限变化、校验与 violation path |
| `S07/resource-transitions.jsonl` | VMID/page/IRQ/CPU binding 生命周期 |
| `S07/security-lifecycle-model.json` | 生命周期与 HKIP 的集成模型 |
| `S07/ida-stage.i64` | 生命周期/HKIP checkpoint |
| `S07/records/<producer>.*.jsonl` | 三个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
S05 runtime + S06 service + S04 architecture
  +-> recover-hypervisor-vm-lifecycle -+
  +-> recover-hypervisor-hkip-model ----+-> integrate-hypervisor-security-lifecycle
                                          -> review-stage-output
                                          -> human lifecycle/HKIP gate
                                          -> apply-reviewed-ida-changes
                                          -> snapshot-ida-analysis-state
                                          -> validate-artifact-contract
                                          -> orchestrate-hypervisor-recovery
```

- Lifecycle 与 HKIP Worker 可并行读取 accepted models。
- 集成时必须交叉检查 page、VMID、IRQ、CPU binding 与权限状态。
- Worker 输出状态候选，Integration 才能建立跨子系统 transition。
- 人工门禁确认 HKIP 保护对象、violation path 和资源终止状态。

### 退出条件

- **accepted**：生命周期与 HKIP 模型完成或显式 unknown；正常/回滚路径均纳入；资源转换无未解释冲突。
- **rework**：状态转换矛盾、资源泄漏模型与 S05/S06 冲突、HKIP 仅由算法相似性支持。
- **blocked**：无法识别任何资源状态写入或权限变化路径，导致 S09 核心安全审计无对象。

### 边界

- 无证据的状态名称必须使用 `state_0xN`。
- HKIP 不能仅凭 hash/checksum、只读常量或业务背景确认。
- 本 Stage 描述静态状态转换，不声称运行时一定发生。
- 不能把“未发现释放路径”直接判定为漏洞；该结论属于 S09。

## S08：静态代码仓合成

### 目标

将 accepted 模型合成为静态恢复代码仓，不添加模型之外的新业务事实。

### 输入

- `S03/program-model.json`
- `S04/architecture-model.json`
- `S05/runtime-object-model.json`
- `S05/types.jsonl`
- `S05/resource-ownership.jsonl`
- `S06/service-model.json`
- `S06/state-machines.jsonl`
- `S07/security-lifecycle-model.json`
- `S07/resource-transitions.jsonl`
- S03–S07 各 Stage 的 `evidence-index.json`、`decision-index.json`、`unknown-index.json`
- `S07/ida-stage.i64`

### 产物

| Artifact | 内容 |
|---|---|
| `S08/recovered-repository/` | C-like/C 候选、符号化 `.S`、类型与模块目录 |
| `S08/source-map.jsonl` | 恢复文件/符号到 Image 地址与 Evidence 的映射 |
| `S08/recovery-index.json` | 所有恢复对象、等级和路径 |
| `S08/unresolved-index.jsonl` | 未恢复对象及原因 |
| `S08/records/<producer>.*.jsonl` | 三个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
accepted S03-S07 models
  -> synthesize-hypervisor-repository
  -> generate-recovery-source-map
  -> index-recovery-evidence
  -> validate-artifact-contract
  -> review-stage-output
  -> human repository gate
  -> orchestrate-hypervisor-recovery
```

- 三个 Skill 串行：source map 依赖已生成符号，index 依赖 repository 与 source map。
- S08 只读 accepted IDA checkpoint，不允许产生 IDA proposal。
- Repository synthesis 只能转换既有模型，不能重新解释汇编。

### 退出条件

- **accepted**：每个生成对象都有 source map；恢复等级完整；repository 与 recovery index 一致。
- **rework**：出现无模型来源的函数/字段、source-map 缺失、目录归属冲突或过度确定性表述。
- **blocked**：accepted 模型不足以形成最小仓库索引；可以生成 unresolved-only 包时不视为阻塞。

### 边界

- 不调用 IDA 写操作，不重做 S03–S07 分析。
- 不补写硬件、平台、错误处理或“合理”业务代码。
- 不承诺代码可编译、可链接、可启动或行为等价。
- Markdown 报告不能替代结构化 source map 和 unresolved index。

## S09：静态一致性与安全审计

### 目标

审计恢复仓相对 Image/IDA 模型的一致性，并评估安全不变量。

### 输入

- `S08/recovered-repository/`
- `S08/source-map.jsonl`
- `S08/recovery-index.json`
- `S08/unresolved-index.jsonl`
- `S03/program-model.json`
- `S04/architecture-model.json`
- `S05/runtime-object-model.json`
- `S06/service-model.json`
- `S07/security-lifecycle-model.json`
- S03–S08 各 Stage 的 `evidence-index.json`、`decision-index.json`、`unknown-index.json`
- `S07/ida-stage.i64`

### 产物

| Artifact | 内容 |
|---|---|
| `S09/static-consistency.json` | CFG、xref、结构偏移、架构事件一致性 |
| `S09/security-invariants.json` | supported/violated/unknown |
| `S09/coverage.json` | 函数、区域、类型、间接调用覆盖率 |
| `S09/findings.jsonl` | 审计发现及严重度 |
| `S09/rework-plan.json` | 需要回退的 Stage 和对象 |
| `S09/audit-summary.json` | 集成审计结论 |

### Skill 路由编排

```text
S08 repository + accepted models
  +-> audit-recovery-static-consistency ---+
  +-> audit-hypervisor-security-invariants +-> integrate-recovery-audit
  +-> assess-recovery-coverage ------------+   -> validate-artifact-contract
                                               -> review-stage-output
                                               -> human audit gate
                                               -> orchestrate-hypervisor-recovery
                                                  (accept OR invalidate/rework upstream)
```

- 三个 Audit Worker 并行，只读同一冻结输入集。
- Security Audit 不读取 Consistency Audit 的草稿，避免结论互相污染。
- Integration Skill 合并 findings、严重度、覆盖率和最早回退 Stage。
- 高严重度 finding 必须先回退，不能由报告文字豁免。

### 退出条件

- **accepted**：finding 全部可追溯；无未处理 high-severity 冲突；安全结论符合 supported/violated/unknown。
- **rework**：一致性失败、覆盖率计算缺失、high-severity finding 或 source-map 断链。
- **blocked**：审计输入损坏或关键模型缺失，无法判断任何核心不变量。

### 边界

- 只做静态审计，不执行目标、不编译、不仿真。
- `supported` 不等于安全证明；不得使用 `proved safe`。
- 未解析间接调用影响安全路径时必须为 `unknown`。
- Audit Skill 不直接修改恢复仓或 IDA，只能生成 finding/rework plan。

## S10：收敛与交付

### 目标

冻结 accepted Artifact，生成可继续分析的 AI Native 交付包。

### 输入

- S00–S09 的 accepted `stage-manifest.json`
- `workflow/workflow-state.json`
- `S08/recovered-repository/`
- `S08/recovery-index.json`
- `S09/audit-summary.json`
- `S09/rework-plan.json`
- `S09/findings.jsonl`
- `S09/coverage.json`
- `S07/ida-stage.i64`

### 产物

| Artifact | 内容 |
|---|---|
| `S10/delivery-manifest.json` | 全部交付文件、schema、hash、producer |
| `S10/final-report.md` | 结果、覆盖率、发现、限制 |
| `S10/final-unknowns.jsonl` | 合并后的未知项 |
| `S10/final-decisions.jsonl` | 关键决定与替代解释 |
| `S10/recovered-repository/` | 冻结的静态恢复仓 |
| `S10/final-ida.i64` | 最终 IDA 数据库 |
| `S10/workflow-trace.jsonl` | Stage/Skill 执行轨迹 |

### Skill 路由编排

```text
accepted S00-S09 artifact set
  -> write-hypervisor-recovery-report
  -> package-hypervisor-recovery-delivery
  -> validate-artifact-contract
  -> review-stage-output
  -> final human delivery gate
  -> orchestrate-hypervisor-recovery marks workflow complete
```

- Report 只能总结 accepted Artifact，不产生新技术结论。
- Packaging 在报告、最终 unknown/decision 汇总完成后执行。
- Delivery manifest 最后生成并覆盖全部交付 hash。
- S10 不允许触发新的二进制分析；发现问题必须回退来源 Stage。

### 退出条件

- **accepted**（Workflow complete）：manifest hash 全通过；无未接受产物；最终人工门禁通过；workflow 标记 complete。
- **rework**：交付缺文件、hash 不一致、报告与 Artifact 不一致，或遗漏 unknown/stubbed/unresolved。
- **blocked**：最终 IDA checkpoint 或 accepted repository 不可读取，无法形成可验证交付包。

### 边界

- 只冻结、索引和总结，不重新分析、重命名或修改 accepted Artifact。
- 不隐藏 unknown、accepted-risk、stubbed 或 unresolved。
- 不把原型工具、临时文件和未接受草稿打入交付。
- 最终报告必须重申单文件、静态、IDA-only 和非安全证明边界。

## 4. 回退关系

| 发现问题 | 回退 Stage |
|---|---|
| 输入或约束被破坏 | S00 |
| 文件区域划分错误 | S01 |
| base/entry/segment 错误 | S02 |
| 函数、数据、间接控制流错误 | S03 |
| 异常、context、系统寄存器语义错误 | S04 |
| CPU/vCPU 或 Stage-2 ownership 冲突 | S05 |
| 配置、调度、中断关系错误 | S06 |
| 生命周期或 HKIP 状态矛盾 | S07 |
| 代码仓引入无证据行为 | S08 |
| 审计证据不足 | 对应的最早生产 Stage |

下游 Stage 失效时，Orchestrator 必须把所有依赖该 Artifact 的 accepted Stage 标记为 `rework`。

## 5. 人工门禁

以下决定不能由单一 Producer Skill 自动接受：

- Image base 和 entry
- 异常向量确认
- 大范围函数/数据边界
- 安全关键结构体
- candidate 升级为 confirmed
- 资源 ownership 模型
- HKIP 保护对象与 violation path
- 安全不变量结论
- 最终交付接受

Reviewer Skill 负责生成审查建议；最终门禁可以由用户或被授权的独立 Review Agent 接受。
## S03 forward-test oracle addendum

This addendum is part of the S03 workflow contract and applies only to lab validation runs where a paired symbolized IDB is explicitly provided by the user.

### Scope

- A symbolized oracle such as `tests/xen-syms_arm64.i64` is a validation-only artifact.
- It may be used to tune S03 function-boundary and `.inst fallback` recovery in the test case.
- It is not a production input and must not appear as evidence in recovered production `functions.jsonl`, `data-objects.jsonl`, `call-graph.json`, or final source-map claims.

### Ordered workflow

1. Build an oracle relation from byte/function fingerprints, dominant address delta, size, and branch-local CFG shape.
2. Use target-only IDA evidence to make the primary S03 proposal.
3. Compare the target proposal against the oracle and write the report under `validation/oracle/`.
4. If the user explicitly authorizes oracle-assisted lab repair, convert only target words that map to oracle code and record the action as `validation_only`.
5. Re-export target word state after every apply pass.
6. Repeat apply/readback until oracle-code candidates reach zero, or record the remaining candidates as S03 residual blockers.

### Exit rule

S03 remains `rework_required` if any non-waived target middle `.text` word is still:

- mapped to oracle code but not represented as target code,
- represented only by stale `.inst fallback` comments,
- hidden by IDA item-head/tail ambiguity,
- or blocked by function-boundary/segment-coverage mismatch.

Only after those residuals are fixed, waived with explicit reviewed rationale, or proven to be outside target `.text` may S03 proceed to S04.

When residuals are waived, S03 may be marked `accepted` only if:

- each waived address is represented in `accepted-risk-*.jsonl`,
- `stage-manifest.json` records `residual_policy.status = accepted-risk`,
- downstream stages include the accepted-risk artifact in their input provenance,
- and any downstream conclusion directly depending on a waived address is downgraded to `inferred` or `unresolved`.
