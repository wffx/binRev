## S02：程序结构恢复

### 目标

恢复代码/数据边界、函数、调用图、跳转表、函数指针和未决区域。

### 输入

- `S00/ida-baseline.i64`
- `S00/ida-baseline-snapshot.json`
- `S00/address-space.json`
- `S00/region-map.json`
- `S00/evidence-index.json`
- `S00/unknown-index.json`
- `S00/evidence-index.json`
- `S00/decision-index.json`
- `S00/unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S00/program-model.json` | 统一程序结构模型 |
| `S00/functions.jsonl` | 函数边界、置信度、调用关系 |
| `S00/data-objects.jsonl` | 表、数组、字符串、状态对象候选 |
| `S00/data-islands.jsonl` | 仅限 header/tail/明确非 text 区的外部数据、alignment/padding、嵌入 blob；主 `.text` 中间不得默认保留 literal pool/qword |
| `S00/code-data-boundary-audit.json` | 全量 code/data/bit 未识别区域审计、text code-first 审计和剩余阻塞项 |
| `S00/call-graph.json` | 直接调用图 |
| `S00/indirect-targets.jsonl` | 间接调用/跳转候选 |
| `S00/unresolved-regions.jsonl` | 未解析代码/数据区域，包括 `.text` 中不可解码的 `instruction_fallback` |
| `S00/branch-sample.json` | 至少一个代表性函数分支样本，包含 root、范围、节点、直接边、间接边和选择理由 |
| `S00/ida-stage.i64` | Stage 接受时的 IDA checkpoint |
| `S00/records/<producer>.*.jsonl` | 四个 Producer 的 Evidence、Decision、Unknown 分片 |

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
- `recover-ida-functions` 在导出函数时同步记录每个函数的 STP/LDP 栈帧偏移（`frame_size`、`saved_regs`、`restored_regs`），为 S03 context-layout 提供直接数据来源，避免 S03 重复扫描。
- `recover-binary-data-objects` 必须执行全量 code/data boundary 扫描，覆盖 IDA 中所有 code-bearing segment 内的未识别 bit/data、literal pool、pointer table、constant table、alignment/padding 和嵌入数据岛。
- 对主 `.text` body 执行 code-first 策略：除 binary header/tail appendix 或明确非 text 区外，中间区域不得以 `DCQ`/`DCD`/`qword` data island 作为最终状态。可解码 4-byte word 必须恢复为 ARM64 code；不可解码 word 必须成为 `.inst`/`instruction_fallback` blocker，或经过显式人工审核后作为 accepted-risk。
- Indirect-control-flow Skill 等待函数边界与 data-island/data-object 候选输出。
- Integration Skill 解决 code/data 冲突并产生唯一 program model。
- S02 必须产生 `branch-sample.json`（至少一个代表性函数分支样本），作为 S03 分支质量审计的基线。
- S02 必须产生 `code-data-boundary-audit.json`，报告 `.text` 中 qword/data item 数量、已恢复 code word 数量和 `.inst fallback` 数量。未审核 `.inst fallback` 或中间 `.text` data island 需标记为 unresolved 并写入 `unresolved-regions.jsonl`。
- 对用户报告或抽样的 data-island 地址，S02 产物必须记录 point-level head/tail readback（owning `item_head`/`item_end`、分类）。
- 若调测阶段存在符号 oracle 或 symbolized IDB，比对报告必须放在 `validation/oracle/` 区域，标记 `validation_only`；oracle 名称不得进入 S02 正式 `functions.jsonl`/`call-graph.json` 证据。
- IDA 变更只在集成模型通过 Review 后提交。

### 退出条件

- **accepted**：可达直接代码形成调用图；函数边界和 code/data 边界冲突已消解；主 `.text` body 已按 code-first 策略恢复为 ARM64 code 或经审核的 `.inst` fallback；所有 IDA 可见 bit/data/data-island 未识别问题已结构化分类并形成已审核/已应用的 IDA proposal；用户报告/抽样 data-island 点具备 head/tail readback 解释；间接目标有候选集或 Unknown；至少一个代表性函数分支通过边界质量审计。
- **rework**：函数重叠、数据被误识别为代码、代码被误识别为数据、literal pool/pointer table/constant table/alignment 未分类、jump table 破坏 CFG、代表性函数分支出现 false function start / boundary miss / merged functions，或 accepted address-space 被新证据否定。
- **blocked**：entry/主要可达代码无法建立稳定边界，或存在当前约束下无法分类的 bit/data/code-data 区域，导致 S04 无法获得干净程序结构输入。

### 边界

- 只恢复程序结构，不赋予 CPU/VM/调度/HKIP 等业务语义。
- 不允许“所有 branch target 即函数”或用反编译美观度决定边界。
- 间接调用不能被忽略；无法解析时必须进入 Unknown Registry。
- S02 的 Unknown 不能用来绕过 bit/data 修复门禁；会污染 S03/S04 的 code/data boundary unknown 必须阻塞或 rework。
- Worker 不能直接修改共享 IDA baseline。
- IDA 写回成功不是 S02 接受条件；必须有分支级结构质量证据。
- forward-test oracle 是调测验证材料，不得污染真实目标的 functions/data/call graph 证据，也不得成为生产 workflow 的必需输入。
