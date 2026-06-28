# Stage Contract 审计

本审计针对 [workflow.md](workflow.md) 的 S00–S09。审计标准固定为：

1. 目标明确且只包含一个状态转换。
2. 输入穷举必需 Artifact 和 accepted checkpoint。
3. 产物具有唯一 Owner，能被下游直接消费。
4. Skill 路由说明串行、并行、集成、Review、IDA commit 和 checkpoint。
5. 退出条件分别定义 accepted、rework、blocked。
6. 边界说明本 Stage 不做什么，以及禁止使用的证据/工具。

## 审计矩阵

| Stage | 目标 | 输入 | 产物 | Skill 路由 | 退出条件 | 边界 | 结论 |
|---|---|---|---|---|---|---|---|
| S00 | 通过 | 通过 | 通过 | 串行初始化→约束→布局→区域分类→Review→人工门禁 | 三态齐全 | 文件偏移层，不进 IDA；不解析样本 | 通过 |
| S01 | 通过 | 通过 | 通过 | IDA load→地址迭代→人工门禁→checkpoint | 三态齐全 | 中性 baseline，不加业务语义 | 通过 |
| S02 | 通过 | 通过 | 通过 | 函数/数据并行→text code-first→全量 code/data boundary→间接流→集成→IDA commit | 三态齐全；主 `.text` 中间 qword/data 或未审核 `.inst fallback` 必须 rework/block；小范围 residual 可经 accepted-risk waiver 继续 | 只恢复程序结构，但必须清洁 code/data 边界 | 通过；当前 xen_arm64 case 为 `accepted` with `accepted-risk-rw14.jsonl` |
| S03 | 通过 | 通过；必须读取 S02 manifest 与 unresolved blobs | 通过；forward-test 产物不得冒充 accepted checkpoint | boot/exception/architecture 并行→context→集成；S02 未 accepted 时只能 forward-test | 三态齐全；S02 blocking unresolved 会阻塞 accepted/S04-ready | 只确认架构语义；不升级 unresolved blob 内代码为 architecture root | 设计通过；当前 xen_arm64 case 已 accepted |
| S04 | 通过 | 通过；必须要求 S02/S03 accepted | 通过；上游未 accepted 时只允许 `blocked_by_upstream` | CPU/vCPU 与 Stage-2 并行→runtime 集成 | 三态齐全；上游 gate 未通过时不得产生 S05-ready ownership；ownership 未解时必须 review/block S05 | 不恢复服务策略 | 设计通过；当前 xen_arm64 case 为 `review_required_root_classification` |
| S05 | 通过 | 通过 | 通过 | config/scheduler/IRQ 并行→service 集成 | 三态齐全 | 不修改基础 ownership | 通过 |
| S06 | 通过 | 通过 | 通过 | lifecycle/HKIP 并行→security-lifecycle 集成 | 三态齐全 | 不直接判定漏洞 | 通过 |
| S07 | 通过 | 通过 | 通过 | repository→source map→index 串行 | 三态齐全 | 不重新分析、不写 IDA | 通过 |
| S08 | 通过 | 通过 | 通过 | consistency/security/coverage 并行→audit 集成 | 三态齐全 | 只读静态审计 | 通过 |
| S09 | 通过 | 通过 | 通过 | report→package→Review→最终人工门禁 | 三态齐全 | 只冻结和总结 | 通过 |

## Stage 依赖审计

| Stage | 直接依赖 | 不允许跳过的原因 |
|---|---|---|
| S00 | 无 | 建立 Case ID、hash 和约束 |
| S01 | S00 | IDA 装载必须依据已确认文件边界 |
| S02 | S00、S01 | 函数/数据恢复依赖 region 与 address space |
| S03 | S02 | 架构语义依赖稳定程序结构和已清洁 code/data boundary |
| S04 | S02、S03 | runtime object 依赖函数图、context 和 sysreg |
| S05 | S02–S04 | 服务模型依赖 runtime ownership |
| S06 | S03–S05 | 生命周期/HKIP 依赖架构、资源和服务关系 |
| S07 | S02–S06 | 代码仓只能合成 accepted 模型 |
| S08 | S02–S07 | 审计需要原模型、证据和恢复仓 |
| S09 | S00–S08 | 交付只能冻结全部 accepted Artifact |

## Skill 路由审计

### 并行安全

- 并行 Worker 必须读取同一 accepted 输入快照。
- 并行 Worker 不读取彼此草稿。
- 每个 Worker 写独立 Evidence/Decision/Unknown 分片。
- 只有 Integration Skill 合并并行输出。

### IDA 安全

- S01–S06 的 Producer 只能生成 IDA proposal。
- `apply-reviewed-ida-changes` 只能接收 reviewed proposal。
- 每个 Stage 接受前保存 IDA checkpoint。
- S07–S09 对 accepted IDA checkpoint 只读。

### Review 独立性

- `review-stage-output` 不参与 Producer 推断。
- Review 读取 Stage 输入、候选输出、验收和边界。
- Review 结论只能为 `accept`、`rework`、`block`。
- 涉及人工门禁的 Stage，Reviewer 建议不能替代最终授权。

## 退出条件审计

### accepted

表示当前 Stage 的产物足以作为下游输入，不表示所有对象都已解析。非阻塞 Unknown 可以随 accepted Artifact 向下游传播。

### rework

必须包含：

- 问题对象；
- 最早责任 Stage；
- 被失效的 Artifact；
- 需要重新执行的 Skill；
- 下游失效传播列表。

### blocked

只用于缺少当前约束下不可获得、且会破坏下游前提的证据。不能因为工作困难、覆盖率低或存在普通 Unknown 就标记 blocked。

## 剩余设计风险

1. 目前只定义了 Skill 规格，尚未创建或前向验证真实 Skill。
2. Artifact schema 仍是合同示例，后续需要独立 JSON Schema 文件。
3. 人工门禁的授权主体和 UI 交互尚未实现。
4. IDA checkpoint 与 transaction 的具体适配层仍需在实际 IDA 环境验证。
5. 覆盖率阈值暂不作为硬编码退出条件，避免在单样本静态场景中制造虚假完成度。
6. G02-B forward-test 已发现 S02 需要新增分支级质量门：孤立函数写回成功不足以证明程序结构恢复可被 S03 消费。
7. S02 现新增全量 code/data boundary 门禁：未识别 bit/data/data-island 问题不得带入 S03；若无法在固定约束下结构化分类，Stage 必须 rework 或 blocked。
8. S03-RW9 人工 IDA 复核发现 head/tail 可视性缺口：data-island 地址即使 `is_unknown=false`，若落在 data item tail 且没有 owning-head 映射，也会被人工误判为未修复。S02 验收必须包含 point-level head/tail readback。
9. S03-RW10 根据目标约束改为 text-middle code-first：中间 `.text` 不应默认保留 qword/DCQ data island。当前已将可解码 word 转 code，并将不可解码 word 标成 `.inst fallback` blocker；因此先前 S02 accepted 状态被标记为 stale/rework。
10. S03-RW11 已建立 `xen_arm64.i64` 到 `xen-syms_arm64.i64` 的 validation-only oracle map；dominant delta 为 `0xa0000200000`，可用于调测 skill 偏差，但不得导入生产证据链。
11. S03-RW12/RW13 将 oracle-code residual 从大批量 `.inst fallback` 收敛到 6 个点；该修复过程具有普适性的是"code-first apply/readback/compare/iterate/residual-risk"闭环，而不是依赖特定 oracle。
12. S03-RW14 根据用户继续推进决策，将 6 个 residual 显式转为 `accepted-risk`；S02 可进入 `accepted`，但 downstream 必须携带 `accepted-risk-rw14.jsonl` provenance。

## Current case update: xen_arm64 S05-RW1

- S02 is accepted again for the local `xen_arm64` case after S03-RW14, with explicit residual accepted-risk provenance.
- S04 has advanced from seed-only output to runtime-anchor clustering, local dataflow slicing, owner/base-root tracing, lifecycle-edge tracing, teardown candidate discovery, owner/root matching, caller argument propagation, and root-class classification.
- Current S04 status is `review_required_root_classification`.
- Current S05 gate remains `blocked_until_s04_object_like_owner_root`.
- The blocking reason is no longer upstream S02/S03; it is unresolved CPU/vCPU/VM/Stage-2 ownership and lifetime links inside S04.
