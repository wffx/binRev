# Stage Contract 审计

本审计针对 [workflow.md](workflow.md) 的 S00–S10。审计标准固定为：

1. 目标明确且只包含一个状态转换。
2. 输入穷举必需 Artifact 和 accepted checkpoint。
3. 产物具有唯一 Owner，能被下游直接消费。
4. Skill 路由说明串行、并行、集成、Review、IDA commit 和 checkpoint。
5. 退出条件分别定义 accepted、rework、blocked。
6. 边界说明本 Stage 不做什么，以及禁止使用的证据/工具。

## 审计矩阵

| Stage | 目标 | 输入 | 产物 | Skill 路由 | 退出条件 | 边界 | 结论 |
|---|---|---|---|---|---|---|---|
| S00 | 通过 | 通过 | 通过 | 串行初始化→约束→Review→人工门禁 | 三态齐全 | 不解析样本 | 通过 |
| S01 | 通过 | 通过 | 通过 | 布局→区域分类→Review | 三态齐全 | 文件偏移层，不进 IDA | 通过 |
| S02 | 通过 | 通过 | 通过 | IDA load→地址迭代→人工门禁→checkpoint | 三态齐全 | 中性 baseline，不加业务语义 | 通过 |
| S03 | 通过 | 通过 | 通过 | 函数/数据并行→间接流→集成→IDA commit | 三态齐全 | 只恢复程序结构 | 通过 |
| S04 | 通过 | 通过 | 通过 | boot/exception/architecture 并行→context→集成 | 三态齐全 | 只确认架构语义 | 通过 |
| S05 | 通过 | 通过 | 通过 | CPU/vCPU 与 Stage-2 并行→runtime 集成 | 三态齐全 | 不恢复服务策略 | 通过 |
| S06 | 通过 | 通过 | 通过 | config/scheduler/IRQ 并行→service 集成 | 三态齐全 | 不修改基础 ownership | 通过 |
| S07 | 通过 | 通过 | 通过 | lifecycle/HKIP 并行→security-lifecycle 集成 | 三态齐全 | 不直接判定漏洞 | 通过 |
| S08 | 通过 | 通过 | 通过 | repository→source map→index 串行 | 三态齐全 | 不重新分析、不写 IDA | 通过 |
| S09 | 通过 | 通过 | 通过 | consistency/security/coverage 并行→audit 集成 | 三态齐全 | 只读静态审计 | 通过 |
| S10 | 通过 | 通过 | 通过 | report→package→Review→最终人工门禁 | 三态齐全 | 只冻结和总结 | 通过 |

## Stage 依赖审计

| Stage | 直接依赖 | 不允许跳过的原因 |
|---|---|---|
| S00 | 无 | 建立 Case ID、hash 和约束 |
| S01 | S00 | 所有观察必须绑定唯一 Image |
| S02 | S00、S01 | IDA 装载必须依据已确认文件边界 |
| S03 | S01、S02 | 函数/数据恢复依赖 region 与 address space |
| S04 | S03 | 架构语义依赖稳定程序结构 |
| S05 | S03、S04 | runtime object 依赖函数图、context 和 sysreg |
| S06 | S03–S05 | 服务模型依赖 runtime ownership |
| S07 | S04–S06 | 生命周期/HKIP 依赖架构、资源和服务关系 |
| S08 | S03–S07 | 代码仓只能合成 accepted 模型 |
| S09 | S03–S08 | 审计需要原模型、证据和恢复仓 |
| S10 | S00–S09 | 交付只能冻结全部 accepted Artifact |

## Skill 路由审计

### 并行安全

- 并行 Worker 必须读取同一 accepted 输入快照。
- 并行 Worker 不读取彼此草稿。
- 每个 Worker 写独立 Evidence/Decision/Unknown 分片。
- 只有 Integration Skill 合并并行输出。

### IDA 安全

- S02–S07 的 Producer 只能生成 IDA proposal。
- `apply-reviewed-ida-changes` 只能接收 reviewed proposal。
- 每个 Stage 接受前保存 IDA checkpoint。
- S08–S10 对 accepted IDA checkpoint 只读。

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
