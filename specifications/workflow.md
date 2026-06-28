# AI Native ARM64 EL2 Hypervisor 逆向恢复工作流

本文档是规范性 Workflow 的精简入口。实现脚本、IDA 数据库和具体 Skill 都必须服从该 Workflow，不能反向决定流程。

详细 Skill 职责见 [skill-architecture.md](skill-architecture.md)，Artifact 字段和目录契约见 [artifact-contracts.md](contracts/artifact-contracts.md)。

完整 Workflow 的模块化版本位于 `specifications/workflows/`，方便各 Stage 独立维护和优化。

## 拆分文档映射

| # | 文档 | 内容 |
|---|---|---|
| 0 | [workflows/00-overview-and-policy.md](workflows/00-overview-and-policy.md) | 不变量、设计原则、状态机、通用门禁、Contract 模板 |
| 1 | [workflows/01-global-workflow.md](workflows/01-global-workflow.md) | 全局 Workflow 总览、Stage 依赖、并行拓扑 |
| 2 | [workflows/02-stage-s00-case-and-image-setup.md](workflows/02-stage-s00-case-and-image-setup.md) | S00 Case 初始化 + Image 布局（合并原 S00+S01） |
| 3 | [workflows/03-stage-s01-ida-baseline.md](workflows/03-stage-s01-ida-baseline.md) | S01 IDA 基线与地址空间 |
| 4 | [workflows/04-stage-s02-program-structure.md](workflows/04-stage-s02-program-structure.md) | S02 程序结构恢复 |
| 5 | [workflows/05-stage-s03-el2-architecture.md](workflows/05-stage-s03-el2-architecture.md) | S03 ARM64 EL2 架构语义 |
| 6 | [workflows/06-stage-s04-runtime-object-model.md](workflows/06-stage-s04-runtime-object-model.md) | S04 运行时基础对象模型 |
| 7 | [workflows/07-stage-s05-vm-service-model.md](workflows/07-stage-s05-vm-service-model.md) | S05 VM 服务模型 |
| 8 | [workflows/08-stage-s06-lifecycle-hkip.md](workflows/08-stage-s06-lifecycle-hkip.md) | S06 生命周期与 HKIP |
| 9 | [workflows/09-stage-s07-source-repository.md](workflows/09-stage-s07-source-repository.md) | S07 静态代码仓合成（output class、重写/呈现规则） |
| 10 | [workflows/10-stage-s08-static-audit.md](workflows/10-stage-s08-static-audit.md) | S08 静态审计（可读性门禁、就绪门禁） |
| 11 | [workflows/11-stage-s09-delivery.md](workflows/11-stage-s09-delivery.md) | S09 收敛与交付（包布局） |
| 12 | [workflows/12-cross-stage-rules.md](workflows/12-cross-stage-rules.md) | 跨 Stage 规则：回退、人工门禁、Codegen 门禁 |
| 13 | [workflows/13-s02-oracle-addendum.md](workflows/13-s02-oracle-addendum.md) | S02 forward-test oracle 附录 |
| | [workflows/stage-audit-template.md](workflows/stage-audit-template.md) | `stage-audit.md` 强制模板（6 节结构） |

## 始终生效的不变量

以下规则跨越所有 Stage 生效：

1. 生产输入仅为一个目标二进制及其 IDA 派生证据。
2. Oracle/symbolized 二进制仅用于实验室验证，必须存放在 validation/evaluation 产物下，不得进入生产证据链。
3. 每个导出的 IDA 函数必须路由到以下四种 output class 之一：
   `semantic-c`、`lifted-c`、`asm-fallback`、`unresolved`。
4. `lifted-c` 和 `semantic-c` 是独立的输出等级。伪代码证据、注释或 wrapper body 不能将函数提升为 semantic。
5. 规范代码仓路径为 `recovered-repos/<case-id>/recovered-hypervisor/`。
6. `cases/<case-id>/stages/` 是证据工作区，不是面向用户的代码仓。
7. 代码仓必须包含 `.c`、`.h`、`.S` 等源文件；JSON/JSONL/IDA/SQLite 等中间产物只属于 evidence outputs。
8. S09 必须保留上游 source status，不得将 `source_slice_ready` 或 `source_corpus_lifted` 提升为 `source_repo_ready`。

## Stage 序列

| Stage | 名称 | 主要出口 |
|---|---|---|
| S00 | Case 初始化与 Image 布局 | Case manifest、constraint profile、Image layout、region map |
| S01 | IDA 基线与地址空间 | IDA baseline、address-space decision |
| S02 | 程序结构恢复 | Function/data model、call graph、unresolved regions |
| S03 | ARM64 EL2 架构语义 | Boot/exception/context/architecture model |
| S04 | 运行时基础对象模型 | CPU/vCPU model、Stage-2 memory model |
| S05 | VM 服务模型 | VM config、scheduler、interrupt model |
| S06 | 生命周期与 HKIP | Lifecycle model、HKIP model、resource transitions |
| S07 | 静态代码仓合成 | Recovered repository、source map、recovery index |
| S08 | 静态一致性与安全审计 | Consistency audit、security findings、coverage |
| S09 | 收敛与交付 | Delivery manifest、final report、final unknown registry |

## 维护规则

- 修改单个 Stage 规则时，先更新 `workflows/` 下对应的拆分文档。
- 跨 Stage 的全局规则变更时，更新 `workflows/00-overview-and-policy.md` 或 `workflows/12-cross-stage-rules.md`，并将影响判断为全局不变量时同步更新本入口的"始终生效的不变量"列表。
- 当规则影响至少两个拆分文档时，考虑是否应加入不变量。
- 不要在不同子文档之间复制完整的 Stage 合同；使用链接引用所属文档。
- 本入口文件保持精简：仅含不变量、Stage 总览表和拆分文档索引。
