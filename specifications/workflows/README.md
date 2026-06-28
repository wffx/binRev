# Workflow 拆分索引

本目录包含 `specifications/workflow.md` 的模块化拆分版本。每个 Stage 独立为一个文件，方便单独维护和优化。

## 文档列表

| # | 文件 | 内容 |
|---|---|---|---|
| 0 | [00-overview-and-policy.md](00-overview-and-policy.md) | 始终生效的不变量、设计原则、Stage 状态机、通用门禁、Contract 模板 |
| 1 | [01-global-workflow.md](01-global-workflow.md) | 全局 Workflow 总览表、Stage 依赖、并行拓扑 |
| 2 | [02-stage-s00-case-and-image-setup.md](02-stage-s00-case-and-image-setup.md) | S00 Case 初始化与 Image 布局 |
| 3 | [03-stage-s01-ida-baseline.md](03-stage-s01-ida-baseline.md) | S01 IDA 基线与地址空间 |
| 4 | [04-stage-s02-program-structure.md](04-stage-s02-program-structure.md) | S02 程序结构恢复 |
| 5 | [05-stage-s03-el2-architecture.md](05-stage-s03-el2-architecture.md) | S03 ARM64 EL2 架构语义 |
| 6 | [06-stage-s04-runtime-object-model.md](06-stage-s04-runtime-object-model.md) | S04 运行时基础对象模型 |
| 7 | [07-stage-s05-vm-service-model.md](07-stage-s05-vm-service-model.md) | S05 VM 服务模型 |
| 8 | [08-stage-s06-lifecycle-hkip.md](08-stage-s06-lifecycle-hkip.md) | S06 生命周期与 HKIP |
| 9 | [09-stage-s07-source-repository.md](09-stage-s07-source-repository.md) | S07 静态代码仓合成（output class、重写规则、呈现规则） |
| 10 | [10-stage-s08-static-audit.md](10-stage-s08-static-audit.md) | S08 静态审计（可读性门禁、源码就绪门禁） |
| 11 | [11-stage-s09-delivery.md](11-stage-s09-delivery.md) | S09 收敛与交付（包布局） |
| 12 | [12-cross-stage-rules.md](12-cross-stage-rules.md) | 跨 Stage 规则：回退关系、人工门禁、函数级 Codegen 门禁 |
| 13 | [13-s02-oracle-addendum.md](13-s02-oracle-addendum.md) | S02 forward-test oracle 附录（仅实验室验证） |
| — | [stage-audit-template.md](stage-audit-template.md) | `stage-audit.md` 强制模板——每个 Stage 必须遵循的 6 节结构 |

## 维护指南

- 修改单个 Stage 规则时，只更新对应的 Stage 文件。
- 跨 Stage 的全局规则变更时，更新 `00-overview-and-policy.md` 或 `12-cross-stage-rules.md`。
- 当规则影响至少两个 Stage 时，考虑是否应加入 `00-overview-and-policy.md` 的"始终生效的不变量"。
- 不要在不同文件之间复制完整的 Stage 合同；使用交叉引用链接。
- 顶层 `specifications/workflow.md` 为精简入口，Stage 序列变更后同步更新。
- 各 Stage 独立后，经人工审计确认可以合并的 Stage 再考虑合并，在此之前保持独立。

## 拆分原则

1. 每个 Stage 一个独立文件，S00-S09 分别对应编号 02-11。
2. 跨 Stage 共享的全局规则（回退、门禁、Codegen 约束）集中在 `12-cross-stage-rules.md`。
3. 顶层设计原则和 Workflow 总览分别独立为 `00` 和 `01`。
4. 专用于实验室验证的 Oracle 附录独立为 `13`，与生产规则隔离。
