# 全局 Workflow 与 Stage 总览

## Stage 序列

| Stage | 名称 | 执行 Skill 数 | 主要出口 |
|---|---|---|---:|---|
| S00 | Case 初始化与 Image 布局 | 2 | Case manifest、constraint profile、Image layout |
| S01 | IDA 基线与地址空间 | 3 | IDA baseline、address-space decision |
| S02 | 程序结构恢复 | 4 | Function/data model、call graph、unresolved regions |
| S03 | ARM64 EL2 架构语义 | 5 | Boot/exception/context/architecture model |
| S04 | 运行时基础对象模型 | 3 | CPU/vCPU model、Stage-2 memory model |
| S05 | VM 服务模型 | 4 | VM config、scheduler、interrupt model |
| S06 | 生命周期与 HKIP | 3 | Lifecycle model、HKIP model、resource transitions |
| S07 | 静态代码仓合成 | 3 | Recovered repository、source map、recovery index |
| S08 | 静态一致性与安全审计 | 4 | Consistency audit、security findings、coverage |
| S09 | 收敛与交付 | 2 | Delivery manifest、final report、final unknown registry |

`review-stage-output` 是所有 Stage 的公共 Reviewer Skill，不计入上表的专业 Skill 数。

## Stage 依赖

| Stage | 直接依赖 | 理由 |
|---|---|---|---|
| S00 | 无 | 建立 Case ID、hash、约束并解析 Image 布局 |
| S01 | S00 | IDA 装载必须依据已确认文件边界 |
| S02 | S00、S01 | 函数/数据恢复依赖 region 与 address space |
| S03 | S02 | 架构语义依赖稳定程序结构和已清洁 code/data boundary |
| S04 | S02、S03 | runtime object 依赖函数图、context 和 sysreg |
| S05 | S02–S04 | 服务模型依赖 runtime ownership |
| S06 | S03–S05 | 生命周期/HKIP 依赖架构、资源和服务关系 |
| S07 | S02–S06 | 代码仓只能合成 accepted 模型 |
| S08 | S02–S07 | 审计需要原模型、证据和恢复仓 |
| S09 | S00–S08 | 交付只能冻结全部 accepted Artifact |

## 并行与依赖拓扑

```text
S00 -> S01 -> S02 -> S03
                       |
                       v
          +--------------------------+
S04       | CPU/vCPU      Stage-2    |  parallel
          +------------+-------------+
                       |
                       v integrate
          +--------------------------+
S05       | Config Scheduler IRQ     |  parallel
          +------------+-------------+
                       |
                       v integrate
          +--------------------------+
S06       | Lifecycle      HKIP      |  partial parallel
          +------------+-------------+
                       |
                       v integrate
S07 -> S08(parallel audits -> integrate) -> S09
```

并行 Skill 不得直接读取彼此未接受的工作目录；只能通过 Integration Skill 合并。
