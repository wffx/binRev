# Stage 架构说明

本目录保存 Workflow 中关键 Stage 的人类可读解释，用于帮助逆向工程师理解每个
Stage 实际要解决的问题。

这些文档是 [Workflow Contract](../specifications/workflow.md) 的说明材料。若描述与
Workflow Contract 冲突，以 Contract 为准。

当前包含：

- [S00：Case 初始化与边界锁定](stage-s00-case-initialization.md)
- [S04：ARM64 EL2 架构语义](stage-s04-el2-architecture.md)
- [S05：运行时基础对象模型](stage-s05-runtime-object-model.md)
- [S06：VM 服务模型](stage-s06-vm-service-model.md)

统一理解顺序：

```text
S00：固定“分析谁、允许用什么、不能声称什么”

S04：解释匿名汇编中的 ARM64 EL2 架构行为
  ↓
S05：把架构行为组织成 CPU、vCPU、VM、Stage-2 等核心对象
  ↓
S06：恢复这些对象如何完成配置、调度和中断服务
```

## UTF-8 index supplement

- [S07: VM Lifecycle and HKIP Security Lifecycle](stage-s07-security-lifecycle.md)
- [S08: Repository Synthesis](stage-s08-repository-synthesis.md)
- [S09: Static Audit](stage-s09-static-audit.md)
- [S10: Final Report and Delivery Package](stage-s10-delivery-package.md)

Updated stage flow:

```text
S04 -> S05 -> S06 -> S07 -> S08 -> S09 -> S10
S07 recovers, or explicitly blocks, VM lifecycle and HKIP security-lifecycle semantics.
S08 converts accepted models into source, or creates unresolved review-seed scaffolding when production recovery is blocked.
S09 audits consistency, coverage, and invariants; in review-seed mode it emits unknown/not-evaluable security results only.
S10 freezes the results into either a production package or an explicitly production-blocked review-seed package.
```
