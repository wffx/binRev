# binRev

AI Native 的 ARM64 EL2 Hypervisor 静态逆向恢复工作流。

本仓库当前聚焦于“可审计的 workflow + 可复用的 Codex skills”，用于指导在只有一个无符号 ARM64 boot executable `Image` 和 IDA 的约束下，逐步恢复程序结构、EL2 架构语义、运行时对象、VM 服务模型和最终代码仓。

## 当前定位

- 输入边界：单个 little-endian ARM64 boot executable `Image`
- 已知背景：EL2 Hypervisor / 虚拟机管理程序，可能包含 CPU/vCPU、VM 配置、Stage-2、调度、生命周期、HKIP、中断直通等能力
- 外部工具：IDA / IDAPython / 可选 Hex-Rays
- 禁止依赖：外部源码、符号表、日志、DTB、动态运行环境或非 IDA 逆向工具
- 产物原则：所有结论必须有 artifact、evidence、decision、unknown/accepted-risk 记录

## 目录结构

```text
binRev/
├── README.md
├── arch/
│   └── stage explanation docs
├── specifications/
│   ├── workflow.md
│   ├── stage-audit.md
│   ├── skill-architecture.md
│   ├── skill-catalog.md
│   └── contracts/
├── skills/
│   └── <codex-skill>/
└── cases/
    └── .gitkeep
```

## 主要内容

### `specifications/`

规范层，是 workflow、stage、skill 和 artifact contract 的权威定义。

- [Workflow 与 Stage Contract](specifications/workflow.md)
- [Stage Contract 审计](specifications/stage-audit.md)
- [Skill Catalog](specifications/skill-catalog.md)
- [Skill 架构与职责](specifications/skill-architecture.md)
- [Artifact Contract](specifications/contracts/artifact-contracts.md)
- [IDA Tool Contract](specifications/contracts/ida-tool-contract.md)
- [约束边界](specifications/contracts/constraint-boundary.md)

### `arch/`

面向逆向工程师的 Stage 解释文档，用具体问题说明各阶段为什么存在、输入输出是什么、如何避免越界。

### `skills/`

正式 Codex Skill 包。每个 skill 独立描述一个可复用能力，例如：

- 初始化 case 和约束边界
- 分析 ARM64 Image 布局
- 准备 IDA database
- 恢复函数边界、code/data 边界和间接控制流
- 恢复 ARM64 EL2 boot/exception/context/sysreg 语义
- 恢复 CPU/vCPU、Stage-2、VM、scheduler、interrupt、lifecycle、HKIP 等模型
- 生成报告、覆盖率、代码仓和交付包

### `cases/`

运行实例目录。真实二进制、IDA 数据库、中间分析产物和大体量报告默认不提交，只保留 `.gitkeep`。

## 不上传的本地产物

以下目录/文件默认保留在本地，不进入 GitHub：

- `tests/`
- `tmp/`
- `validation/`
- `prototypes/`
- `cases/<case-id>/`
- `*.i64` / `*.idb` / IDA sidecar 文件

其中 `prototypes/` 是早期实验代码，当前 workflow 和 skills 不依赖它；如未来某些能力成熟，应迁移为正式 `skills/` 后再纳入版本库。

## Workflow 总览

```text
S00 Case 初始化与边界锁定
 -> S01 Image 格式与内容布局
 -> S02 IDA 基线与地址空间
 -> S03 程序结构恢复
 -> S04 ARM64 EL2 架构语义
 -> S05 运行时基础对象模型
 -> S06 VM 服务模型
 -> S07 生命周期与 HKIP
 -> S08 静态代码仓合成
 -> S09 一致性与安全审计
 -> S10 收敛与交付
```

## 当前进展

- S03 支持 code-first 的 `.text` 恢复策略，并能通过 apply/readback/diff/accepted-risk 闭环处理零星残留。
- S04/S05 已定义 accepted-risk provenance 传播规则。
- Oracle 或 symbolized IDB 只允许作为 forward-test / 调测材料，不得成为真实逆向流程的生产输入。
