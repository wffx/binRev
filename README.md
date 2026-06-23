# hvrev

AI Native 的 ARM64 EL2 Hypervisor 静态逆向恢复工程。

项目当前处于“规范冻结、Skill 尚未实现”阶段。Workflow、Stage、Skill 和
Artifact Contract 是唯一权威定义；已有 Python/IDAPython 代码仅作为早期原型归档。

## 目录结构

```text
binRev/
├── README.md
├── specifications/
│   ├── workflow.md
│   ├── skill-architecture.md
│   └── contracts/
│       ├── artifact-contracts.md
│       ├── ida-tool-contract.md
│       └── constraint-boundary.md
├── skills/
│   └── .gitkeep
├── cases/
│   └── .gitkeep
└── prototypes/
    └── static-analysis-mvp/
        ├── README.md
        ├── pyproject.toml
        ├── src/
        ├── scripts/
        ├── config/
        └── tests/
```

### `specifications/`

项目的规范层，也是唯一事实来源：

- [Workflow 与 Stage Contract](specifications/workflow.md)
- [Stage Contract 审计](specifications/stage-audit.md)
- [Skill Catalog](specifications/skill-catalog.md)
- [Skill 架构与职责](specifications/skill-architecture.md)
- [Artifact Contract](specifications/contracts/artifact-contracts.md)
- [IDA Tool Contract](specifications/contracts/ida-tool-contract.md)
- [约束边界](specifications/contracts/constraint-boundary.md)

### `arch/`

面向逆向工程师的 Stage 解释文档，用具体问题说明 Stage 的作用：

- [S00 Case 初始化](arch/stage-s00-case-initialization.md)
- [S04 EL2 架构语义](arch/stage-s04-el2-architecture.md)
- [S05 运行时基础对象](arch/stage-s05-runtime-object-model.md)
- [S06 VM 服务模型](arch/stage-s06-vm-service-model.md)

### `skills/`

后续存放真实、可发现的 Codex Skill 包。当前保持为空，因为应先冻结合同，再按照
公共治理 Skill、基础 Stage Skill、领域 Skill、合成审计 Skill、Orchestrator Skill
的顺序创建。

每个子目录未来必须是独立 Skill：

```text
skills/<skill-name>/
├── SKILL.md
├── agents/openai.yaml
└── references|scripts|assets/
```

### `cases/`

Workflow 运行实例目录。每个 Case 只能有一个输入 `Image`，运行态 Artifact 按
`artifact-contracts.md` 保存。案例二进制和分析产物默认不提交到版本库。

```text
cases/<case-id>/
├── input/Image
├── workflow/
├── stages/S00...S10/
└── delivery/
```

### `prototypes/`

非权威实验实现。现有
[static-analysis-mvp](prototypes/static-analysis-mvp/README.md)
可用于验证局部想法，但：

- 不能定义 Workflow 或 Stage。
- 输出不自动满足 Artifact Contract。
- 代码不能直接视为正式 Skill 实现。
- 原型能力应在合同适配和独立验证后才能迁移到 `skills/`。

## 固定边界

- 唯一案例输入：一个 little-endian ARM64 boot executable `Image`
- 已知背景：EL2 Hypervisor，涉及 CPU/vCPU、VM 配置、Stage-2、调度、生命周期、HKIP 和中断直通
- 外部逆向工具：仅 IDA/IDAPython；Hex-Rays 可选
- 不使用外部源码、符号、日志、DTB、平台资料、动态环境或其他逆向工具
- 交付是静态恢复仓和证据，不承诺可编译、可运行、行为等价或安全证明

## Workflow

```text
S00 Case 初始化
 -> S01 Image 布局
 -> S02 IDA 地址空间
 -> S03 程序结构
 -> S04 EL2 架构语义
 -> S05 运行时基础对象
 -> S06 VM 服务
 -> S07 生命周期与 HKIP
 -> S08 静态代码仓合成
 -> S09 一致性与安全审计
 -> S10 收敛与交付
```

实现工作应从 `skills/` 的公共治理 Skills 开始，而不是继续扩展原型 CLI。
