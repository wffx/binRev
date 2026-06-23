# 工作流约束合规审计

## 约束声明

| 项目 | 约束 |
|---|---|
| 输入 | 只有一个 `Image` 文件 |
| 已知事实 | ARM64 boot executable Image、little-endian |
| 已知背景 | EL2 Hypervisor；CPU、VM、内存隔离、调度、生命周期、HKIP、中断直通 |
| 外部工具 | 只有 IDA |
| 分析方式 | 静态分析 |
| 交付 | 静态恢复代码仓和证据，不承诺构建或行为等价 |
| 工程形态 | AI Native：Workflow 编排、Stage 门禁、Skill 执行、Artifact 交接 |

## 合规检查

| 检查项 | 当前处理 | 结论 |
|---|---|---|
| 是否需要第二个输入文件 | 不需要 | 符合 |
| 是否要求外部 DTB/日志/配置 | 不要求；只扫描 Image 内嵌候选 | 符合 |
| 是否要求源码或符号 | 不要求 | 符合 |
| 是否依赖 MCP | 主流程和 CLI 均不依赖 | 符合 |
| 是否依赖 Hex-Rays | 可选；无反编译器时使用反汇编、CFG 和 xref | 符合 |
| 是否依赖调试器/仿真器/目标板 | 不依赖 | 符合 |
| 是否依赖交叉编译器 | 不依赖；不执行编译验收 | 符合 |
| 是否使用其他逆向工具 | 不使用 | 符合 |
| 是否把业务背景当作事实 | 业务名称默认为 candidate，须二进制证据确认 | 符合 |
| 是否承诺恢复原源码 | 不承诺 | 符合 |
| 是否承诺可构建/可运行 | 不承诺 | 符合 |
| 是否声称证明安全 | 不声称；只提供 supported/violated/unknown 静态结论 | 符合 |
| Skill 是否依赖聊天记忆 | 禁止；只读取声明的 Artifact | 符合 |
| Stage 是否有显式输入输出 | 每个 S00–S10 均定义必需输入、输出和接受条件 | 符合 |
| IDA 是否是隐式共享状态 | 否；使用 proposal/review/transaction/checkpoint | 符合 |
| 并行 Skill 是否直接共享草稿 | 禁止；通过集成 Skill 和 Artifact 合并 | 符合 |

## 允许的内部派生文件

以下文件由唯一 `Image` 生成，不构成额外输入：

- `image-manifest.json`
- `address-map.json`
- `analysis.json`
- `analysis.sqlite`
- 可选的 `synthetic-hypervisor.elf`（仅内部派生，非必需）
- IDA `.i64`/IDB
- IDAPython 导出的 snapshot
- 恢复后的 C-like/C 候选和 `.S`

## 禁止进入确认结论的材料

- 未获得的设备资料或内部规范
- 从业务背景直接推导的函数名称
- 未验证的开源相似实现
- IDA 自动生成但未经人工检查的函数边界和类型
- 仅凭单个字符串、常量或算法相似性产生的模块归属

本文档用于检查工作流边界；具体执行顺序见
[workflow.md](../workflow.md)。
