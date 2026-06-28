# Workflow Constraint Boundary

本文档定义本项目的硬约束边界。所有 Workflow、Stage、Skill、Artifact 和验证动作都必须服从这里的边界。

## 1. 固定输入

唯一目标输入：

- 一个无符号 little-endian ARM64 boot executable `Image` 格式二进制文件。

已知背景：

- 业务背景类似 EL2 Hypervisor / 虚拟机管理程序。
- 可能涉及 CPU/vCPU 管理、VM 配置、Stage-2 内存隔离、共核调度、VM 生命周期、HKIP 和中断直通。

边界要求：

- 业务背景不是二进制事实。
- 不引入第二个目标样本。
- IDB、snapshot、source map、报告和恢复代码仓都是派生 artifact，不是新的目标输入。

## 2. 固定工具

允许：

- IDA Pro。
- IDAPython。
- 当前 IDA 安装中实际可用的 Hex-Rays。
- IDA MCP / `ida-mcp-rs`，仅作为 IDA 自动化传输层。

IDA MCP 连接、读取、脚本执行和 proposal 执行不需要单独人工确认；它属于 Stage/Skill 的正常工具通道。写入 IDA、保存变更或执行 proposal 不再以“是否允许连接 MCP”为门禁，而必须以对应 Stage 的 proposal / review 或 oracle-assisted auto-review / transaction / rollback 纪律为门禁。

禁止：

- Ghidra、Binary Ninja、radare2、objdump/readelf 等非 IDA 逆向工具。
- 调试器、仿真器、QEMU、Unicorn 或运行目标二进制。
- 外部源码、符号包、日志、DTB、平台文档、设备资料或动态 trace。

## 3. 固定分析方式

- 首期只做静态分析。
- 不承诺完整启动验证。
- 不承诺重建出的工程可编译、可运行或行为等价。
- 不声称证明安全；安全结论只能是 `supported`、`violated` 或 `unknown` 的静态审计结果。

## 4. 合规检查矩阵

| 检查项 | 当前处理 | 结论 |
|---|---|---|
| 是否需要第二个目标输入 | 不需要，只允许一个目标二进制 | 符合 |
| 是否要求外部 DTB/日志/配置 | 不要求，只扫描二进制内部候选对象 | 符合 |
| 是否要求源码或符号 | 不要求 | 符合 |
| 是否依赖 MCP | 可使用 IDA MCP 作为 IDA 传输层；不把 MCP 当成额外逆向工具 | 符合 |
| 是否依赖 Hex-Rays | 可选；无反编译器时使用反汇编、CFG 和 xref | 符合 |
| 是否依赖调试器/仿真器/目标板 | 不依赖 | 符合 |
| 是否依赖交叉编译器 | 不依赖；不执行编译验收 | 符合 |
| 是否使用其他逆向工具 | 不使用 | 符合 |
| 是否把业务背景当作事实 | 不允许；业务名称默认只能是 candidate | 符合 |
| 是否承诺恢复原源码 | 不承诺 | 符合 |
| 是否承诺可构建/可运行 | 不承诺 | 符合 |
| 是否声称证明安全 | 不声称 | 符合 |
| Skill 是否依赖聊天记忆 | 禁止；只能读取声明的 Artifact | 符合 |
| Stage 是否有显式输入输出 | S00-S09 必须定义输入、输出和退出条件 | 符合 |
| IDA 是否是隐式共享状态 | 否；必须使用 proposal/review/transaction/checkpoint | 符合 |
| 并行 Skill 是否直接共享草稿 | 禁止；通过 Integration Skill 和 Artifact 合并 | 符合 |

## 5. 允许的内部派生文件

以下文件可以由唯一目标二进制派生，不构成额外输入：

- `case-manifest.json`
- `constraint-profile.json`
- `image-header.json`
- `region-map.json`
- `address-space.json`
- `analysis.sqlite`
- IDA `.i64` / `.idb`
- IDA MCP / IDAPython 导出的 snapshot
- 可选 synthetic ELF，且仅作为内部地址空间载体
- 恢复后的 C-like/C 候选和符号化 `.S`
- source map、recovery index、audit report
- 各 Stage 人工审计文档 `stage-audit.md`（Markdown 格式，概括基本信息，方便人工快速审计）

## 6. 禁止进入确认结论的材料

以下材料不得直接支撑 confirmed 结论：

- 未获得的设备资料或内部规范。
- 从业务背景直接推导的函数名称。
- 未验证的开源相似实现。
- IDA 自动生成但未经人工检查的函数边界和类型。
- 仅凭单个字符串、常量或算法相似性产生的模块归属。
- MCP 服务端自身的陈述，除非它只是转述 IDA 状态。

## 7. Forward-test 样本边界

`tests/xen` / `tests/xen.i64` 可以用于验证 IDA MCP 连接、IDB 打开、元数据读取、函数列表和反汇编读取。

该样本不是目标 ARM64 Image，因此：

- 不用于证明 ARM64 Image header 解析正确。
- 不用于证明 ARM64 load base 推断正确。
- 不用于证明 EL2 system register 或 hypervisor 语义恢复正确。
- 当 S00/S01 Skill 对该样本输出 `incompatible` 或 `not_applicable` 时，这是正确的边界行为。

`tests/xen_arm64` / `tests/xen_arm64.i64` 可以用于验证目标格式 ARM64 Image 的 S00-S02 小范围闭环。

`tests/xen-syms_arm64` / `tests/xen-syms_arm64.i64` 只允许作为调测阶段的 forward-test validation oracle：

- 可以用于计算函数边界、函数名和分支结构偏差。
- 可以用于判断某次 Skill/Stage 设计是否需要 rework。
- 不得作为真实目标恢复的输入 Artifact。
- 不得作为任何生产 Stage 的必需输入或正式输出。
- 不得把 oracle 符号名直接写入 production `functions.jsonl`、`program-model.json` 或最终恢复代码仓。
- 不得用 oracle 符号把候选结论升级为 `confirmed`。
- 使用 oracle 的报告必须明确标记为 validation-only，并存放在 `validation/`、`reports/` 或 `specifications/skill-forward-tests.md` 等调测区域，与目标证据链隔离。
