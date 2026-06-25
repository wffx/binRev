# IDA Tool Contract

本文档定义本项目中 IDA 的使用边界。当前项目允许使用 `ida-mcp-rs`，但它只被视为 IDA 的自动化传输层，不被视为额外逆向工具或独立证据来源。

## 1. 固定边界

允许：

- IDA Pro。
- IDAPython。
- 当前 IDA 安装中实际可用的 Hex-Rays 反编译能力。
- `ida-mcp-rs` / `ida-mcp.exe`，仅用于调用 IDA 能力、读取 IDA 状态、打开/关闭 IDB、导出 IDA 元数据或执行已审核 IDA 事务。

禁止：

- Ghidra、Binary Ninja、radare2、objdump/readelf 等非 IDA 逆向工具。
- 调试器、仿真器、QEMU、Unicorn 或运行目标二进制。
- 外部符号包、源码树、启动日志、DTB、平台文档或动态 trace。
- 将 MCP 服务端自身的输出当成独立于 IDA 的事实来源。

结论来源只能是：

- 唯一输入二进制。
- 已接受的 workflow artifact。
- IDA/IDAPython/IDA MCP 读取到的 IDA 状态。
- 明确标注为通用架构知识的 ARM64/EL2 规范语义。

## 2. IDA MCP 使用规则

IDA/IDA MCP 交互属于本项目的正常分析与执行通道，不需要单独人工确认。Skill 需要连接 IDA MCP、打开 IDB、读取 IDB、执行只读或事务脚本、导出元数据、或执行已进入 workflow 的 IDA proposal 时，可以直接请求并使用当前可用的 IDA MCP transport。

技术门禁不再是“是否允许连接 IDA MCP”，而是“是否满足 workflow 事务条件”：创建/删除函数、修改 chunk、重命名、应用类型、写注释、保存 checkpoint 或执行 proposal mutation 时，必须有对应 proposal、review/auto-review 依据、transaction record 和 rollback/pre-state 记录。

当 Codex 会话暴露 `mcp__ida__...` 工具时，优先使用原生 MCP 工具。

当当前会话未暴露原生工具，但本机存在 `ida-mcp.exe` 时，可以用以下方式作为适配层：

- `ida-mcp.exe serve --read-only` 进行只读 JSON-RPC 验证。
- `ida-mcp.exe probe --path <idb>` 进行只读连通性检查。
- 仅在 Stage contract 授权时打开 raw binary 并生成 IDB。

所有 MCP 调用必须记录：

- transport：`native_mcp`、`ida_mcp_serve` 或 `ida_mcp_probe`。
- IDA MCP 版本。
- 打开的 IDB 路径。
- session id，若工具返回。
- 只读/可写模式。
- 成功、失败、超时或锁冲突状态。

## 3. Stage 映射

| Stage | IDA 职责 |
|---|---|
| S00 | 不使用 IDA。 |
| S01 | 不使用 IDA。 |
| S02 | 建立或读取中性 IDA baseline，确认 processor、endianness、entry、segment、analysis status。 |
| S03 | 基于 accepted S02 checkpoint 恢复函数、数据对象和间接控制流候选。 |
| S04 | 基于 accepted S03 checkpoint 恢复 ARM64/EL2 架构语义候选。 |
| S05 | 写入已审核 CPU/vCPU/Stage-2 类型和名称。 |
| S06 | 写入已审核 VM config、scheduler、interrupt 模型。 |
| S07 | 写入已审核 lifecycle/HKIP 模型。 |
| S08 | 只读 accepted IDA checkpoint，用于代码仓合成。 |
| S09 | 只读 accepted IDA checkpoint，用于一致性和安全审计。 |
| S10 | 冻结 final IDA checkpoint。 |

## 4. 写入纪律

- Producer Skill 只能提出 IDA change proposal。
- `apply-reviewed-ida-changes` 是唯一可以提交已审核 IDA 修改的 Skill。
- 每次写入必须有 proposal、review、transaction、before/after snapshot 和 rollback 信息。
- 未经人工门禁确认，不得把 candidate 名称升级为 confirmed 名称。
- S08-S10 不得产生新的 IDA 写入。

## 5. S02 基线检查要求

`prepare-ida-image-database` 至少记录：

- IDA/IDA MCP 版本和 transport。
- 打开的路径。
- file type。
- processor。
- bits。
- base address。
- min/max address。
- entry/main address。
- function count。
- analysis status。
- input SHA-256。

`resolve-arm64-load-address` 至少检查：

- 样本是否为 ARM64/AArch64。
- Image header 与 IDA metadata 是否一致。
- ADRP/ADD/LDR 引用闭合度。
- 直接分支目标有效率。
- 绝对指针落点。
- 异常向量候选。
- EL2 system register 或 architecture event 锚点。

如果样本不是 ARM64，必须输出 `not_applicable`，不能强行套用 ARM64 load-base 规则。

## 6. Forward-test 记录

`tests/xen.i64` 可作为 IDA MCP 连通性与只读 baseline snapshot 的测试样本。该样本当前被 IDA 识别为：

- file type：ELF。
- processor：MetaPC。
- bits：32。

因此它只能验证 S02 的 IDA MCP 通路、metadata 读取、函数列表和反汇编读取；不能验证 ARM64 Image header、EL2 system register 或 ARM64 load-base 推断。
