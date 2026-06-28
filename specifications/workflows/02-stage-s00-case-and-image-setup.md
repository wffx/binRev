# S00: Case 初始化与 Image 布局

> 原 S00 (Case 初始化) 和 S01 (Image 解析) 合并。两者均为文件偏移级只读分析，不依赖 IDA，合并以减少工程复杂度。

## 目标

建立唯一 Case 身份，锁定约束边界，验证工具链就绪，并解析 Image 文件头、区域分类、内嵌对象候选。

## 输入

| Artifact | 要求 |
|---|---|
| `input/Image` | 唯一用户输入文件 |
| `case-request.json` | 只含格式、字节序和业务背景 |

## 产物

| Artifact | 内容 | Owner Skill |
|---|---|---|
| `S00/case-manifest.json` | Case ID、Image SHA-256、大小、路径 | `initialize-hypervisor-recovery-case` |
| `S00/constraint-profile.json` | 允许/禁止输入、工具、知识、声明；含工具状态摘要 | `enforce-recovery-constraints` |
| `S00/tool-status.json` | IDA 版本/路径、IDA MCP 连通性/probe 结果、Hex-Rays 可用性 | `enforce-recovery-constraints` |
| `S00/image-header.json` | ARM64 Image 头字段及校验 | `analyze-arm64-image-layout` |
| `S00/region-map.json` | 文件偏移范围、区域类别、置信度 | `classify-binary-regions` |
| `S00/embedded-candidates.json` | 内嵌 DTB/压缩/配置/签名候选 | `analyze-arm64-image-layout` |
| `S00/string-index.jsonl` | 字符串及文件偏移 | `classify-binary-regions` |
| `S00/stage-audit.md` | 人工审计摘要 | `orchestrate-hypervisor-recovery` |
| `workflow/workflow-state.json` | 初始 Stage 状态 | `orchestrate-hypervisor-recovery` |

## Skill 路由编排

```text
initialize-hypervisor-recovery-case
  -> enforce-recovery-constraints
       -> [IDA MCP probe: ida-mcp.exe probe --path <test-idb>]
  -> analyze-arm64-image-layout
  -> classify-binary-regions
  -> validate-artifact-contract
  -> review-stage-output
  -> human gate
  -> orchestrate-hypervisor-recovery
```

- `initialize-hypervisor-recovery-case` 固化文件、哈希和 Case ID。
- `enforce-recovery-constraints` 锁定输入/工具/结论边界，并执行 IDA MCP 连通性 probe（open_idb, list_functions, disasm, decompile 可用性）。
- 前两个 Producer 串行：约束不能绑定到未固定的 Case。
- `analyze-arm64-image-layout` 解析 ARM64 Image header、内嵌候选。依赖前两步的 case-manifest 和 constraint-profile。
- `classify-binary-regions` 全量字节区域分类、字符串提取。依赖 image-header 和 embedded-candidates。
- 本 Stage 不调用 IDA 进行目标二进制分析。允许通过 `ida-mcp.exe probe` 验证工具链就绪。

## 退出条件

- **accepted**：唯一输入 SHA-256 固定；约束声明完整；IDA MCP probe 通过（或明确记录不可用）；ARM64 Image header 解析成功（或明确记录 format_status）；每个字节属于一个已知或 `unknown` region，无重叠/空洞；Review 建议 `accept`；人工门禁通过。
- **rework**：请求字段超出允许背景、哈希/路径不一致、约束缺项、工具就绪未记录、header 不可解析、region map 有重叠/空洞或遗漏字节。
- **blocked**：输入不可读、不是单一文件、用户要求保留与固定边界冲突的外部输入、IDA/IDA MCP 均不可用且无法替代、文件头无法读取且无法以 raw payload 继续分类。

## 边界

- 只建立 Case 和文件偏移级布局，不推断虚拟加载地址、不创建函数、不生成代码仓。
- 不引入第二个样本或外部目标知识。
- 不把业务背景标为二进制事实。
- 不调用 IDA 进行目标二进制分析。允许 `ida-mcp.exe probe` 做工具链就绪检查。
- 内嵌 DTB/压缩/配置/签名只能标为 candidate，除非结构完整校验。
- 高熵不等于加密/压缩，字符串不等于业务事实。
- Oracle/symbolized 二进制仅用于实验室验证，不得进入生产证据链。
