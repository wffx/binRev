## S07：静态代码仓合成

### 目标

将 accepted 模型合成为静态恢复代码仓，不添加模型之外的新业务事实。

### 输入

- `S02/program-model.json`
- `S03/architecture-model.json`
- `S04/runtime-object-model.json`
- `S04/types.jsonl`
- `S04/resource-ownership.jsonl`
- `S05/service-model.json`
- `S05/state-machines.jsonl`
- `S06/security-lifecycle-model.json`
- `S06/resource-transitions.jsonl`
- S02–S06 各 Stage 的 `evidence-index.json`、`decision-index.json`、`unknown-index.json`
- `S06/ida-stage.i64`

### 产物

| Artifact | 内容 |
|---|---|
| `S07/recovered-repository/` | C-like/C 候选、符号化 `.S`、类型与模块目录 |
| `S07/source-map.jsonl` | 恢复文件/符号到 Image 地址与 Evidence 的映射 |
| `S07/recovery-index.json` | 所有恢复对象、等级和路径 |
| `S07/unresolved-index.jsonl` | 未恢复对象及原因 |
| `S07/records/<producer>.*.jsonl` | 三个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
accepted S02–S06 models
  -> synthesize-hypervisor-repository
  -> generate-recovery-source-map
  -> index-recovery-evidence
  -> validate-artifact-contract
  -> review-stage-output
  -> human repository gate
  -> orchestrate-hypervisor-recovery
```

- 三个 Skill 串行：source map 依赖已生成符号，index 依赖 repository 与 source map。
- S07 只读 accepted IDA checkpoint，不允许产生 IDA proposal。
- Repository synthesis 只能转换既有模型，不能重新解释汇编。

### 退出条件

- **accepted**：每个生成对象都有 source map；恢复等级完整；repository 与 recovery index 一致。
- **rework**：出现无模型来源的函数/字段、source-map 缺失、目录归属冲突或过度确定性表述。
- **blocked**：accepted 模型不足以形成最小仓库索引；可以生成 unresolved-only 包时不视为阻塞。

### 边界

- 不调用 IDA 写操作，不重做 S02–S06 分析。
- 不补写硬件、平台、错误处理或“合理”业务代码。
- 不承诺代码可编译、可链接、可启动或行为等价。
- Markdown 报告不能替代结构化 source map 和 unresolved index。
