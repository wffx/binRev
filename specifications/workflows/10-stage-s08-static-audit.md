## S08：静态一致性与安全审计

### 目标

审计恢复仓相对 Image/IDA 模型的一致性，并评估安全不变量。

### 输入

- `S07/recovered-repository/`
- `S07/source-map.jsonl`
- `S07/recovery-index.json`
- `S07/unresolved-index.jsonl`
- `S02/program-model.json`
- `S03/architecture-model.json`
- `S04/runtime-object-model.json`
- `S05/service-model.json`
- `S06/security-lifecycle-model.json`
- S02–S07 各 Stage 的 `evidence-index.json`、`decision-index.json`、`unknown-index.json`
- `S06/ida-stage.i64`

### 产物

| Artifact | 内容 |
|---|---|
| `S08/static-consistency.json` | CFG、xref、结构偏移、架构事件一致性 |
| `S08/security-invariants.json` | supported/violated/unknown |
| `S08/coverage.json` | 函数、区域、类型、间接调用覆盖率 |
| `S08/findings.jsonl` | 审计发现及严重度 |
| `S08/rework-plan.json` | 需要回退的 Stage 和对象 |
| `S08/audit-summary.json` | 集成审计结论 |

### Skill 路由编排

```text
S08 repository + accepted models
  +-> audit-recovery-static-consistency ---+
  +-> audit-hypervisor-security-invariants +-> integrate-recovery-audit
  +-> assess-recovery-coverage ------------+   -> validate-artifact-contract
                                               -> review-stage-output
                                               -> human audit gate
                                               -> orchestrate-hypervisor-recovery
                                                  (accept OR invalidate/rework upstream)
```

- 三个 Audit Worker 并行，只读同一冻结输入集。
- Security Audit 不读取 Consistency Audit 的草稿，避免结论互相污染。
- Integration Skill 合并 findings、严重度、覆盖率和最早回退 Stage。
- 高严重度 finding 必须先回退，不能由报告文字豁免。

### 退出条件

- **accepted**：finding 全部可追溯；无未处理 high-severity 冲突；安全结论符合 supported/violated/unknown。
- **rework**：一致性失败、覆盖率计算缺失、high-severity finding 或 source-map 断链。
- **blocked**：审计输入损坏或关键模型缺失，无法判断任何核心不变量。

### 边界

- 只做静态审计，不执行目标、不编译、不仿真。
- `supported` 不等于安全证明；不得使用 `proved safe`。
- 未解析间接调用影响安全路径时必须为 `unknown`。
- Audit Skill 不直接修改恢复仓或 IDA，只能生成 finding/rework plan。
