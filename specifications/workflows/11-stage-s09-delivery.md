## S09：收敛与交付

### 目标

冻结 accepted Artifact，生成可继续分析的 AI Native 交付包。

### 输入

- S00–S08 的 accepted `stage-manifest.json`
- `workflow/workflow-state.json`
- `S07/recovered-repository/`
- `S07/recovery-index.json`
- `S08/audit-summary.json`
- `S08/rework-plan.json`
- `S08/findings.jsonl`
- `S08/coverage.json`
- `S06/ida-stage.i64`

### 产物

| Artifact | 内容 |
|---|---|
| `S09/delivery-manifest.json` | 全部交付文件、schema、hash、producer |
| `S09/final-report.md` | 结果、覆盖率、发现、限制 |
| `S09/final-unknowns.jsonl` | 合并后的未知项 |
| `S09/final-decisions.jsonl` | 关键决定与替代解释 |
| `S09/recovered-repository/` | 冻结的静态恢复仓 |
| `S09/final-ida.i64` | 最终 IDA 数据库 |
| `S09/workflow-trace.jsonl` | Stage/Skill 执行轨迹 |

### Skill 路由编排

```text
accepted S00–S08 artifact set
  -> generate-final-recovery-report
  -> package-recovery-deliverable
  -> validate-artifact-contract
  -> review-stage-output
  -> final human delivery gate
  -> orchestrate-hypervisor-recovery marks workflow complete
```

- Report 只能总结 accepted Artifact，不产生新技术结论。
- Packaging 在报告、最终 unknown/decision 汇总完成后执行。
- Delivery manifest 最后生成并覆盖全部交付 hash。
- S09 不允许触发新的二进制分析；发现问题必须回退来源 Stage。

### 退出条件

- **accepted**（Workflow complete）：manifest hash 全通过；无未接受产物；最终人工门禁通过；workflow 标记 complete。
- **rework**：交付缺文件、hash 不一致、报告与 Artifact 不一致，或遗漏 unknown/stubbed/unresolved。
- **blocked**：最终 IDA checkpoint 或 accepted repository 不可读取，无法形成可验证交付包。

### 边界

- 只冻结、索引和总结，不重新分析、重命名或修改 accepted Artifact。
- 不隐藏 unknown、accepted-risk、stubbed 或 unresolved。
- 不把原型工具、临时文件和未接受草稿打入交付。
- 最终报告必须重申单文件、静态、IDA-only 和非安全证明边界。
