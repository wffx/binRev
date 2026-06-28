# `stage-audit.md` 强制模板

每个 Stage 完成时必须产出 `Sxx/stage-audit.md`，遵循以下固定结构。缺少任何一节视为合同不完整。

## 强制结构

```markdown
# Sxx Audit: <Stage 名称>

**Status:** `accepted|rework|blocked` | **<readiness_flag>:** <value> | **Case:** `<case_id>`

---

## 1. 输入

列出本 Stage 消费的上游 Artifact，说明来源 Stage 和具体用途。

| 输入 | 来源 | 用途 |
|---|---|---|
| Sxx/artifact.json | Sxx <stage name> | 用于 <purpose> |

---

## 2. 执行过程

逐个 Skill 描述做了什么操作、收集了什么数据、产出了什么。

### Skill A: `<skill-name>`

**做了什么**: <具体操作描述：IDA 查询了什么、扫描了什么模式、分析了什么数据>

**关键数据**:
- <关键统计数字 1>
- <关键统计数字 2>

**产出**: `Sxx/<output-file>`

### Skill B: ...

（每个 Worker Skill 和 Integration Skill 各一节）

---

## 3. IDA 重命名（已应用）

若本 Stage 有 IDA 修改，列出每一个重命名/类型声明。若没有，写明"本 Stage 无 IDA 修改"。

| # | 原名称 | 新名称 | 类型 | 理由 |
|---|---|---|---|---|
| 1 | `sub_NNNN` | `candidate_xxx` | <category> | <rationale> |

**累计重命名**: <previous stage count> + <this stage count> = **<total>** 个 candidate_ 函数

---

## 4. 关键决策

列出本 Stage 做出的每一项重要判断，每个决策必须引用证据。

| ID | 决策 | 证据 |
|---|---|---|
| Sxx-D0001 | <decision> | <evidence> |

---

## 5. 未知项

列出本 Stage 发现的不确定项及其对下游的影响评估。

| ID | 内容 | 影响 |
|---|---|---|
| Sxx-U0001 | <unknown> | <impact level> (<mitigation or downstream resolution>) |

---

## 6. 审查结论

- **stage-review**: `<conclusion>`
- **artifact-validation**: `<pass/fail>`
- **human gate**: `<通过/rework>`
- **<readiness_flag>**: `<value>`
- **Next**: Sxx <next stage name> (<what the next stage will do>)
```

## 强制规则

1. **6 个节缺一不可**。无内容时写明"无"或"不适用"。
2. 每个 Stage 接受前，`stage-audit.md` **必须**通过完成校验清单验证。
3. S07-S09 也不例外——合成、审计、交付 Stage 不能因为"不需要 IDA"就简化审计文档。

1. **6 个节缺一不可**。无内容时写明"无"或"不适用"。
2. **每个 Skill 必须有一节**在"执行过程"中。Worker 和 Integration Skill 各一节，Governance Skill 不需要。
3. **关键决策**每个至少引用一条 Evidence ID。
4. **未知项**每条必须标注对下游的影响等级（高/中/低）和消解路径。
5. **累计重命名**跟踪从 S03 开始的 candidate_ 函数总数。
6. **标题中的 readiness flag**随 Stage 不同而变化：
   - S00: `tool_ready`
   - S01: `s02_ready`
   - S02: `s03_ready`
   - S03: `s04_readiness`
   - S04: `s05_readiness`
   - S05: `s06_readiness`
   - S06: `s07_readiness`
   - S07: `repository_status`
   - S08: `audit_status`
    - S09: `delivery_status`

## 完成校验清单

声明 Stage 完成前，必须逐项验证以下文件存在于文件系统。**不得跳过，不得依赖记忆。**

### Producer 记录（每个 Producer Skill 产生 3 个文件）
- [ ] `Sxx/records/<skill-1>.evidence.jsonl`
- [ ] `Sxx/records/<skill-1>.decisions.jsonl`
- [ ] `Sxx/records/<skill-1>.unknowns.jsonl`
- [ ] `Sxx/records/<skill-2>.evidence.jsonl`
- [ ] `Sxx/records/<skill-2>.decisions.jsonl`
- [ ] `Sxx/records/<skill-2>.unknowns.jsonl`
- [ ] ... (每个 Producer 重复)

### Governance 层
- [ ] `Sxx/stage-manifest.json`
- [ ] `Sxx/artifact-validation.json`
- [ ] `Sxx/stage-review.json`
- [ ] `Sxx/stage-audit.md` — **必须包含全部 6 个节**（输入、执行过程、IDA重命名、关键决策、未知项、审查结论）。仅检查文件存在不足以保证质量。若缺少任何一节，Stage 不得声明 accepted。

### 内容质量校验
- [ ] `Sxx/evidence-index.json`
- [ ] `Sxx/decision-index.json`
- [ ] `Sxx/unknown-index.json`

### IDA 相关（S02-S06）
- [ ] `Sxx/ida-change-proposal.json`（若本 Stage 有命名职责）
- [ ] `Sxx/ida-change-transactions.jsonl`
- [ ] `Sxx/ida-stage.i64`（若本 Stage 修改了 IDA）
- [ ] `Sxx/records/apply-reviewed-ida-changes.*.jsonl`
- [ ] `Sxx/records/snapshot-ida-analysis-state.*.jsonl`

### 本 Stage 特有产物
- [ ] 逐一对照 Stage spec 产物表中的每个文件
