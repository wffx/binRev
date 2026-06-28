# 跨 Stage 规则

## 4. 回退关系

| 发现问题 | 回退 Stage |
|---|---|
| 输入或约束被破坏 | S00 |
| 文件区域划分错误 | S00 |
| base/entry/segment 错误 | S01 |
| 函数、数据、间接控制流错误 | S02 |
| 异常、context、系统寄存器语义错误 | S04 |
| CPU/vCPU 或 Stage-2 ownership 冲突 | S05 |
| 配置、调度、中断关系错误 | S06 |
| 生命周期或 HKIP 状态矛盾 | S06 |
| 代码仓引入无证据行为 | S07 |
| 审计证据不足 | 对应的最早生产 Stage |

下游 Stage 失效时，Orchestrator 必须把所有依赖该 Artifact 的 accepted Stage 标记为 `rework`。

## 5. 人工门禁

以下决定不能由单一 Producer Skill 自动接受：

- Image base 和 entry
- 异常向量确认
- 大范围函数/数据边界
- 安全关键结构体
- candidate 升级为 confirmed
- 资源 ownership 模型
- HKIP 保护对象与 violation path
- 安全不变量结论
- 最终交付接受

Reviewer Skill 负责生成审查建议；最终门禁可以由用户或被授权的独立 Review Agent 接受。
## S02 forward-test oracle addendum

This addendum is part of the S02 workflow contract and applies only to lab validation runs where a paired symbolized IDB is explicitly provided by the user.

### Scope

- A symbolized oracle such as `tests/xen-syms_arm64.i64` is a validation-only artifact.
- It may be used to tune S02 function-boundary and `.inst fallback` recovery in the test case.
- It is not a production input and must not appear as evidence in recovered production `functions.jsonl`, `data-objects.jsonl`, `call-graph.json`, or final source-map claims.

### Ordered workflow

1. Build an oracle relation from byte/function fingerprints, dominant address delta, size, and branch-local CFG shape.
2. Use target-only IDA evidence to make the primary S02 proposal.
3. Compare the target proposal against the oracle and write the report under `validation/oracle/`.
4. If the user explicitly authorizes oracle-assisted lab repair, convert only target words that map to oracle code and record the action as `validation_only`.
5. Re-export target word state after every apply pass.
6. Repeat apply/readback until oracle-code candidates reach zero, or record the remaining candidates as S02 residual blockers.

### Exit rule

S02 remains `rework_required` if any non-waived target middle `.text` word is still:

- mapped to oracle code but not represented as target code,
- represented only by stale `.inst fallback` comments,
- hidden by IDA item-head/tail ambiguity,
- or blocked by function-boundary/segment-coverage mismatch.

Only after those residuals are fixed, waived with explicit reviewed rationale, or proven to be outside target `.text` may S02 proceed to S04.

When residuals are waived, S02 may be marked `accepted` only if:

- each waived address is represented in `accepted-risk-*.jsonl`,
- `stage-manifest.json` records `residual_policy.status = accepted-risk`,
- downstream stages include the accepted-risk artifact in their input provenance,
- and any downstream conclusion directly depending on a waived address is downgraded to `inferred` or `unresolved`.

## 函数级 Codegen 门禁

只有 output_class 为 lifted-c、semantic-c或 sm-fallback 的函数可以创建源文件。unresolved 记录不得创建空壳内部源文件。

### 边界不匹配规则

若目标地址是疑似函数 root，但 IDA 只提供了起始地址不同的包含函数，候选不是 codegen_ready。记录为 oundary_mismatch，回退 S02/S06 进行边界修复，不应将包含函数 lifted 到代码仓。

### Source-map 规则

每个生成的源函数必须有：
- 目标地址；
- 原始 IDA 名称；
- 主源符号；
- 源文件路径；
- output class；
- 置信度；
- 证据来源。

在声称 source_repo_ready 的仓库中，地址和 IDA 名称可以出现在注释和 source map 中，但不得占主导地位于主源符号之上。
