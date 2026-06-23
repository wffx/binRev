# Artifact 与 Stage Contract

本合同是所有 Workflow 运行实例和 Skill 输出的规范接口。

Artifact 是 AI Native Workflow 的唯一交接接口。

## 1. Case 目录

```text
case/
├── input/
│   └── Image
├── workflow/
│   ├── workflow-state.json
│   └── workflow-trace.jsonl
├── stages/
│   ├── S00/
│   ├── S01/
│   └── ...
│       └── S10/
│           └── records/
└── delivery/
```

每个 Stage 只能写自己的 `stages/Sxx/`。S10 可以把 accepted Artifact 复制到 `delivery/`，不得修改原件。

Workflow 文档中的 `Sxx/foo.json` 是 `stages/Sxx/foo.json` 的简写。

初始请求固定为：

```json
{
  "input_path": "input/Image",
  "known_format": "ARM64 boot executable Image",
  "endianness": "little",
  "business_background": [
    "EL2 hypervisor",
    "CPU and vCPU management",
    "VM configuration",
    "Stage-2 memory isolation",
    "shared-core scheduling",
    "VM lifecycle",
    "HKIP",
    "interrupt passthrough"
  ]
}
```

`case-request.json` 不得包含样本外符号、源码结论或平台事实。

## 2. 通用 Artifact Envelope

每个 JSON/JSONL Artifact 必须包含或继承：

```json
{
  "schema_version": "1.0",
  "artifact_type": "program-model",
  "artifact_id": "artifact-uuid",
  "case_id": "case-uuid",
  "stage_id": "S03",
  "producer_skill": "integrate-program-structure",
  "image_sha256": "hex",
  "source_artifacts": [
    {
      "artifact_id": "upstream-artifact-uuid",
      "sha256": "hex"
    }
  ],
  "created_at": "RFC3339 timestamp",
  "content": {}
}
```

规则：

- `source_artifacts` 必须穷举直接依赖。
- Artifact 内容改变时必须生成新 `artifact_id`。
- 不允许原地覆盖 accepted Artifact。
- 二进制和 IDA 文件使用同名 `.meta.json` envelope。

## 3. Evidence Record

```json
{
  "evidence_id": "E-S04-000123",
  "case_id": "case-uuid",
  "stage_id": "S04",
  "producer_skill": "recover-el2-architecture-semantics",
  "source_kind": "image|ida",
  "file_offset": 4096,
  "virtual_address": "0x80001000",
  "byte_length": 4,
  "bytes_sha256": "hex",
  "observation": "MSR VTTBR_EL2, X0",
  "inference": "candidate Stage-2 root/VMID activation",
  "confidence": "confirmed|high|medium|low",
  "limitations": []
}
```

Evidence 必须区分：

- `observation`：二进制或 IDA 中直接可见的事实。
- `inference`：由观察推导的解释。

## 4. Decision Record

```json
{
  "decision_id": "D-S05-000042",
  "stage_id": "S05",
  "object_id": "function:0x80001234",
  "decision": "accept|reject|defer|supersede",
  "subject": "candidate function is Stage-2 map",
  "rationale": "two independent evidence classes",
  "evidence_ids": ["E-S04-000123", "E-S05-000031"],
  "alternatives": ["descriptor allocator", "EL2 page-table map"],
  "review_status": "proposed|reviewed|accepted",
  "reviewer": "skill-or-human-id"
}
```

## 5. Unknown Record

```json
{
  "unknown_id": "U-S06-000017",
  "stage_id": "S06",
  "scope": "indirect-call:0x80004560",
  "description": "target set incomplete",
  "blocking": true,
  "affected_artifacts": ["interrupt-model"],
  "evidence_ids": ["E-S03-000221"],
  "next_action": "return to S03 indirect-control-flow analysis",
  "status": "open|resolved|accepted-risk"
}
```

未知项不得只写在 Markdown 报告中。

每个 Producer Skill 都必须创建自己的 Evidence、Decision 和 Unknown 分片，
即使文件为空。Stage Integration Skill 只生成索引，不把并行分片拼接覆盖。

## 6. IDA Change Contract

IDA 是唯一外部分析工具，也是可变共享状态。所有修改使用两阶段提交。

### Proposal

```json
{
  "transaction_id": "IDA-TX-S05-001",
  "base_snapshot_id": "ida-snapshot-uuid",
  "producer_skill": "recover-hypervisor-stage2-memory-model",
  "review_required": true,
  "actions": [
    {
      "action": "rename",
      "address": "0x80001234",
      "before": "sub_80001234",
      "after": "candidate_stage2_map",
      "evidence_ids": ["E-S04-000123", "E-S05-000031"]
    }
  ]
}
```

### Commit result

```json
{
  "transaction_id": "IDA-TX-S05-001",
  "review_decision_id": "D-S05-000042",
  "result": "committed|partial|failed",
  "before_snapshot_id": "ida-snapshot-uuid",
  "after_snapshot_id": "ida-snapshot-uuid",
  "action_results": []
}
```

Producer Skill 不能直接提交自己的 proposal；必须由 `apply-reviewed-ida-changes` 执行。

## 7. Stage Review Contract

```json
{
  "stage_id": "S05",
  "reviewer_skill": "review-stage-output",
  "input_validation": "pass",
  "output_validation": "pass",
  "evidence_quality": "pass|concern|fail",
  "overclaim_check": "pass|fail",
  "blocking_unknowns": [],
  "rework_items": [],
  "recommendation": "accept|rework|block"
}
```

Orchestrator 只能依据该 recommendation 和授权门禁更新 Stage 状态。

## 8. Stage Manifest

```json
{
  "stage_id": "S05",
  "status": "review_required",
  "input_artifacts": ["artifact-uuid"],
  "output_artifacts": ["artifact-uuid"],
  "producer_skills": [
    "recover-hypervisor-cpu-vcpu-model",
    "recover-hypervisor-stage2-memory-model",
    "integrate-hypervisor-runtime-model"
  ],
  "evidence_index": "S05/evidence-index.json",
  "decision_index": "S05/decision-index.json",
  "unknown_index": "S05/unknown-index.json",
  "review_artifact": "S05/stage-review.json"
}
```

Stage manifest 由 Orchestrator 生成，只索引 Artifact，不复制技术结论。

## 9. Workflow State

```json
{
  "case_id": "case-uuid",
  "image_sha256": "hex",
  "current_stage": "S05",
  "stages": {
    "S00": {"status": "accepted", "artifact_set_id": "set-uuid"},
    "S01": {"status": "accepted", "artifact_set_id": "set-uuid"},
    "S05": {"status": "review_required", "artifact_set_id": "set-uuid"}
  },
  "invalidated_artifacts": [],
  "last_transition": {
    "from": "in_progress",
    "to": "review_required",
    "actor": "orchestrate-hypervisor-recovery",
    "decision_id": null
  }
}
```

## 10. 置信度与状态

### 证据置信度

```text
confirmed > high > medium > low
```

### 恢复对象状态

```text
confirmed
inferred-c
asm-fallback
stubbed
unresolved
```

两者不可混用：置信度描述证据质量，对象状态描述代码仓处理方式。

## 11. Schema 演进

- 新增可选字段：增加 minor version。
- 删除字段或改变语义：增加 major version。
- Skill 必须声明支持的 schema version。
- Orchestrator 不得自动转换不兼容 schema。
