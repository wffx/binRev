## S04：运行时基础对象模型

### 目标

恢复 CPU/vCPU 与 Stage-2 memory 两个基础模型，并建立对象所有权关系。

### 输入

- `S02/stage-manifest.json`
- `S02/program-model.json`
- `S02/functions.jsonl`
- `S02/call-graph.json`
- `S02/data-objects.jsonl`
- `S02/data-islands.jsonl`
- `S02/indirect-targets.jsonl`
- `S02/unresolved-regions*.jsonl`
- `S03/stage-manifest.json`
- `S03/architecture-model.json`
- `S03/context-layouts.jsonl`
- `S03/sysreg-accesses.jsonl`
- `S03/architecture-events.jsonl`
- `S03/ida-stage.i64`
- `S02/evidence-index.json`、`decision-index.json`、`unknown-index.json`
- `S03/evidence-index.json`、`decision-index.json`、`unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S04/cpu-vcpu-model.json` | CPU、per-CPU、vCPU、context ownership |
| `S04/stage2-memory-model.json` | VMID、VTTBR、descriptor、map/unmap/protect |
| `S04/runtime-object-model.json` | CPU/vCPU/memory 的交叉关系 |
| `S04/function-clusters.json` | 函数按 CPU/vCPU/Stage-2 的聚类归属 |
| `S04/types.jsonl` | 结构、字段和 enum 候选 |
| `S04/resource-ownership.jsonl` | 对象所有权与共享关系 |
| `S04/ida-change-proposal.json` | CPU/vCPU/Stage-2 函数重命名提案 + 类型应用提案 |
| `S04/ida-stage.i64` | 运行时基础模型 checkpoint |
| `S04/records/<producer>.*.jsonl` | 三个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
S02 program + S03 architecture
  +-> recover-hypervisor-cpu-vcpu-model ------+
  +-> recover-hypervisor-stage2-memory-model -+-> integrate-hypervisor-runtime-model
                                                -> review-stage-output
                                                -> human ownership/type gate
                                                -> apply-reviewed-ida-changes
                                                -> snapshot-ida-analysis-state
                                                -> validate-artifact-contract
                                                -> orchestrate-hypervisor-recovery
```

- CPU/vCPU 与 Stage-2 Worker 并行，使用同一 S03 checkpoint。
- 两个 Worker 不读取彼此草稿，避免循环推断。
- Integration Skill 负责统一 VM、vCPU、CPU、VMID、page ownership 引用。
- 安全关键类型与 ownership 需要人工门禁。
- S04 输出必须标记 `s05_readiness`：若 runtime ownership 基础已建立（至少 1 个 object-like root），标记为 ready；否则标记为 blocked_until_s04_owner_root。
- S04 不得将 blocking unresolved blob 内的片段用作 CPU/vCPU、VMID 或 Stage-2 ownership 的证据。
- S04 识别的 teardown/rollback/free/remove/unmap-like 函数和 setup/activate 函数均以候选形式记录；ownership 闭合（teardown↔setup 指向同一 owner 根）由 S05 完成。
- S04 integration 必须输出 root-class 统计；当 `object_like_count == 0` 时，S05 gate 标记为 `blocked_until_s04_object_like_owner_root`。

### 退出条件

- **accepted**：CPU/vCPU 和 Stage-2 模型均存在；交叉引用一致；setup/activate/teardown 的 owner-root 闭合已证明或不影响下游消费；无法确定关系已登记 Unknown。
- **rework**：context owner、VMID、页所有权或 descriptor 解释冲突；新证据否定 S04 context。
- **blocked**：无法识别 vCPU/context 或 Stage-2 根对象，导致 S05 无法关联服务对象；或 root classification 中无 object-like root，导致资源生命周期无法闭合；或上游 S02/S03 未 accepted，导致 runtime ownership 无法安全建立。

### 边界

- 只恢复运行时基础对象和 ownership，不恢复调度策略、VM 配置格式、IRQ route 或生命周期名称。
- 不得用业务背景直接命名结构字段。
- 具体页表粒度、VMID 位宽和 descriptor 含义必须有指令证据。
- 两个并行 Worker 不能互相强化未经集成验证的假设。
