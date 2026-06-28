## S06：生命周期与 HKIP

### 目标

恢复资源生命周期、错误回滚和 HKIP 保护状态，并整合跨子系统转换。

### 输入

- `S04/runtime-object-model.json`
- `S04/resource-ownership.jsonl`
- `S04/types.jsonl`
- `S05/service-model.json`
- `S05/vm-config-model.json`
- `S05/scheduler-model.json`
- `S05/interrupt-model.json`
- `S05/state-machines.jsonl`
- `S03/architecture-model.json`
- `S03/architecture-events.jsonl`
- `S03/call-graph.json`
- `S03/sysreg-accesses.jsonl`
- `S04/stage2-memory-model.json`
- `S05/ida-stage.i64`
- `S04/evidence-index.json`、`decision-index.json`、`unknown-index.json`
- `S05/evidence-index.json`、`decision-index.json`、`unknown-index.json`

### 产物

| Artifact | 内容 |
|---|---|
| `S06/lifecycle-model.json` | create/load/start/pause/reset/destroy 候选 |
| `S06/hkip-model.json` | 保护对象、权限变化、校验与 violation path |
| `S06/resource-transitions.jsonl` | VMID/page/IRQ/CPU binding 生命周期 |
| `S06/security-lifecycle-model.json` | 生命周期与 HKIP 的集成模型 |
| `S06/ida-change-proposal.json` | lifecycle/HKIP 函数重命名提案 |
| `S06/ida-stage.i64` | 生命周期/HKIP checkpoint |
| `S06/records/<producer>.*.jsonl` | 三个 Producer 的 Evidence、Decision、Unknown 分片 |

### Skill 路由编排

```text
S04 runtime + S05 service + S03 architecture
  +-> recover-hypervisor-vm-lifecycle -+
  +-> recover-hypervisor-hkip-model ----+-> integrate-hypervisor-security-lifecycle
                                          -> review-stage-output
                                          -> human lifecycle/HKIP gate
                                          -> apply-reviewed-ida-changes
                                          -> snapshot-ida-analysis-state
                                          -> validate-artifact-contract
                                          -> orchestrate-hypervisor-recovery
```

- Lifecycle 与 HKIP Worker 可并行读取 accepted models。
- 集成时必须交叉检查 page、VMID、IRQ、CPU binding 与权限状态。
- Worker 输出状态候选，Integration 才能建立跨子系统 transition。
- 人工门禁确认 HKIP 保护对象、violation path 和资源终止状态。

### 退出条件

- **accepted**：生命周期与 HKIP 模型完成或显式 unknown；正常/回滚路径均纳入；资源转换无未解释冲突。
- **rework**：状态转换矛盾、资源泄漏模型与 S05/S06 冲突、HKIP 仅由算法相似性支持。
- **blocked**：无法识别任何资源状态写入或权限变化路径，导致 S08 核心安全审计无对象。

### 边界

- 无证据的状态名称必须使用 `state_0xN`。
- HKIP 不能仅凭 hash/checksum、只读常量或业务背景确认。
- 本 Stage 描述静态状态转换，不声称运行时一定发生。
- 不能把“未发现释放路径”直接判定为漏洞；该结论属于 S09。
