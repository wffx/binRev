## S01：IDA 基线与地址空间

### 目标

在 IDA 中建立可追溯基线，确认或保留 Image base、entry 和 segment 候选。

### 输入

- `S00/image-header.json`
- `S00/region-map.json`
- `S00/embedded-candidates.json`
- `S00/evidence-index.json`
- `S00/unknown-index.json`
- `input/Image`

### 产物

| Artifact | 内容 |
|---|---|
| `S01/ida-baseline.i64` | 未加入业务语义的 IDA 基线 |
| `S01/ida-baseline-snapshot.json` | segment、function、xref、处理器信息 |
| `S01/address-space.json` | base/entry/segment 候选与结论 |
| `S01/ida-change-transactions.jsonl` | 已执行 IDA 变更 |
| `S01/records/resolve-arm64-load-address.evidence.jsonl` | ADRP、branch、pointer、vector 证据 |
| `S01/records/resolve-arm64-load-address.decisions.jsonl` | base/entry 候选决定 |
| `S01/records/resolve-arm64-load-address.unknowns.jsonl` | 未决地址与 segment |

### Skill 路由编排

```text
prepare-ida-image-database
  -> resolve-arm64-load-address
       -> [candidate iteration if needed]
  -> review-stage-output
  -> human base/entry gate
  -> apply-reviewed-ida-changes
  -> snapshot-ida-analysis-state
  -> validate-artifact-contract
  -> orchestrate-hypervisor-recovery
```

- IDA database 创建与 load-address 分析串行。
- 多个 base candidate 使用独立临时数据库或可回滚 snapshot，禁止在同一状态上叠加。
- 只有人工审核后的 address-space decision 可写入基线。
- Snapshot 是本 Stage 最后一个 Producer 动作。

### 退出条件

- **accepted**：processor/endianness 确认；base 为 `confirmed` 或可供下游显式传播的候选集合；IDA baseline 可重载。
- **rework**：xref 大量越界、候选 base 评分证据冲突、entry 不可解释或 segment 与 S00 冲突。
- **blocked**：没有任何候选地址空间可产生稳定反汇编；此时保留 raw-offset 模式并停止依赖虚拟地址的下游 Stage。

### 边界

- 仅建立地址空间和中性 IDA baseline，不加入业务函数名或安全语义。
- IDA 是唯一外部工具；Hex-Rays 输出不能作为 base 的唯一证据。
- 所有 IDA 修改必须经过 proposal/review/transaction。
- 不能因为 ARM64 Image 头存在就假设 Linux 内核虚拟地址布局。
