# Workflow 总览与设计原则

## 始终生效的不变量

以下规则跨越所有 Stage 生效：

1. 生产输入仅为一个目标二进制及其 IDA 派生证据。
2. Oracle/symbolized 二进制仅用于实验室验证，必须存放在 validation/evaluation 产物下，不得进入生产证据链。
3. 每个导出的 IDA 函数必须路由到以下四种 output class 之一：
   semantic-c、lifted-c、sm-fallback、unresolved。
4. lifted-c 和 semantic-c 是独立的输出等级。伪代码证据、注释或 wrapper body 不能将函数提升为 semantic。
5. 规范代码仓路径为 
ecovered-repos/<case-id>/recovered-hypervisor/。
6. cases/<case-id>/stages/ 是证据工作区，不是面向用户的代码仓。
7. 代码仓必须包含 .c、.h、.S 等源文件；JSON/JSONL/IDA/SQLite 等中间产物只属于 evidence outputs。
8. S09 必须保留上游 source status，不得将 source_slice_ready 或 source_corpus_lifted 提升为 source_repo_ready。

## 1. 设计原则

### 1.1 Workflow、Stage、Skill、Artifact 分层

- **Workflow**：维护全局状态、Stage 顺序、门禁和回退。
- **Stage**：定义一次有边界的状态转换，只描述目标、输入、输出和验收。
- **Skill**：执行 Stage 内的专业任务；一个 Stage 可以调用一个或多个 Skill。
- **Artifact**：Skill 间唯一允许的交接介质，必须落盘、版本化并带来源。

AI 不得依赖聊天记忆、未落盘推断或其他 Skill 的隐式上下文。任何会影响后续结论的信息都必须写入 Artifact。

### 1.2 固定约束

- 唯一案例输入是一个 little-endian ARM64 boot executable `Image`。
- 样本特定知识只有文件格式与 Hypervisor 业务背景。
- 外部逆向工具只有 IDA；允许 IDAPython，Hex-Rays 可选。
- 不使用外部源码、符号、日志、DTB、平台资料、动态环境或其他逆向工具。
- Skill 可携带通用 ARM64/EL2、Image 格式和逆向方法知识，但不得携带目标特定源码或签名库。
- 交付是静态恢复代码仓和证据，不承诺可编译、可运行、行为等价或安全证明。

### 1.3 Stage 状态机

每个 Stage 只能处于以下状态：

```text
pending -> in_progress -> review_required -> accepted
                          |                  |
                          v                  v
                        rework <---------- rework

in_progress/review_required -> blocked
```

- `accepted`：满足 Stage 出口，可以进入下一 Stage。
- `rework`：输出存在可修正问题，回到当前或上游 Stage。
- `blocked`：缺少当前约束下不可获得的必要证据；必须保留未知项，不能猜测补齐。
- 未知项可以非阻塞；只有破坏下游前提的未知项才阻止 Stage 接受。

### 1.4 通用 Stage 门禁

每个 Stage 接受前必须同时满足：

1. 所有必需输入通过 schema、case ID 和 Image SHA-256 校验。
2. 所有必需输出存在且通过 schema 校验。
3. 每个结论引用 Evidence ID。
4. 每个未知项写入 Unknown Registry。
5. 所有 IDA 修改存在 proposal、review 和 transaction record。
6. Reviewer Skill 已产生 `stage-review.json`。
7. Orchestrator 已更新 `workflow-state.json`。
8. 已产生人工审计文档 `stage-audit.md`。
9. **完成校验**：执行者必须在声明"完成"前，逐项对照本 Stage spec 的产物表 + 公共输出表，验证每个文件在文件系统中存在。若缺失任何文件，必须补齐后方可声明 accepted。此校验不得委托给 task agent 或依赖记忆。

每个 Stage 和 Skill 还有三个全局必需输入，不在后续表格中重复：

- `stages/S00/case-manifest.json`
- `stages/S00/constraint-profile.json`
- `workflow/workflow-state.json`

每个 Stage 还必须产生以下公共输出，不在各 Stage 表格中重复：

| Artifact | Owner Skill |
|---|---|
| `Sxx/stage-manifest.json` | `orchestrate-hypervisor-recovery` |
| `Sxx/artifact-validation.json` | `validate-artifact-contract` |
| `Sxx/stage-review.json` | `review-stage-output` |
| `Sxx/stage-audit.md` | `orchestrate-hypervisor-recovery`；必须遵循 [人工审计文档模板](08-stage-audit-template.md) |
| `Sxx/records/<producer>.evidence.jsonl` | 对应 Producer Skill；文件必须存在，可为空 |
| `Sxx/records/<producer>.decisions.jsonl` | 对应 Producer Skill；文件必须存在，可为空 |
| `Sxx/records/<producer>.unknowns.jsonl` | 对应 Producer Skill；文件必须存在，可为空 |
| `Sxx/evidence-index.json` | 当前 Stage 的 Integration Skill；无 Integration Skill 时由 Orchestrator 生成 |
| `Sxx/decision-index.json` | 当前 Stage 的 Integration Skill；无 Integration Skill 时由 Orchestrator 生成 |
| `Sxx/unknown-index.json` | 当前 Stage 的 Integration Skill；无 Integration Skill 时由 Orchestrator 生成 |

### 1.5 Stage Contract 强制模板

每个 Stage 必须按以下顺序定义，缺少任何一项即视为合同不完整：

```text
### 目标
### 输入
### 产物
### Skill 路由编排
### 退出条件
### 边界
```

- **目标**：只描述本 Stage 完成的一次状态转换。
- **输入**：列出具体 Artifact 路径、版本要求和 accepted checkpoint；不得只写“上游结果”。
- **产物**：列出具体路径、内容和唯一 Owner Skill。
- **Skill 路由编排**：明确串行、并行、依赖、Integration、Review、人工门禁、IDA commit 和 checkpoint。
- **退出条件**：分别定义 `accepted`、`rework`、`blocked`。
- **边界**：明确不属于本 Stage 的分析、禁止证据、禁止工具和不可声明的结论。
