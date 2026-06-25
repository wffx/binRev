# Skill Catalog

本文档是 Workflow 涉及 Skill 的规范清单，也是未来创建 `skills/<skill-name>/SKILL.md`
时名称、描述和目标的唯一来源。

## 1. Catalog 规则

每个 Skill 条目包含：

- **名称**：稳定、唯一的 Skill ID。
- **Stage**：Skill 所属 Stage；公共 Skill 标记为 `ALL`。
- **角色**：Orchestrator、Worker、Integrator、Validator、Reviewer、IDA Executor、Synthesizer、Auditor 或 Delivery。
- **描述**：未来可直接改写为 `SKILL.md` frontmatter `description`，包含功能和触发场景。
- **目标**：该 Skill 唯一负责的结果；目标之间不得重叠。

Skill 不负责推进 Workflow 状态，除 `orchestrate-hypervisor-recovery` 外；Skill 不得读取
未在 Stage Contract 中声明的 Artifact。

## 2. 汇总

| 分类 | 数量 |
|---|---:|
| Orchestrator | 1 |
| 公共治理 | 3 |
| S00 Case 初始化 | 2 |
| S01 Image 布局 | 2 |
| S02 IDA 地址空间 | 3 |
| S03 程序结构 | 4 |
| S04 EL2 架构语义 | 5 |
| S05 运行时基础对象 | 3 |
| S06 VM 服务 | 4 |
| S07 生命周期与 HKIP | 3 |
| S08 代码仓合成 | 3 |
| S09 审计 | 4 |
| S10 交付 | 2 |
| **合计** | **39** |

## 3. Skill 索引

| # | Skill | Stage | 角色 |
|---:|---|---|---|
| 1 | `orchestrate-hypervisor-recovery` | ALL | Orchestrator |
| 2 | `validate-artifact-contract` | ALL | Validator |
| 3 | `review-stage-output` | ALL | Reviewer |
| 4 | `apply-reviewed-ida-changes` | S02–S07 | IDA Executor |
| 5 | `initialize-hypervisor-recovery-case` | S00 | Worker |
| 6 | `enforce-recovery-constraints` | S00 | Worker |
| 7 | `analyze-arm64-image-layout` | S01 | Worker |
| 8 | `classify-binary-regions` | S01 | Worker |
| 9 | `prepare-ida-image-database` | S02 | Worker |
| 10 | `resolve-arm64-load-address` | S02 | Worker |
| 11 | `snapshot-ida-analysis-state` | S02–S07 | Worker |
| 12 | `recover-ida-functions` | S03 | Worker |
| 13 | `recover-binary-data-objects` | S03 | Worker |
| 14 | `recover-indirect-control-flow` | S03 | Worker |
| 15 | `integrate-program-structure` | S03 | Integrator |
| 16 | `recover-arm64-boot-flow` | S04 | Worker |
| 17 | `recover-arm64-exception-model` | S04 | Worker |
| 18 | `recover-arm64-context-layout` | S04 | Worker |
| 19 | `recover-el2-architecture-semantics` | S04 | Worker |
| 20 | `integrate-el2-architecture-model` | S04 | Integrator |
| 21 | `recover-hypervisor-cpu-vcpu-model` | S05 | Worker |
| 22 | `recover-hypervisor-stage2-memory-model` | S05 | Worker |
| 23 | `integrate-hypervisor-runtime-model` | S05 | Integrator |
| 24 | `recover-hypervisor-vm-config` | S06 | Worker |
| 25 | `recover-hypervisor-scheduler` | S06 | Worker |
| 26 | `recover-hypervisor-interrupt-routing` | S06 | Worker |
| 27 | `integrate-hypervisor-service-model` | S06 | Integrator |
| 28 | `recover-hypervisor-vm-lifecycle` | S07 | Worker |
| 29 | `recover-hypervisor-hkip-model` | S07 | Worker |
| 30 | `integrate-hypervisor-security-lifecycle` | S07 | Integrator |
| 31 | `synthesize-hypervisor-repository` | S08 | Synthesizer |
| 32 | `generate-recovery-source-map` | S08 | Synthesizer |
| 33 | `index-recovery-evidence` | S08 | Synthesizer |
| 34 | `audit-recovery-static-consistency` | S09 | Auditor |
| 35 | `audit-hypervisor-security-invariants` | S09 | Auditor |
| 36 | `assess-recovery-coverage` | S09 | Auditor |
| 37 | `integrate-recovery-audit` | S09 | Integrator |
| 38 | `write-hypervisor-recovery-report` | S10 | Delivery |
| 39 | `package-hypervisor-recovery-delivery` | S10 | Delivery |

## 4. Orchestrator

### `orchestrate-hypervisor-recovery`

- **Stage**：ALL
- **角色**：Orchestrator
- **描述**：编排单一 ARM64 EL2 Hypervisor `Image` 的 AI Native 静态逆向 Workflow；用于校验当前 Stage 输入、路由 Worker/Integrator/Reviewer Skills、管理并行依赖、更新 Workflow 状态、执行回退和失效传播。不得执行具体逆向分析或直接修改 IDA。
- **目标**：使 S00–S10 严格按照 Stage Contract 推进，并保证每次状态迁移都有可审计的 Artifact、Review 和 Decision。

## 5. 公共治理 Skills

### `validate-artifact-contract`

- **Stage**：ALL
- **角色**：Validator
- **描述**：校验 Stage 输入和输出 Artifact 是否符合 schema、Case ID、Image SHA-256、producer、source artifact、hash 和路径约束；用于任何 Stage 进入 Review 或接受之前的合同验证。
- **目标**：阻止损坏、不兼容、来源不明或跨 Case 的 Artifact 进入下游 Stage。

### `review-stage-output`

- **Stage**：ALL
- **角色**：Reviewer
- **描述**：独立审查某个 Stage 的输入、候选产物、证据质量、未知项、过度推断和退出条件；用于生成 `accept`、`rework` 或 `block` 建议，不参与该 Stage 的 Producer 推断。
- **目标**：为 Stage 门禁提供独立、可追溯且不受 Producer 自我确认影响的审查结论。

### `apply-reviewed-ida-changes`

- **Stage**：S02–S07
- **角色**：IDA Executor
- **描述**：在 IDA 中事务化应用已经审核的 rename、function、type、comment、segment 等 change proposal；用于保存 before/after snapshot、执行结果和失败动作。不得自行提出名称、类型或业务语义。
- **目标**：把已授权的分析结论安全写入 IDA，同时保持可回滚、可复查的状态历史。

## 6. S00 Case 初始化

### `initialize-hypervisor-recovery-case`

- **Stage**：S00
- **角色**：Worker
- **描述**：初始化只有一个 ARM64 boot executable `Image` 输入的恢复 Case；用于固化输入文件、计算 SHA-256、生成 Case ID，并记录文件路径、大小、格式和用户提供的业务背景。
- **目标**：建立后续所有 Artifact 共同引用的唯一 Case 身份和不可变样本基线。

### `enforce-recovery-constraints`

- **Stage**：S00
- **角色**：Worker
- **描述**：根据固定边界生成并检查 Case constraint profile；用于声明唯一输入、IDA-only、静态分析、禁止外部源码/符号/日志/平台资料，以及不可宣称可编译、行为等价或安全证明。
- **目标**：把项目边界转换为机器可读约束，防止下游 Skill 引入未授权输入、工具或结论。

## 7. S01 Image 格式与布局

### `analyze-arm64-image-layout`

- **Stage**：S01
- **角色**：Worker
- **描述**：分析 little-endian ARM64 boot executable `Image` 的文件头、声明大小、flags、magic、appended bytes 和内嵌格式候选；用于生成基于文件偏移的原始布局证据，不推断业务语义或加载虚拟地址。
- **目标**：建立经过校验的 Image header 与内嵌对象候选清单，为区域分类提供确定的文件结构输入。

### `classify-binary-regions`

- **Stage**：S01
- **角色**：Worker
- **描述**：依据 Image header、字节分布、熵、零填充、字符串和内嵌候选，对整个文件划分 header、code candidate、read-only data candidate、writable data candidate、appended data 和 unknown region。
- **目标**：生成无重叠、无遗漏、覆盖整个二进制文件的 region map，并显式保留无法分类的区域。

## 8. S02 IDA 基线与地址空间

### `prepare-ida-image-database`

- **Stage**：S02
- **角色**：Worker
- **描述**：按照 S01 region map 将唯一 `Image` 装载到 IDA AArch64 little-endian 数据库；用于设置中性 segment、processor 和初始 entry candidate，不写入业务名称或高级类型。
- **目标**：建立可供加载地址分析的未污染 IDA baseline 和初始 snapshot。

### `resolve-arm64-load-address`

- **Stage**：S02
- **角色**：Worker
- **描述**：基于 IDA baseline 中的 ADRP/ADD/LDR 闭合、直接分支、绝对指针、异常向量和系统寄存器地址关系，评估 Image base、entry 和 segment 候选；用于保留多候选或提出人工确认建议。
- **目标**：产生证据化的 address-space decision，不在证据不足时伪造唯一加载地址。

### `snapshot-ida-analysis-state`

- **Stage**：S02–S07
- **角色**：Worker
- **描述**：把当前 accepted IDA 状态保存为版本化 `.i64`/IDB 和规范化 JSON snapshot；用于记录 segment、function、xref、type、comment、处理器和地址范围，并生成对应 Artifact metadata。
- **目标**：为每个会修改 IDA 的 Stage 提供可复现、可比较、可回滚的 checkpoint。

## 9. S03 程序结构恢复

### `recover-ida-functions`

- **Stage**：S03
- **角色**：Worker
- **描述**：从 entry、直接调用、异常向量候选、prologue/epilogue、tail call 和 noreturn 路径恢复函数候选；用于输出函数边界、直接调用关系和边界置信度，不赋予业务语义。
- **目标**：建立有证据来源的函数集合，避免将所有 branch target 或数据误建为函数。

### `recover-binary-data-objects`

- **Stage**：S03
- **角色**：Worker
- **描述**：按 text code-first 策略恢复 S03 数据对象与 code/data boundary：主 `.text` 中间优先还原为 ARM64 code，只有 binary header/tail 或明确非 text 区才允许保留外部数据；不可解码 word 必须进入 `.inst`/`instruction_fallback` blocker。
- **目标**：建立与函数候选互补的数据对象模型，并在进入 S04 前完成全量 code/data/data-island 结构修复；主 `.text` 中间 qword/DCQ 或未审核 `.inst fallback` 必须阻塞或 rework。

### `recover-indirect-control-flow`

- **Stage**：S03
- **角色**：Worker
- **描述**：在函数与数据候选基础上恢复 jump table、function pointer table、indirect call 和 indirect branch 的目标集合；用于记录完整、部分或无法解析的间接控制流。
- **目标**：最大化间接控制流可见性，并把未解析目标作为显式 Unknown 传播到后续安全分析。

### `integrate-program-structure`

- **Stage**：S03
- **角色**：Integrator
- **描述**：合并函数、数据对象、text code-first 结果、data-island、code/data boundary 和间接控制流候选，解决函数重叠、未识别 bit/data、code/data 冲突和调用图不一致；用于生成唯一 program model、直接调用图、code-data-boundary audit 和 IDA change proposal。
- **目标**：形成下游架构分析可稳定消费的统一程序结构模型，并保证 S04 输入没有结构性未识别 bit/data 区域。

## 10. S04 ARM64 EL2 架构语义

### `recover-arm64-boot-flow`

- **Stage**：S04
- **角色**：Worker
- **描述**：沿 entry 恢复早期栈、清零、异常级初始化、secondary CPU 和主要控制转移；用于建立启动路径，不提前使用 VM、scheduler 或 HKIP 业务名称。
- **目标**：明确从 Image entry 到主要控制循环或 guest transition 候选的启动链。

### `recover-arm64-exception-model`

- **Stage**：S04
- **角色**：Worker
- **描述**：识别 VBAR_EL2、16 个异常向量 slot、同步异常/IRQ/FIQ/SError handler、公共保存恢复、分发和 ERET 路径；用于建立异常入口到处理/终止路径的模型。
- **目标**：形成可追踪的 EL2 exception model，并显式记录无法解析的 vector 或 handler。

### `recover-arm64-context-layout`

- **Stage**：S04
- **角色**：Worker
- **描述**：依据启动和异常路径中的成组 load/store、固定偏移和 save/restore 对称性恢复 trap、vCPU 和 per-CPU context 候选；字段采用 offset-first 命名。
- **目标**：产生不依赖外部源码结构的 context layout，为运行时对象恢复提供字段级基础。

### `recover-el2-architecture-semantics`

- **Stage**：S04
- **角色**：Worker
- **描述**：识别并解释 ARM64 EL2 system register、HVC/SMC、ERET、TLBI、DMB/DSB/ISB、WFI/WFE、timer 和 GIC architecture event；用于记录指令位置、数据来源和架构效果。
- **目标**：建立由明确指令语义支持的 EL2 architecture event 索引，不把架构动作直接等同于业务模块。

### `integrate-el2-architecture-model`

- **Stage**：S04
- **角色**：Integrator
- **描述**：合并 boot、exception、context 和 architecture event 输出，检测地址、控制流、保存恢复和字段偏移冲突；用于生成唯一 architecture model 和经过审查的 IDA proposal。
- **目标**：形成 S05 可消费的统一 ARM64 EL2 架构语义模型。

## 11. S05 运行时基础对象模型

### `recover-hypervisor-cpu-vcpu-model`

- **Stage**：S05
- **角色**：Worker
- **描述**：结合 MPIDR_EL1、TPIDR_EL2、per-CPU stride、context layout 和调用关系恢复 CPU、per-CPU、vCPU、affinity 和当前执行对象候选。
- **目标**：建立 CPU、vCPU、context 与 VM 引用的基础对象关系，并标明无法确认的 ownership。

### `recover-hypervisor-stage2-memory-model`

- **Stage**：S05
- **角色**：Worker
- **描述**：结合 VTCR_EL2、VTTBR_EL2、HPFAR_EL2、descriptor 位操作、table walk、TLBI 和 barrier 恢复 VMID、Stage-2 root、map/unmap/protect、fault 和 page ownership 候选。
- **目标**：建立有架构证据的 Stage-2 内存隔离模型，不套用外部实现细节。

### `integrate-hypervisor-runtime-model`

- **Stage**：S05
- **角色**：Integrator
- **描述**：合并 CPU/vCPU 与 Stage-2 memory 模型，统一 CPU、vCPU、VM、context、VMID、page 和 ownership 引用；用于检测冲突并生成 types、resource ownership 和 IDA proposal。
- **目标**：形成服务层可依赖的统一 Hypervisor runtime object model。

## 12. S06 VM 服务模型

### `recover-hypervisor-vm-config`

- **Stage**：S06
- **角色**：Worker
- **描述**：从 Image 内部固定数组、对象初始化、校验路径和数据引用恢复 VM、vCPU、memory region、device 和 IRQ 配置候选；不假设存在外部配置文件。
- **目标**：建立内嵌配置数据到运行时对象的映射模型。

### `recover-hypervisor-scheduler`

- **Stage**：S06
- **角色**：Worker
- **描述**：依据 runqueue、runnable/block 状态、timer/IRQ 唤醒、previous/next vCPU、affinity、迁移、锁和 world switch 恢复共核调度候选。
- **目标**：解释一次静态可见的 vCPU 选择和上下文切换路径，并保留未确认策略。

### `recover-hypervisor-interrupt-routing`

- **Stage**：S06
- **角色**：Worker
- **描述**：结合 ICH/ICC system register、GIC 风格 MMIO、route table、注入、maintenance、EOI 和 teardown 恢复 physical IRQ、vIRQ、VM 和 vCPU 路由候选。
- **目标**：建立中断来源到目标 VM/vCPU 的静态路由模型，不无证据确认具体 GIC/SMMU 型号。

### `integrate-hypervisor-service-model`

- **Stage**：S06
- **角色**：Integrator
- **描述**：合并 VM config、scheduler 和 interrupt routing 模型，校验对象引用、状态、ownership 和 service 间关系；用于生成统一 service model、状态机候选和 IDA proposal。
- **目标**：形成生命周期与安全分析可依赖的 VM 服务层模型。

## 13. S07 生命周期与 HKIP

### `recover-hypervisor-vm-lifecycle`

- **Stage**：S07
- **角色**：Worker
- **描述**：从 VM 状态写入、资源创建、错误回滚、启动、暂停、恢复、重置和销毁路径恢复生命周期候选；无证据的状态使用 `state_0xN`。
- **目标**：建立 VM 状态转换与 VMID、page、IRQ、CPU binding 资源变化的静态模型。

### `recover-hypervisor-hkip-model`

- **Stage**：S07
- **角色**：Worker
- **描述**：从保护区、页权限变化、临时写窗口、完整性元数据、校验函数候选、TLBI/barrier 和 violation path 恢复 HKIP 候选模型。
- **目标**：识别 Hypervisor 完整性保护对象和允许/拒绝的修改路径，不仅凭 hash/checksum 相似性确认 HKIP。

### `integrate-hypervisor-security-lifecycle`

- **Stage**：S07
- **角色**：Integrator
- **描述**：合并 VM lifecycle 和 HKIP 模型，交叉检查 page、VMID、IRQ、CPU binding、权限与错误回滚的状态转换；用于生成 security-lifecycle model 和 IDA proposal。
- **目标**：形成 S08 合成与 S09 安全审计所需的统一资源和权限生命周期模型。

## 14. S08 静态代码仓合成

### `synthesize-hypervisor-repository`

- **Stage**：S08
- **角色**：Synthesizer
- **描述**：只依据 S03–S07 accepted 模型合成模块目录、C-like/C 候选、类型定义和符号化 AArch64 `.S`；不重新分析汇编或补写模型外业务逻辑。
- **目标**：把结构化恢复模型转换为可阅读、可追溯的静态代码仓。

### `generate-recovery-source-map`

- **Stage**：S08
- **角色**：Synthesizer
- **描述**：为恢复仓中的每个文件、函数、类型和字段建立到 Image 地址、字节范围、IDA 对象、Evidence ID 和 Decision ID 的映射。
- **目标**：保证每个生成对象都能反向追溯到原始二进制和分析依据。

### `index-recovery-evidence`

- **Stage**：S08
- **角色**：Synthesizer
- **描述**：索引恢复对象、恢复等级、文件路径、source map、unknown、stubbed 和 unresolved 项；用于生成 recovery index 和 unresolved index。
- **目标**：提供完整、机器可读的恢复仓清单与未完成项入口。

## 15. S09 静态一致性与安全审计

### `audit-recovery-static-consistency`

- **Stage**：S09
- **角色**：Auditor
- **描述**：只读审计恢复仓与 program/architecture/runtime/service/lifecycle 模型之间的 CFG、xref、结构偏移、访问宽度、system register、TLBI 和 barrier 一致性。
- **目标**：发现恢复仓遗漏、篡改或过度解释原始静态语义的具体对象。

### `audit-hypervisor-security-invariants`

- **Stage**：S09
- **角色**：Auditor
- **描述**：静态审计跨 VM 映射、HKIP 写保护、vCPU ownership、中断 route 和 VM 销毁资源释放等安全不变量；结论限定为 `supported`、`violated` 或 `unknown`。
- **目标**：识别明确静态反例和证据缺口，不把静态支持表述为安全证明。

### `assess-recovery-coverage`

- **Stage**：S09
- **角色**：Auditor
- **描述**：统计文件区域、函数、直接/间接控制流、数据对象、类型、模块、source map 和安全路径的恢复覆盖情况，并区分 confirmed、candidate 和 unresolved。
- **目标**：量化恢复范围和剩余盲区，为审计结论及后续 rework 提供边界。

### `integrate-recovery-audit`

- **Stage**：S09
- **角色**：Integrator
- **描述**：合并一致性、安全和覆盖率审计输出，归一化 finding、严重度、受影响 Artifact 和最早责任 Stage；用于生成 audit summary 与 rework plan。
- **目标**：形成能够驱动 Workflow 回退或进入交付的统一审计结论。

## 16. S10 收敛与交付

### `write-hypervisor-recovery-report`

- **Stage**：S10
- **角色**：Delivery
- **描述**：仅根据 S00–S09 accepted Artifact 编写最终恢复报告；用于汇总模型、覆盖率、审计发现、限制、未知项和固定约束，不产生新的技术推断。
- **目标**：生成与结构化 Artifact 一致、可供工程与安全人员阅读的最终报告。

### `package-hypervisor-recovery-delivery`

- **Stage**：S10
- **角色**：Delivery
- **描述**：冻结 accepted Artifact、最终 IDA checkpoint、静态恢复仓、报告和 Workflow trace，计算 hash 并生成 delivery manifest；不得包含草稿或未接受 Stage 产物。
- **目标**：生成完整、不可歧义、可校验并可继续分析的最终交付包。

## 17. Skill 创建状态

正式 Skill 按阶段生成，并在每个生成阶段结束后进入人工审计门禁；审计通过前，不继续生成下一阶段。

| 生成阶段 | 范围 | 状态 | 已创建 Skill |
|---|---|---|---|
| G01 | 公共治理 Skills | `accepted` | `validate-artifact-contract`、`review-stage-output`、`apply-reviewed-ida-changes` |
| G02-A | S00–S02 基础闭环 Skills | `accepted` | `initialize-hypervisor-recovery-case`、`enforce-recovery-constraints`、`analyze-arm64-image-layout`、`classify-binary-regions`、`prepare-ida-image-database`、`resolve-arm64-load-address`、`snapshot-ida-analysis-state` |
| G02-B | S03 程序结构 Skills | `rework`（forward-test 发现需优化；不代表生产 Stage 引入符号 oracle） | `recover-ida-functions`、`recover-binary-data-objects`、`recover-indirect-control-flow`、`integrate-program-structure` |
| G02-C | S04 EL2 架构语义 Skills | `forward_test_deferred_by_s03_rework`（boot-slice forward-test 已完成；生产 S04 依赖 S03 accepted，当前 S03-RW4 仍有 12 个 blocking unresolved code/data blob） | `recover-arm64-boot-flow`、`recover-arm64-exception-model`、`recover-arm64-context-layout`、`recover-el2-architecture-semantics`、`integrate-el2-architecture-model` |
| G03 | S05–S07 领域 Skills | `created_blocked_by_upstream`（S05–S07 domain skills 已创建；实测需等待 S03/S04/S05 accepted） | `recover-hypervisor-cpu-vcpu-model`、`recover-hypervisor-stage2-memory-model`、`integrate-hypervisor-runtime-model`、`recover-hypervisor-vm-config`、`recover-hypervisor-scheduler`、`recover-hypervisor-interrupt-routing`、`integrate-hypervisor-service-model`、`recover-hypervisor-vm-lifecycle`、`recover-hypervisor-hkip-model`、`integrate-hypervisor-security-lifecycle` |
| G04 | S08–S10 合成、审计与交付 Skills | `created_blocked_by_upstream`（S08-S10 skills 已创建；实测需等待 S03-S07 accepted） | `synthesize-hypervisor-repository`、`generate-recovery-source-map`、`index-recovery-evidence`、`check-recovered-code-consistency`、`check-hypervisor-security-invariants`、`compute-recovery-coverage`、`integrate-static-audit-report`、`generate-final-recovery-report`、`package-recovery-deliverable` |
| G05 | Orchestrator Skill | `created` | `orchestrate-hypervisor-recovery` |

创建顺序：

1. 公共治理 Skills。
2. S00–S02 基础闭环 Skills。
3. S03 程序结构 Skills。
4. S04 EL2 架构语义 Skills。
5. S05–S07 领域 Skills。
6. S08–S10 合成、审计与交付 Skills。
7. 最后创建 Orchestrator Skill。

每个正式 Skill 创建后，必须验证其 `SKILL.md` description 与本 Catalog 一致；如需修改名称、描述或目标，应先更新本 Catalog 和 Workflow 路由。
