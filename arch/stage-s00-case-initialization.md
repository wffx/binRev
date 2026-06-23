# S00：Case 初始化与边界锁定

## 核心目标

S00 不做逆向分析。它负责创建一个唯一、不可混淆的分析 Case，并锁定后续所有
AI Skill 必须遵守的边界。

一句话概括：

> S00 固定“分析的是哪个文件、已知什么、允许使用什么、不能声称什么”。

## 具体需要做什么

### 1. 固化唯一输入

将用户提供的唯一二进制保存为：

```text
cases/<case-id>/input/Image
```

记录：

- Case ID
- SHA-256
- 文件大小
- 输入路径
- 已知格式
- little-endian 字节序

后续每个 Artifact 都必须引用相同的 Case ID 和 Image SHA-256。

### 2. 区分事实与业务背景

已知事实：

- 文件是 ARM64 boot executable `Image`
- little-endian

业务背景：

- 目标可能运行于 EL2
- 可能包含 CPU/vCPU、VM 配置、Stage-2、调度、生命周期、HKIP 和中断直通

业务背景只能指导后续搜索，不能直接作为函数命名或模块确认的证据。

### 3. 生成机器可读约束

约束至少包含：

```text
唯一输入：Image
外部逆向工具：IDA/IDAPython
动态分析：禁止
外部源码和符号：禁止
外部 DTB、日志和配置：禁止
目标特定平台资料：禁止
Hex-Rays：可选
可编译/可运行声明：禁止
行为等价声明：禁止
安全证明声明：禁止
```

## 输入

```text
input/Image
case-request.json
```

`case-request.json` 只允许包含格式、字节序和业务背景，不得包含未经验证的目标事实。

## Skills

```text
initialize-hypervisor-recovery-case
  → enforce-recovery-constraints
  → validate-artifact-contract
  → review-stage-output
  → human gate
  → orchestrate-hypervisor-recovery
```

## 产物

```text
S00/
├── case-manifest.json
├── constraint-profile.json
├── evidence-index.json
├── decision-index.json
├── unknown-index.json
└── records/

workflow/
└── workflow-state.json
```

## 不做什么

- 不解析 Image 头。
- 不分析汇编。
- 不启动 IDA。
- 不创建函数或类型。
- 不判断是否真的存在 Hypervisor 功能。
- 不生成恢复代码。

## 完成标准

可以进入 S01：

- 唯一 Image 已固定并生成 SHA-256。
- 已知事实与业务背景已分离。
- 约束明确外部工具只有 IDA。
- 后续不可宣称的能力边界已写入 constraint profile。
- Review 和人工门禁均通过。

必须停止：

- 输入无法读取。
- 输入实际不是单一文件。
- 用户要求强制引入固定边界之外的材料或工具。
