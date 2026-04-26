# Phase 2: Probe Interface Unification - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-26
**Phase:** 02-Probe Interface Unification
**Areas discussed:** Probe interface signature, Type-erased result container, Middleware composition, Scanner declarative execution, Probe registration mechanism, Migration path

---

## Probe Interface Signature

| Option | Description | Selected |
|--------|-------------|----------|
| Run(ctx, target, opts) Result | Probe 特定参数放 opts struct，Scanner 统一调用 | ✓ |
| Builder / 链式调用 | Builder 模式：probe.WithSNI().WithALPN().Run(ctx, target) | |

**User's choice:** Run(ctx, target, opts) Result
**Notes:** opts struct 在构造 Probe 时传入（非每次调用），接口保持统一。

---

## Type-Erased Result Container

| Option | Description | Selected |
|--------|-------------|----------|
| Type + Data 判别联合 | []ProbeResult{Type Layer, Data any} 判别联合 | ✓ |
| map[Layer][]any | 简单但类型不安全 | |
| 保持现状（不重构）| Per-probe 命名切片字段，加新协议仍需改 TargetResult | |

**User's choice:** Type + Data 判别联合
**Notes:** TargetResult 改为 Results []ProbeResult + Findings []Finding。这是核心突破性变更。

---

## Middleware Composition

| Option | Description | Selected |
|--------|-------------|----------|
| Timeout→Retry→Logging | 函数式 Middleware func(Probe) Probe，放在 internal/probe/middleware/ | ✓ |
| 其他顺序或模式 | 不同的顺序或装饰器 struct 模式 | |

**User's choice:** Timeout→Retry→Logging
**Notes:** 外层到内层：Timeout → Retry → Logging。

---

## Scanner Declarative Execution

| Option | Description | Selected |
|--------|-------------|----------|
| []Probe 列表 + 选项过滤 | 简单列表 + Scanner 层根据 --trace/--quic 过滤 | ✓ |
| Phase struct 带元数据 | 更结构化的 []Phase{Name, Required, Optional} | |

**User's choice:** []Probe 列表 + 选项过滤
**Notes:** Probes 在注册表构建时筛选，Scanner 只接收本次要执行的 probes。

---

## Probe Registration

| Option | Description | Selected |
|--------|-------------|----------|
| map[Layer]Probe 全局注册表 | 每个 probe import 后自动注册，Scanner 导入包触发副作用 | ✓ |
| Scanner 显式声明（无注册表）| 明确但不灵活 | |

**User's choice:** map[Layer]Probe 全局注册表
**Notes:** Registry 放在 internal/probe/probe.go，每个 probe init() 注册。

---

## Migration Path

| Option | Description | Selected |
|--------|-------------|----------|
| 六步渐进迁移 | 接口→Middleware→Adapter→Scanner→消费者→删旧 API | |
| 一次性大重构 | 全部同步修改 | ✓ |

**User's choice:** 一次性大重构
**Notes:** 所有 internal 变更一次性完成。代码量适中（~2000行），现有测试做回归。

---

## Claude's Discretion

- Probe 特定 opts struct 字段设计
- Middleware 具体实现
- ProbeResult struct 字段和 JSON tag
- Registry 初始化和错误处理
- 测试适配策略

## Deferred Ideas

None — discussion stayed within phase scope.
