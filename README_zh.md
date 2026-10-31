# traceshield 🛡️

**AI 智能体行为的审计追踪与策略执行框架。**

智能体的每一个动作 —— 工具调用、API 请求、文件写入、决策判断 —— 都被实时记录、归因和策略校验。就像为你的智能体集群提供不可篡改的操作审计日志。

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](tsconfig.json)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](tests/)

[English](./README.md) | **中文**

---

## 问题背景

AI 智能体是自主运行的。当出现问题 —— 一次错误的 API 调用、一次策略违规、一次意外输出 —— 你需要答案：

- **智能体究竟做了什么？**
- **它为什么做出那个决策？**
- **谁授权了这个操作？**
- **它是否遵守了我们的策略？**

没有 traceshield，回答这些问题意味着翻阅杂乱无章的日志。有了 traceshield，每个操作都经过加密链接、归因标注和策略校验。

---

## 功能特性

- 📝 **不可篡改的追踪日志** — 每个智能体动作均以哈希链方式记录，确保完整性
- 🔗 **行为归因** — 将每个操作链接到触发它的智能体、用户和请求
- 🚦 **策略引擎** — 定义规则（YAML 或代码），自动拦截或标记策略违规
- 🛡️ **运行时守卫** — 在操作执行前拦截并强制执行策略
- 🔍 **审计查询** — 按智能体、时间、操作类型或策略结果查询追踪记录
- 💾 **存储适配器** — 内存存储、SQLite、PostgreSQL
- 🔌 **大模型适配器** — 开箱即用支持 OpenAI、LangChain

---

## 安装

```bash
npm install traceshield
```

持久化存储安装：
```bash
npm install traceshield better-sqlite3   # SQLite
npm install traceshield pg               # PostgreSQL
```

---

## 快速上手

```typescript
import { TraceRecorder, RuntimeGuard, PolicyEngine } from 'traceshield';

// 1. 配置策略引擎
const policy = new PolicyEngine();
policy.loadFromYaml(`
rules:
  - name: 外部-API-需审批
    match: { action: 'http-request', external: true }
    require: { approval: true }
    on_violation: block

  - name: 工具调用速率限制
    match: { action: 'tool-call' }
    limit: { per_minute: 20, per_agent: true }
    on_violation: throttle

  - name: 敏感数据访问日志
    match: { action: 'data-read', tags: ['pii', 'sensitive'] }
    on_match: flag
`);

// 2. 用运行时守卫包装你的智能体
const guard = new RuntimeGuard({ policy });

// 3. 记录追踪信息
const recorder = new TraceRecorder({ guard });

// 拦截智能体操作
const trace = await recorder.record({
  agentId: 'data-processor',
  action: 'data-read',
  resource: 'users.csv',
  tags: ['pii'],
  metadata: { userId: 'u-123' },
}, async () => {
  // 智能体的实际操作
  return await readUserData('users.csv');
});

console.log(trace.id);       // 唯一追踪 ID
console.log(trace.hash);     // 追踪内容的 SHA-256 哈希
console.log(trace.prevHash); // 链接到上一条记录（哈希链）
console.log(trace.policy);   // { outcome: 'flagged', rule: '敏感数据访问日志' }
```

---

## 核心概念

### 哈希链完整性

每条追踪记录包含自身内容的哈希值，以及对前一条记录哈希的引用 —— 形成不可篡改的链条：

```
追踪 #1: hash=abc123, prevHash=null
追踪 #2: hash=def456, prevHash=abc123
追踪 #3: hash=ghi789, prevHash=def456
```

篡改任意记录都会导致链条断裂。验证完整性：

```typescript
const { valid, brokenAt } = await recorder.verifyChain();
if (!valid) {
  console.error(`链条在追踪记录 ${brokenAt.id} 处断裂`);
}
```

### 策略引擎

用 YAML 或 TypeScript 定义策略：

```typescript
policy.addRule({
  name: '删除操作需人工审批',
  match: (action) => action.type === 'delete',
  check: async (action) => {
    const approved = await checkHumanApproval(action);
    return approved ? 'allow' : 'block';
  },
  onViolation: 'block',
  message: '删除操作需要人工审批',
});
```

### 行为归因分析器

追溯任意操作的根本来源：

```typescript
const attribution = await analyzer.trace(traceId);
console.log(attribution);
// {
//   traceId: 'tr-789',
//   agentId: 'data-processor',
//   triggeredBy: { agentId: 'coordinator', traceId: 'tr-456' },
//   userRequest: { userId: 'u-001', sessionId: 'sess-123' },
//   causalChain: ['tr-123', 'tr-456', 'tr-789'],
// }
```

---

## 大模型适配器

### OpenAI
```typescript
import { OpenAIAdapter } from 'traceshield/adapters/openai';

const tracedClient = new OpenAIAdapter(openai, recorder);
// 所有补全、工具调用和 Embedding 请求均自动记录
const response = await tracedClient.chat.completions.create({...});
```

### LangChain
```typescript
import { TraceShieldCallbackHandler } from 'traceshield/adapters/langchain';

const handler = new TraceShieldCallbackHandler(recorder);
const chain = new LLMChain({ ..., callbacks: [handler] });
```

---

## 审计查询

```typescript
// 查询过去一小时内某智能体的所有追踪记录
const traces = await recorder.query({
  agentId: 'data-processor',
  from: Date.now() - 3600_000,
  actionTypes: ['data-read', 'tool-call'],
});

// 查询所有策略违规记录
const violations = await recorder.query({
  policyOutcome: ['blocked', 'flagged'],
  limit: 100,
});

// 生成完整审计报告
const report = await recorder.auditReport({
  from: startOfDay,
  to: endOfDay,
  groupBy: 'agent',
});
```

---

## 合规报告

把录制的追踪数据直接转成审计可用的报告，覆盖真正决定企业采购的三大框架。
三者共用同一套聚合逻辑，避免不同标准之间数字口径不一致。

```typescript
import {
  generateSOC2Report,
  generateGDPRReport,
  generateHIPAAReport,
  generateComplianceReport,
  formatReportAsMarkdown,
} from 'traceshield';

const traces = await recorder.getTraces({ from, to });

// 显式指定框架
const hipaa = generateHIPAAReport(traces, { coveredEntity: 'Acme Health' });

// 或运行时选择（CLI 参数 / 配置项）
const report = generateComplianceReport(traces, 'soc2', { orgName: 'Acme' });

console.log(formatReportAsMarkdown(report));
```

**各报告包含什么**

- **共同部分** —— 摘要（追踪数、违规数、拦截/告警计数、合规率、平均延迟、
  覆盖智能体数）、按规则聚合的违规明细（含受影响智能体与示例）、按智能体的
  合规表格，以及框架专属的建议清单。
- **SOC 2**（`generateSOC2Report`）—— 组织/审计方字段，SOC 2 Type II 口径。
- **GDPR**（`generateGDPRReport`）—— 数据控制者归属与 DPIA 建议。（此前该
  报告的 `violations` / `agents` 被硬编码为空数组，现已与 SOC 2 共用聚合。）
- **HIPAA**（`generateHIPAAReport`）—— PHI 相关能力：
  - **PHI 访问计量** —— 按 span 名（`patient` / `medical` / `ehr` 等）、
    `metadata.data_classification` 标记（`phi` / `ephi` / `restricted`）或
    `metadata.phi: true` 标志识别触及受保护健康信息的动作。
  - **§164.312 条款映射** —— 报告每项控制对应的条款（访问控制 `(a)(1)`、
    审计控制 `(b)`、完整性 `(c)(1)`、传输安全 `(e)(1)`）。
  - **PHI 专属建议** —— PHI 动作违规时给出 CRITICAL 提示、§164.316(b)(2)(i)
    的 6 年留存要求，以及加密与年度风险评估提醒。
  - Markdown 渲染器会额外输出**PHI 访问表**，审计方无需翻 JSON。

---

## 对比同类方案

| 功能 | traceshield | LangSmith | Helicone | 自定义日志 |
|------|------------|-----------|----------|-----------|
| 哈希链完整性 | ✅ | ❌ | ❌ | ❌ |
| 策略执行 | ✅ | ❌ | ❌ | ❌ |
| 行为归因追踪 | ✅ | ✅ | ❌ | ❌ |
| 自托管支持 | ✅ | ⚠️ | ❌ | ✅ |
| 大模型适配器 SDK | ✅ | ✅ | ✅ | ❌ |

---

## 路线图

- [x] **合规报告模板（SOC2、GDPR、HIPAA）**（`generateHIPAAReport` + `generateComplianceReport` 统一分发；HIPAA 含 PHI 访问审计与 §164.312 条款映射）✅ (v0.10.0)
- [ ] 实时违规 Webhook 通知
- [ ] 基于 GitOps 的策略即代码集成
- [ ] 敏感追踪数据的差分隐私保护
- [ ] `traceshield` CLI 用于审计调查
- [ ] 多智能体归因关系图可视化

---

## 许可证

Apache 2.0 © cdzzy

