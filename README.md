# traceshield 🛡️

**Audit trail and policy enforcement for AI agent actions.**

Every action an AI agent takes — tool call, API request, file write, decision — is recorded, attributed, and policy-checked in real time. Like an immutable audit log for your agent fleet.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](tsconfig.json)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](tests/)

---

## The Problem

AI agents operate autonomously. When something goes wrong — a bad API call, a policy violation, unexpected output — you need answers:

- **What exactly did the agent do?**
- **Why did it make that decision?**
- **Who authorized this action?**
- **Did it comply with our policies?**

Without traceshield, answering these questions means sifting through unstructured logs. With traceshield, every action is cryptographically chained, attributed, and policy-checked.

---

## Features

- 📝 **Immutable trace log** — every agent action recorded with hash-chain integrity
- 🔗 **Attribution** — link every action to the agent, user, and trigger that caused it
- 🚦 **Policy engine** — define rules (YAML or code) that block or flag policy violations
- 🛡️ **Runtime guard** — intercept actions before they execute and enforce policies
- 🔍 **Audit queries** — query traces by agent, time, action type, or policy outcome
- 💾 **Storage adapters** — in-memory, SQLite, PostgreSQL
- 🔌 **LLM adapters** — OpenAI, LangChain integration out of the box

---

## Installation

```bash
npm install traceshield
```

For persistent storage:
```bash
npm install traceshield better-sqlite3   # SQLite
npm install traceshield pg               # PostgreSQL
```

---

## Quick Start

```typescript
import { TraceRecorder, RuntimeGuard, PolicyEngine } from 'traceshield';

// 1. Set up policy engine
const policy = new PolicyEngine();
policy.loadFromYaml(`
rules:
  - name: no-external-api-without-approval
    match: { action: 'http-request', external: true }
    require: { approval: true }
    on_violation: block

  - name: rate-limit-tool-calls
    match: { action: 'tool-call' }
    limit: { per_minute: 20, per_agent: true }
    on_violation: throttle

  - name: log-sensitive-data-access
    match: { action: 'data-read', tags: ['pii', 'sensitive'] }
    on_match: flag
`);

// 2. Wrap your agent with the runtime guard
const guard = new RuntimeGuard({ policy });

// 3. Record traces
const recorder = new TraceRecorder({ guard });

// Intercept agent actions
const trace = await recorder.record({
  agentId: 'data-processor',
  action: 'data-read',
  resource: 'users.csv',
  tags: ['pii'],
  metadata: { userId: 'u-123' },
}, async () => {
  // Your agent's actual action
  return await readUserData('users.csv');
});

console.log(trace.id);          // unique trace ID
console.log(trace.hash);        // SHA-256 of trace content
console.log(trace.prevHash);    // links to previous trace (hash chain)
console.log(trace.policy);      // { outcome: 'flagged', rule: 'log-sensitive-data-access' }
```

---

## Core Concepts

### Hash Chain Integrity

Every trace record includes a hash of its content plus a reference to the previous hash — forming an immutable chain:

```
Trace #1: hash=abc123, prevHash=null
Trace #2: hash=def456, prevHash=abc123
Trace #3: hash=ghi789, prevHash=def456
```

Tampering with any record breaks the chain. Verify integrity:

```typescript
const { valid, brokenAt } = await recorder.verifyChain();
if (!valid) {
  console.error(`Chain broken at trace ${brokenAt.id}`);
}
```

### Policy Engine

Define policies in YAML or TypeScript:

```typescript
policy.addRule({
  name: 'require-human-approval-for-deletions',
  match: (action) => action.type === 'delete',
  check: async (action) => {
    const approved = await checkHumanApproval(action);
    return approved ? 'allow' : 'block';
  },
  onViolation: 'block',
  message: 'Deletion requires human approval',
});
```

### Attribution Analyzer

Trace the root cause of any action:

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

## LLM Adapters

### OpenAI
```typescript
import { OpenAIAdapter } from 'traceshield/adapters/openai';

const tracedClient = new OpenAIAdapter(openai, recorder);
// All completions, tool calls, and embeddings are automatically traced
const response = await tracedClient.chat.completions.create({...});
```

### LangChain
```typescript
import { TraceShieldCallbackHandler } from 'traceshield/adapters/langchain';

const handler = new TraceShieldCallbackHandler(recorder);
const chain = new LLMChain({ ..., callbacks: [handler] });
```

---

## Audit Queries

```typescript
// Get all traces for an agent in the last hour
const traces = await recorder.query({
  agentId: 'data-processor',
  from: Date.now() - 3600_000,
  actionTypes: ['data-read', 'tool-call'],
});

// Get policy violations
const violations = await recorder.query({
  policyOutcome: ['blocked', 'flagged'],
  limit: 100,
});

// Full audit report
const report = await recorder.auditReport({
  from: startOfDay,
  to: endOfDay,
  groupBy: 'agent',
});
```

---

## Comparison

| Feature | traceshield | LangSmith | Helicone | Custom Logging |
|---------|------------|-----------|----------|----------------|
| Hash-chain integrity | ✅ | ❌ | ❌ | ❌ |
| Policy enforcement | ✅ | ❌ | ❌ | ❌ |
| Attribution tracing | ✅ | ✅ | ❌ | ❌ |
| Self-hosted | ✅ | ⚠️ | ❌ | ✅ |
| LLM adapter SDK | ✅ | ✅ | ✅ | ❌ |

---

## Roadmap

- [x] ~~Compliance report templates~~ ✅ (src/compliance-reports.ts)
- [x] **Real-time violation webhooks** (src/webhook-notifier.ts — Slack/PagerDuty/generic HTTP POST on violations)
- [ ] Policy-as-code with GitOps integration
- [ ] Differential privacy for sensitive trace data
- [ ] `traceshield` CLI for audit investigation
- [ ] Multi-agent attribution graph visualization
- [x] ~~MCP Event Listener~~ ✅ (automatic tracing and policy enforcement for MCP tool calls)

---

## License

Apache 2.0 © cdzzy
