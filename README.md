# TraceShield

> Agent behavior tracing and protection system.

TraceShield provides comprehensive observability, security, and compliance for multi-agent systems. It records agent actions, enforces shield rules, and detects anomalies in real-time.

## Features

- **Comprehensive Tracing** - Record actions, decisions, tool calls, messages, and errors
- **Hierarchical Spans** - Parent-child trace relationships for detailed debugging
- **Shield Rules** - Block, warn, mask, or audit sensitive operations
- **Anomaly Detection** - Automatic detection of error spikes and rate anomalies
- **Audit Logging** - Complete compliance trail for all agent activities
- **Pattern Matching** - Regex-based data filtering and blocking

## Installation

```bash
npm install traceshield
```

## Quick Start

```typescript
import { TraceShield } from 'traceshield';

const shield = new TraceShield({
  tracing: {
    enabled: true,
    level: 'info',
    sampleRate: 1.0,
  },
  shielding: {
    enabled: true,
    failClosed: true,
  },
  audit: {
    enabled: true,
  },
});

// Record an action
const trace = shield.record('agent-1', 'action', {
  action: 'fetch-data',
  target: 'database',
  result: { rows: 100 },
});

// Record a decision
shield.record('agent-1', 'decision', {
  decision: 'route-to-specialist',
  inputs: { query: 'medical', confidence: 0.95 },
  output: 'specialist-agent',
  reasoning: 'High confidence medical query',
});

// Record a tool call
shield.record('agent-1', 'tool_call', {
  tool: 'search',
  arguments: { query: 'AI trends' },
  result: [{ title: 'LLM News', url: '...' }],
  duration: 150,
});

// Add shield rule to block sensitive data
shield.addRule({
  id: 'block-pii',
  name: 'Block PII access',
  enabled: true,
  priority: 100,
  conditions: [
    { type: 'data', field: 'action', operator: 'equals', value: 'read' },
    { type: 'pattern', field: 'target', pattern: '.*(ssn|credit|password).*' },
  ],
  action: 'block',
  response: 'Access to sensitive data is not allowed',
});

// Listen to events
shield.on('shield:blocked', (trace, rule) => {
  console.log(`Blocked: ${rule.name}`);
});

shield.on('anomaly:detected', (alert) => {
  console.log(`Alert: ${alert.description}`);
});

// Get traces
const traces = shield.getTraces('agent-1', { limit: 10 });
```

## Core Concepts

### Trace Types

| Type | Description |
|------|-------------|
| `action` | Agent actions (e.g., fetch data, process) |
| `decision` | Agent decisions with reasoning |
| `tool_call` | Tool invocations with arguments |
| `message` | Inter-agent messages |
| `resource` | Resource acquire/release operations |
| `security` | Security events (auth, permission) |
| `error` | Error conditions |

### Trace Levels

| Level | Description |
|-------|-------------|
| `debug` | Detailed debugging info |
| `info` | General information |
| `warn` | Warning conditions |
| `error` | Error conditions |
| `critical` | Critical issues |

### Shield Actions

| Action | Behavior |
|--------|----------|
| `allow` | Permit the operation |
| `block` | Block and return error |
| `warn` | Allow but emit warning event |
| `audit` | Allow but log to audit trail |
| `mask` | Allow but redact sensitive data |

## Shield Rule Examples

### Block PII Access

```typescript
shield.addRule({
  id: 'block-pii',
  name: 'Block PII',
  enabled: true,
  priority: 100,
  conditions: [
    { type: 'pattern', field: 'target', pattern: '.*(ssn|credit-card|password).*' },
  ],
  action: 'block',
  response: 'PII access denied',
});
```

### Rate Limiting

```typescript
shield.addRule({
  id: 'rate-limit',
  name: 'Rate limit API calls',
  enabled: true,
  priority: 50,
  conditions: [
    { type: 'action', action: 'api-call' },
    { type: 'rate', window: 60_000, maxCount: 100 },
  ],
  action: 'block',
  response: 'Rate limit exceeded',
});
```

### Time-Based Access

```typescript
shield.addRule({
  id: 'off-hours',
  name: 'Block off-hours admin',
  enabled: true,
  priority: 80,
  conditions: [
    { type: 'action', action: 'admin' },
    { type: 'time', start: '09:00', end: '18:00', days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'] },
  ],
  action: 'block',
  response: 'Admin operations only during business hours',
});
```

## API Overview

### Recording Traces

```typescript
shield.record(agentId, type, data, options?): Trace
shield.startSpan(agentId, name, parentId?): Trace
shield.endSpan(trace, result, duration?): void
```

### Querying Traces

```typescript
shield.getTraces(agentId, options?): Trace[]
shield.getAuditRecords(options?): AuditRecord[]
```

### Shield Rules

```typescript
shield.addRule(rule: ShieldRule): void
shield.removeRule(ruleId: string): boolean
shield.getRules(): ShieldRule[]
```

### Events

```typescript
shield.on('trace:recorded', (trace) => {})
shield.on('shield:blocked', (trace, rule) => {})
shield.on('shield:warned', (trace, rule) => {})
shield.on('anomaly:detected', (alert) => {})
shield.on('audit:created', (record) => {})
```

### Metrics

```typescript
shield.getMetrics(): {
  traces: { total, byType, byLevel },
  audit: { total },
  shields: { active },
}
```

## Architecture

```
traceshield/
├── src/
│   ├── index.ts         # Main exports
│   ├── types.ts         # Type definitions
│   └── tracer.ts        # Core TraceShield class
├── tests/
└── examples/
```

## Comparison

| Feature | TraceShield | Traditional Logging |
|---------|-------------|---------------------|
| Structured traces | ✅ | ❌ |
| Shield rules | ✅ | ❌ |
| Anomaly detection | ✅ | ❌ |
| Compliance audit | ✅ | Partial |
| Pattern matching | ✅ | Partial |

## License

Apache License 2.0
