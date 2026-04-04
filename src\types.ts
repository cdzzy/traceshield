// ============================================================
// TraceShield - Core Type Definitions
// Agent Behavior Tracing & Protection System
// ============================================================

import { EventEmitter } from 'node:events';

// ---- Trace Types ----

export type TraceId = string;
export type AgentId = string;
export type TraceLevel = 'debug' | 'info' | 'warn' | 'error' | 'critical';
export type TraceType = 
  | 'action'
  | 'decision'
  | 'tool_call'
  | 'message'
  | 'resource'
  | 'security'
  | 'error';

export interface Trace {
  id: TraceId;
  agentId: AgentId;
  type: TraceType;
  level: TraceLevel;
  timestamp: number;
  parentId?: TraceId;        // For tracing hierarchies
  spanId?: string;           // For distributed tracing
  data: TraceData;
  tags?: Record<string, string>;
  redacted?: boolean;        // Sensitive data redacted
}

export type TraceData = 
  | ActionTrace
  | DecisionTrace
  | ToolCallTrace
  | MessageTrace
  | ResourceTrace
  | SecurityTrace
  | ErrorTrace;

export interface ActionTrace {
  action: string;
  target?: string;
  result?: unknown;
  duration?: number;
}

export interface DecisionTrace {
  decision: string;
  inputs: Record<string, unknown>;
  output: unknown;
  reasoning?: string;
  confidence?: number;
}

export interface ToolCallTrace {
  tool: string;
  arguments: Record<string, unknown>;
  result?: unknown;
  error?: string;
  duration?: number;
}

export interface MessageTrace {
  from: AgentId;
  to: AgentId | 'broadcast';
  content: string;
  topic?: string;
}

export interface ResourceTrace {
  resourceId: string;
  operation: 'acquire' | 'release' | 'timeout' | 'denied';
  duration?: number;
}

export interface SecurityTrace {
  event: 'auth' | 'permission' | 'rate_limit' | 'data_access' | 'anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: Record<string, unknown>;
}

export interface ErrorTrace {
  error: string;
  stack?: string;
  context?: Record<string, unknown>;
}

// ---- Shield Types ----

export type ShieldRuleId = string;
export type ShieldAction = 'allow' | 'block' | 'warn' | 'audit' | 'mask';

export interface ShieldRule {
  id: ShieldRuleId;
  name: string;
  description?: string;
  enabled: boolean;
  priority: number;
  conditions: ShieldCondition[];
  action: ShieldAction;
  response?: string;
}

export type ShieldCondition = 
  | DataCondition
  | ActionCondition
  | TimeCondition
  | RateCondition
  | PatternCondition;

export interface DataCondition {
  type: 'data';
  field: string;
  operator: 'contains' | 'equals' | 'matches' | 'in';
  value: string | string[];
}

export interface ActionCondition {
  type: 'action';
  agentId?: AgentId;
  action?: string;
  target?: string;
}

export interface TimeCondition {
  type: 'time';
  start?: string;  // HH:mm
  end?: string;
  days?: string[]; // ['Mon', 'Tue', ...]
}

export interface RateCondition {
  type: 'rate';
  window: number;  // ms
  maxCount: number;
}

export interface PatternCondition {
  type: 'pattern';
  field: string;
  pattern: string;  // regex
}

// ---- Audit Types ----

export interface AuditRecord {
  id: string;
  timestamp: number;
  agentId: AgentId;
  traceId: TraceId;
  ruleId?: ShieldRuleId;
  action: ShieldAction;
  result: 'success' | 'blocked' | 'warned';
  details: Record<string, unknown>;
}

// ---- Configuration ----

export interface TraceShieldConfig {
  tracing?: {
    enabled: boolean;
    level?: TraceLevel;
    maxTraces?: number;
    retentionMs?: number;
    sampleRate?: number;  // 0-1
  };
  shielding?: {
    enabled: boolean;
    failClosed?: boolean;
  };
  audit?: {
    enabled: boolean;
    storage?: AuditStorage;
  };
}

export type AuditStorage = 'memory' | 'file' | 'database';

// ---- Events ----

export interface TraceShieldEvents {
  'trace:recorded': (trace: Trace) => void;
  'trace:error': (error: Error, trace: Trace) => void;
  'shield:blocked': (trace: Trace, rule: ShieldRule) => void;
  'shield:warned': (trace: Trace, rule: ShieldRule) => void;
  'audit:created': (record: AuditRecord) => void;
  'anomaly:detected': (anomaly: AnomalyAlert) => void;
}

export interface AnomalyAlert {
  id: string;
  timestamp: number;
  type: 'rate_spike' | 'error_spike' | 'security' | 'performance';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  relatedTraces: TraceId[];
}

// ---- Event Emitter ----

export class TypedEventEmitter extends EventEmitter {
  override emit<K extends keyof TraceShieldEvents>(
    event: K, 
    ...args: Parameters<TraceShieldEvents[K]>
  ): boolean;
  override emit(event: string, ...args: unknown[]): boolean {
    return super.emit(event, ...args);
  }

  override on<K extends keyof TraceShieldEvents>(
    event: K, 
    listener: TraceShieldEvents[K]
  ): this;
  override on(event: string, listener: (...args: unknown[]) => void): this {
    return super.on(event, ...arguments);
  }

  override off<K extends keyof TraceShieldEvents>(
    event: K, 
    listener: TraceShieldEvents[K]
  ): this;
  override off(event: string, listener: (...args: unknown[]) => void): this {
    return super.off(event, ...arguments);
  }

  override once<K extends keyof TraceShieldEvents>(
    event: K, 
    listener: TraceShieldEvents[K]
  ): this;
  override once(event: string, listener: (...args: unknown[]) => void): this {
    return super.once(event, ...arguments);
  }
}
