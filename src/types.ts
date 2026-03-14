// ============================================================
// TraceShield - Core Type Definitions
// Agent Reliability & Behavior Auditing Framework
// ============================================================

// ---- Action Types ----

export type ActionType =
  | 'tool_call'
  | 'llm_call'
  | 'decision'
  | 'data_access'
  | 'human_escalation'
  | '*';

// ---- Policy Types ----

export interface PolicySet {
  version: string;
  policies: Policy[];
}

export interface Policy {
  name: string;
  description?: string;
  enabled?: boolean;
  priority?: number;
  rules: PolicyRule[];
}

export interface PolicyRule {
  id: string;
  action: ActionType;
  condition: RuleCondition;
  effect: PolicyEffect;
  message?: string;
}

export type PolicyEffect = 'deny' | 'warn' | 'audit';

export interface RuleCondition {
  tool_name?: PatternMatch;
  model?: PatternMatch;
  input_contains?: string[];
  input_not_contains?: string[];
  output_contains?: string[];
  output_not_contains?: string[];
  token_count?: NumericConstraint;
  latency_ms?: NumericConstraint;
  call_count?: NumericConstraint;
  custom?: string; // serializable expression for custom conditions
}

export interface PatternMatch {
  exact?: string;
  pattern?: string; // regex pattern
  oneOf?: string[];
  noneOf?: string[];
}

export interface NumericConstraint {
  min?: number;
  max?: number;
}

// ---- Policy Evaluation Result ----

export interface PolicyEvaluation {
  policy_name: string;
  rule_id: string;
  effect: PolicyEffect;
  result: 'allow' | 'deny' | 'warn';
  message?: string;
  evaluated_at: string;
}

export interface EvalContext {
  action_type: ActionType;
  action_name: string;
  input: unknown;
  output?: unknown;
  metadata?: Record<string, unknown>;
  trace_id: string;
  span_count: number;
  elapsed_ms: number;
  token_count?: number;
}

export interface PolicyDecision {
  allowed: boolean;
  evaluations: PolicyEvaluation[];
  blocked_by?: PolicyEvaluation;
}

// ---- Trace Types ----

export type TraceStatus = 'running' | 'completed' | 'failed' | 'aborted';
export type SpanStatus = 'running' | 'completed' | 'failed';

export interface Trace {
  id: string;
  session_id?: string;
  agent_id: string;
  started_at: string;
  ended_at?: string;
  status: TraceStatus;
  spans: Span[];
  metadata?: Record<string, unknown>;
  integrity_hash: string;
}

export interface Span {
  id: string;
  trace_id: string;
  parent_span_id?: string;
  sequence: number;
  action_type: ActionType;
  name: string;
  input: unknown;
  output?: unknown;
  started_at: string;
  ended_at?: string;
  duration_ms?: number;
  status: SpanStatus;
  policy_evaluations: PolicyEvaluation[];
  error?: SpanError;
  metadata?: Record<string, unknown>;
  hash: string;
  previous_hash: string;
}

export interface SpanError {
  type: string;
  message: string;
  stack?: string;
}

// ---- Attribution / Root Cause Analysis ----

export type FailureType =
  | 'policy_violation'
  | 'tool_error'
  | 'model_error'
  | 'timeout'
  | 'data_quality'
  | 'cascading_failure'
  | 'unknown';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface AttributionReport {
  id: string;
  trace_id: string;
  failure_span_id: string;
  root_causes: RootCause[];
  causal_chain: CausalLink[];
  timeline: TimelineEvent[];
  summary: string;
  severity: Severity;
  recommendations: string[];
  generated_at: string;
}

export interface RootCause {
  type: FailureType;
  span_id: string;
  description: string;
  confidence: number; // 0.0 - 1.0
  evidence: string[];
}

export interface CausalLink {
  from_span_id: string;
  to_span_id: string;
  relationship: 'caused_by' | 'triggered' | 'dependent_on' | 'correlated';
  description?: string;
}

export interface TimelineEvent {
  timestamp: string;
  span_id: string;
  event_type: 'action_start' | 'action_end' | 'policy_check' | 'violation' | 'error';
  description: string;
}

// ---- Storage Interface ----

export interface TraceQuery {
  agent_id?: string;
  session_id?: string;
  status?: TraceStatus;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export interface ViolationQuery {
  agent_id?: string;
  policy_name?: string;
  effect?: PolicyEffect;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export interface StoredViolation {
  id: string;
  trace_id: string;
  span_id: string;
  agent_id: string;
  policy_name: string;
  rule_id: string;
  effect: PolicyEffect;
  message?: string;
  context: EvalContext;
  occurred_at: string;
}

export interface StorageBackend {
  initialize(): Promise<void>;
  close(): Promise<void>;

  // Trace operations
  saveTrace(trace: Trace): Promise<void>;
  getTrace(traceId: string): Promise<Trace | null>;
  queryTraces(query: TraceQuery): Promise<Trace[]>;
  updateTrace(traceId: string, updates: Partial<Trace>): Promise<void>;

  // Span operations
  saveSpan(span: Span): Promise<void>;
  getSpansByTrace(traceId: string): Promise<Span[]>;

  // Violation operations
  saveViolation(violation: StoredViolation): Promise<void>;
  queryViolations(query: ViolationQuery): Promise<StoredViolation[]>;

  // Attribution operations
  saveReport(report: AttributionReport): Promise<void>;
  getReport(reportId: string): Promise<AttributionReport | null>;
  getReportsByTrace(traceId: string): Promise<AttributionReport[]>;
}

// ---- Configuration ----

export interface TraceShieldConfig {
  policies?: string | PolicySet; // file path or inline policy set
  storage?: StorageConfig;
  hooks?: TraceShieldHooks;
  hashAlgorithm?: string;
}

export type StorageConfig =
  | { type: 'memory' }
  | { type: 'sqlite'; path: string }
  | { type: 'postgresql'; connectionString: string }
  | { type: 'custom'; backend: StorageBackend };

export interface TraceShieldHooks {
  onViolation?: (violation: StoredViolation) => void | Promise<void>;
  onTraceComplete?: (trace: Trace) => void | Promise<void>;
  onSpanStart?: (span: Span) => void | Promise<void>;
  onSpanEnd?: (span: Span) => void | Promise<void>;
}

export interface GuardConfig {
  agentId: string;
  sessionId?: string;
  metadata?: Record<string, unknown>;
}

// ---- Guard Action Input ----

export interface ActionInput {
  name: string;
  input: unknown;
  metadata?: Record<string, unknown>;
  parentSpanId?: string;
}
