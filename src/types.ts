// ============================================================
// TraceShield - Core Type Definitions
// Agent Behavior Tracing & Protection System
// ============================================================

export type TraceId = string;
export type AgentId = string;

// ---- Action / Policy ----

export type ActionType =
  | 'tool_call'
  | 'llm_call'
  | 'decision'
  | 'message'
  | 'resource'
  | 'retrieval'
  | 'output'
  | '*';

export interface ActionInput {
  name: string;
  input: unknown;
  metadata?: Record<string, unknown>;
  parentSpanId?: string;
}

// ---- Span & Trace ----

export type SpanStatus = 'running' | 'completed' | 'failed';
export type TraceStatus = 'running' | 'completed' | 'failed' | 'aborted';

export interface SpanError {
  type: string;
  message: string;
  stack?: string;
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
  metadata?: Record<string, unknown>;
  error?: SpanError;
  hash: string;
  previous_hash: string;
}

export interface Trace {
  id: string;
  session_id?: string;
  agent_id: AgentId;
  started_at: string;
  ended_at?: string;
  status: TraceStatus;
  spans: Span[];
  metadata?: Record<string, unknown>;
  integrity_hash: string;
}

// ---- Policy Model ----

export type PolicyEffect = 'deny' | 'warn' | 'audit';

export interface PatternMatch {
  exact?: string;
  pattern?: string;
  oneOf?: string[];
  noneOf?: string[];
}

export interface NumericConstraint {
  min?: number;
  max?: number;
}

export interface RuleCondition {
  tool_name?: PatternMatch;
  model?: PatternMatch;
  input_contains?: string[];
  input_not_contains?: string[];
  output_contains?: string[];
  output_not_contains?: string[];
  token_count?: NumericConstraint;
  call_count?: NumericConstraint;
  latency_ms?: NumericConstraint;
}

export interface PolicyRule {
  id: string;
  action: ActionType;
  condition: RuleCondition;
  effect: PolicyEffect;
  message?: string;
}

export interface Policy {
  name: string;
  rules: PolicyRule[];
  enabled?: boolean;
  priority?: number;
}

export interface PolicySet {
  version: string;
  policies: Policy[];
}

export type PolicyEvaluationResult = 'deny' | 'warn' | 'allow';

export interface PolicyEvaluation {
  policy_name: string;
  rule_id: string;
  effect: PolicyEffect;
  result: PolicyEvaluationResult;
  message?: string;
  evaluated_at: string;
}

export interface PolicyDecision {
  allowed: boolean;
  evaluations: PolicyEvaluation[];
  blocked_by?: PolicyEvaluation;
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

// ---- Guard ----

export interface GuardConfig {
  agentId: AgentId;
  sessionId?: string;
  metadata?: Record<string, unknown>;
}

export interface TraceShieldHooks {
  onViolation?: (violation: StoredViolation) => void | Promise<void>;
  onSpanStart?: (span: Span) => void | Promise<void>;
  onSpanEnd?: (span: Span) => void | Promise<void>;
  onTraceComplete?: (trace: Trace) => void | Promise<void>;
}

// ---- Storage ----

export interface StorageBackend {
  initialize(): Promise<void>;
  close(): Promise<void>;
  saveTrace(trace: Trace): Promise<void>;
  getTrace(traceId: string): Promise<Trace | null>;
  queryTraces(query: TraceQuery): Promise<Trace[]>;
  updateTrace(traceId: string, updates: Partial<Trace>): Promise<void>;
  saveSpan(span: Span): Promise<void>;
  getSpansByTrace(traceId: string): Promise<Span[]>;
  saveViolation(violation: StoredViolation): Promise<void>;
  queryViolations(query: ViolationQuery): Promise<StoredViolation[]>;
  saveReport(report: AttributionReport): Promise<void>;
  getReport(reportId: string): Promise<AttributionReport | null>;
  getReportsByTrace(traceId: string): Promise<AttributionReport[]>;
}

export interface TraceQuery {
  agent_id?: AgentId;
  session_id?: string;
  status?: TraceStatus;
  from?: string;
  to?: string;
  offset?: number;
  limit?: number;
}

export interface ViolationQuery {
  agent_id?: AgentId;
  policy_name?: string;
  effect?: PolicyEffect;
  from?: string;
  to?: string;
  offset?: number;
  limit?: number;
}

export interface StoredViolation {
  id: string;
  trace_id: string;
  span_id: string;
  agent_id: AgentId;
  policy_name: string;
  rule_id: string;
  effect: PolicyEffect;
  message?: string;
  context: EvalContext;
  occurred_at: string;
}

// ---- Attribution / Analysis ----

export type FailureType =
  | 'policy_violation'
  | 'tool_error'
  | 'model_error'
  | 'timeout'
  | 'cascading_failure'
  | 'data_quality'
  | 'unknown';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface RootCause {
  type: FailureType;
  span_id: string;
  description: string;
  confidence: number;
  evidence: string[];
}

export interface CausalLink {
  from_span_id: string;
  to_span_id: string;
  relationship: 'caused_by' | 'dependent_on' | 'triggered';
  description: string;
}

export interface TimelineEvent {
  timestamp: string;
  span_id: string;
  event_type: 'action_start' | 'action_end' | 'violation' | 'policy_check' | 'error';
  description: string;
}

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

// ---- TraceShield Configuration ----

export interface TraceShieldConfig {
  policies?: PolicySet;
  storage?: { type: 'memory' } | StorageBackend;
  hooks?: TraceShieldHooks;
}
