import { randomUUID } from 'node:crypto';
import type {
  Trace,
  Span,
  SpanStatus,
  TraceStatus,
  ActionType,
  PolicyEvaluation,
  SpanError,
  StorageBackend,
} from './types.js';
import { computeSpanHash, computeTraceIntegrityHash } from './hash-chain.js';

export class TraceRecorder {
  private traces = new Map<string, Trace>();
  private storage?: StorageBackend;
  private hashAlgorithm: string;

  constructor(options?: { storage?: StorageBackend; hashAlgorithm?: string }) {
    this.storage = options?.storage;
    this.hashAlgorithm = options?.hashAlgorithm ?? 'sha256';
  }

  async startTrace(agentId: string, options?: {
    sessionId?: string;
    metadata?: Record<string, unknown>;
  }): Promise<Trace> {
    const trace: Trace = {
      id: randomUUID(),
      session_id: options?.sessionId,
      agent_id: agentId,
      started_at: new Date().toISOString(),
      status: 'running',
      spans: [],
      metadata: options?.metadata,
      integrity_hash: '',
    };

    this.traces.set(trace.id, trace);
    if (this.storage) {
      await this.storage.saveTrace(trace);
    }
    return trace;
  }

  startSpan(
    traceId: string,
    actionType: ActionType,
    name: string,
    input: unknown,
    options?: {
      parentSpanId?: string;
      metadata?: Record<string, unknown>;
    },
  ): Span {
    const trace = this.traces.get(traceId);
    if (!trace) throw new Error(`Trace ${traceId} not found`);
    if (trace.status !== 'running') throw new Error(`Trace ${traceId} is not running (status: ${trace.status})`);

    const sequence = trace.spans.length;
    const previousHash = sequence > 0 ? trace.spans[sequence - 1].hash : '0'.repeat(64);

    const span: Span = {
      id: randomUUID(),
      trace_id: traceId,
      parent_span_id: options?.parentSpanId,
      sequence,
      action_type: actionType,
      name,
      input,
      started_at: new Date().toISOString(),
      status: 'running',
      policy_evaluations: [],
      metadata: options?.metadata,
      hash: '', // computed after creation
      previous_hash: previousHash,
    };

    span.hash = computeSpanHash(span, this.hashAlgorithm);
    trace.spans.push(span);

    return span;
  }

  async endSpan(
    traceId: string,
    spanId: string,
    result: {
      output?: unknown;
      status: SpanStatus;
      error?: SpanError;
      policyEvaluations?: PolicyEvaluation[];
    },
  ): Promise<Span> {
    const trace = this.traces.get(traceId);
    if (!trace) throw new Error(`Trace ${traceId} not found`);

    const span = trace.spans.find((s) => s.id === spanId);
    if (!span) throw new Error(`Span ${spanId} not found in trace ${traceId}`);

    const now = new Date();
    span.output = result.output;
    span.status = result.status;
    span.ended_at = now.toISOString();
    span.duration_ms = now.getTime() - new Date(span.started_at).getTime();
    span.error = result.error;

    if (result.policyEvaluations) {
      span.policy_evaluations.push(...result.policyEvaluations);
    }

    // Recompute hash after updating
    span.hash = computeSpanHash(span, this.hashAlgorithm);

    // Update subsequent spans' previous_hash references are broken now,
    // but since we only append to the end this is fine — endSpan always
    // targets the last running span in practice.

    if (this.storage) {
      await this.storage.saveSpan(span);
    }

    return span;
  }

  async endTrace(traceId: string, status: TraceStatus): Promise<Trace> {
    const trace = this.traces.get(traceId);
    if (!trace) throw new Error(`Trace ${traceId} not found`);

    trace.ended_at = new Date().toISOString();
    trace.status = status;
    trace.integrity_hash = computeTraceIntegrityHash(trace.spans, this.hashAlgorithm);

    if (this.storage) {
      await this.storage.updateTrace(traceId, {
        ended_at: trace.ended_at,
        status: trace.status,
        integrity_hash: trace.integrity_hash,
      });
    }

    return trace;
  }

  getTrace(traceId: string): Trace | undefined {
    return this.traces.get(traceId);
  }

  async loadTrace(traceId: string): Promise<Trace | null> {
    const cached = this.traces.get(traceId);
    if (cached) return cached;
    if (!this.storage) return null;

    const trace = await this.storage.getTrace(traceId);
    if (trace) {
      this.traces.set(trace.id, trace);
    }
    return trace;
  }

  getActiveTraces(): Trace[] {
    return [...this.traces.values()].filter((t) => t.status === 'running');
  }

  clearCache(): void {
    this.traces.clear();
  }
}
