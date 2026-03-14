import { randomUUID } from 'node:crypto';
import { PolicyEngine, PolicyViolationError } from './policy-engine.js';
import { TraceRecorder } from './trace-recorder.js';
import type {
  ActionType,
  ActionInput,
  EvalContext,
  GuardConfig,
  Span,
  SpanError,
  StorageBackend,
  StoredViolation,
  Trace,
  TraceShieldHooks,
} from './types.js';

export class RuntimeGuard {
  private traceId: string | null = null;
  private trace: Trace | null = null;

  constructor(
    private readonly config: GuardConfig,
    private readonly policyEngine: PolicyEngine,
    private readonly recorder: TraceRecorder,
    private readonly storage?: StorageBackend,
    private readonly hooks?: TraceShieldHooks,
  ) {}

  /**
   * Execute an action with full policy checking and trace recording.
   *
   * Flow:
   * 1. Pre-check: evaluate policies BEFORE execution
   * 2. If denied, block and record violation
   * 3. If allowed, execute the action
   * 4. Post-check: evaluate policies AFTER execution (output checks)
   * 5. Record the span with all evaluations
   */
  async execute<T>(
    actionType: ActionType,
    action: ActionInput,
    handler: (input: unknown) => T | Promise<T>,
  ): Promise<T> {
    // Ensure trace is started
    if (!this.traceId || !this.trace) {
      this.trace = await this.recorder.startTrace(this.config.agentId, {
        sessionId: this.config.sessionId,
        metadata: this.config.metadata,
      });
      this.traceId = this.trace.id;
    }

    const spanCount = this.trace.spans.length;
    const startTime = Date.now();

    // Build eval context for pre-check
    const preContext: EvalContext = {
      action_type: actionType,
      action_name: action.name,
      input: action.input,
      metadata: action.metadata,
      trace_id: this.traceId,
      span_count: spanCount,
      elapsed_ms: 0,
    };

    // Step 1: Pre-check policies
    const preDecision = this.policyEngine.evaluatePre(preContext);

    // Start the span
    const span = this.recorder.startSpan(this.traceId, actionType, action.name, action.input, {
      parentSpanId: action.parentSpanId,
      metadata: action.metadata,
    });

    if (this.hooks?.onSpanStart) {
      await this.hooks.onSpanStart(span);
    }

    // Step 2: If denied, block
    if (!preDecision.allowed && preDecision.blocked_by) {
      const violation = preDecision.blocked_by;

      await this.recorder.endSpan(this.traceId, span.id, {
        status: 'failed',
        policyEvaluations: preDecision.evaluations,
        error: {
          type: 'PolicyViolation',
          message: violation.message ?? `Blocked by ${violation.rule_id}`,
        },
      });

      await this.recordViolation(span, violation, preContext);

      if (this.hooks?.onSpanEnd) {
        await this.hooks.onSpanEnd(span);
      }

      throw new PolicyViolationError(violation, preContext);
    }

    // Step 3: Execute the action
    let output: T;
    let error: SpanError | undefined;
    let status: 'completed' | 'failed' = 'completed';

    try {
      output = await handler(action.input);
    } catch (err) {
      status = 'failed';
      error = {
        type: err instanceof Error ? err.constructor.name : 'Error',
        message: err instanceof Error ? err.message : String(err),
        stack: err instanceof Error ? err.stack : undefined,
      };

      await this.recorder.endSpan(this.traceId, span.id, {
        status: 'failed',
        error,
        policyEvaluations: preDecision.evaluations,
      });

      if (this.hooks?.onSpanEnd) {
        await this.hooks.onSpanEnd(span);
      }

      throw err;
    }

    const elapsed = Date.now() - startTime;

    // Step 4: Post-check policies
    const postContext: EvalContext = {
      ...preContext,
      output,
      elapsed_ms: elapsed,
      span_count: spanCount + 1,
    };

    const postDecision = this.policyEngine.evaluatePost(postContext);
    const allEvaluations = [...preDecision.evaluations, ...postDecision.evaluations];

    // If post-check denies, mark as failed but return the output with a warning
    // (action already executed — we can't undo it, but we record the violation)
    if (!postDecision.allowed && postDecision.blocked_by) {
      await this.recordViolation(span, postDecision.blocked_by, postContext);
      status = 'failed';
    }

    // Record violations for warnings too
    for (const evaluation of allEvaluations) {
      if (evaluation.result === 'warn') {
        await this.recordViolation(span, evaluation, postContext);
      }
    }

    // Step 5: End span with results
    await this.recorder.endSpan(this.traceId, span.id, {
      output,
      status,
      error,
      policyEvaluations: allEvaluations,
    });

    if (this.hooks?.onSpanEnd) {
      await this.hooks.onSpanEnd(span);
    }

    return output;
  }

  /**
   * Complete the current trace with the given status.
   */
  async complete(status: 'completed' | 'failed' | 'aborted' = 'completed'): Promise<Trace | null> {
    if (!this.traceId) return null;

    const trace = await this.recorder.endTrace(this.traceId, status);

    if (this.hooks?.onTraceComplete) {
      await this.hooks.onTraceComplete(trace);
    }

    this.traceId = null;
    this.trace = null;
    return trace;
  }

  getTraceId(): string | null {
    return this.traceId;
  }

  getCurrentTrace(): Trace | null {
    if (!this.traceId) return null;
    return this.recorder.getTrace(this.traceId) ?? null;
  }

  private async recordViolation(
    span: Span,
    evaluation: { policy_name: string; rule_id: string; effect: string; message?: string },
    context: EvalContext,
  ): Promise<void> {
    if (!this.storage) return;

    const violation: StoredViolation = {
      id: randomUUID(),
      trace_id: context.trace_id,
      span_id: span.id,
      agent_id: this.config.agentId,
      policy_name: evaluation.policy_name,
      rule_id: evaluation.rule_id,
      effect: evaluation.effect as 'deny' | 'warn' | 'audit',
      message: evaluation.message,
      context,
      occurred_at: new Date().toISOString(),
    };

    await this.storage.saveViolation(violation);

    if (this.hooks?.onViolation) {
      await this.hooks.onViolation(violation);
    }
  }
}
