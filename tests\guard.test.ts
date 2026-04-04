import { describe, it, expect, beforeEach } from 'vitest';
import { TraceShield, PolicyViolationError } from '../src/index.js';
import type { PolicySet } from '../src/types.js';

const testPolicies: PolicySet = {
  version: '1.0',
  policies: [
    {
      name: 'tool-restrictions',
      rules: [
        {
          id: 'block-delete',
          action: 'tool_call',
          condition: { tool_name: { pattern: '^delete_' } },
          effect: 'deny',
          message: 'Delete operations are blocked',
        },
        {
          id: 'warn-http',
          action: 'tool_call',
          condition: { tool_name: { pattern: '^http_' } },
          effect: 'warn',
          message: 'HTTP calls flagged for review',
        },
      ],
    },
    {
      name: 'output-safety',
      rules: [
        {
          id: 'no-pii',
          action: '*',
          condition: { output_contains: ['SSN:', 'social security'] },
          effect: 'deny',
          message: 'Output contains PII',
        },
      ],
    },
  ],
};

describe('RuntimeGuard', () => {
  let shield: TraceShield;

  beforeEach(() => {
    shield = new TraceShield({
      policies: testPolicies,
      storage: { type: 'memory' },
    });
  });

  it('should allow compliant actions', async () => {
    const guard = shield.createGuard({ agentId: 'test-agent' });

    const result = await guard.execute(
      'tool_call',
      { name: 'search', input: { q: 'revenue' } },
      async () => ({ results: ['data'] }),
    );

    expect(result).toEqual({ results: ['data'] });
    await guard.complete();
  });

  it('should block actions that violate deny policies', async () => {
    const guard = shield.createGuard({ agentId: 'test-agent' });

    await expect(
      guard.execute(
        'tool_call',
        { name: 'delete_user', input: { id: '123' } },
        async () => ({ deleted: true }),
      ),
    ).rejects.toThrow(PolicyViolationError);

    await guard.complete('failed');
  });

  it('should provide violation details in PolicyViolationError', async () => {
    const guard = shield.createGuard({ agentId: 'test-agent' });

    try {
      await guard.execute(
        'tool_call',
        { name: 'delete_records', input: {} },
        async () => ({}),
      );
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PolicyViolationError);
      const violation = err as PolicyViolationError;
      expect(violation.evaluation.policy_name).toBe('tool-restrictions');
      expect(violation.evaluation.rule_id).toBe('block-delete');
      expect(violation.evaluation.result).toBe('deny');
    }

    await guard.complete('failed');
  });

  it('should allow warned actions but record evaluations', async () => {
    const guard = shield.createGuard({ agentId: 'test-agent' });

    const result = await guard.execute(
      'tool_call',
      { name: 'http_get', input: { url: 'https://api.example.com' } },
      async () => ({ status: 200 }),
    );

    expect(result).toEqual({ status: 200 });

    const trace = guard.getCurrentTrace()!;
    const span = trace.spans[0];
    expect(span.policy_evaluations.some((e) => e.result === 'warn')).toBe(true);

    await guard.complete();
  });

  it('should record tool execution errors in spans', async () => {
    const guard = shield.createGuard({ agentId: 'test-agent' });

    await expect(
      guard.execute(
        'tool_call',
        { name: 'flaky_api', input: {} },
        async () => {
          throw new Error('Connection timeout');
        },
      ),
    ).rejects.toThrow('Connection timeout');

    const trace = guard.getCurrentTrace()!;
    const span = trace.spans[0];
    expect(span.status).toBe('failed');
    expect(span.error?.message).toBe('Connection timeout');

    await guard.complete('failed');
  });

  it('should auto-create trace on first execute', async () => {
    const guard = shield.createGuard({ agentId: 'test-agent' });
    expect(guard.getTraceId()).toBeNull();

    await guard.execute(
      'tool_call',
      { name: 'search', input: {} },
      async () => 'ok',
    );

    expect(guard.getTraceId()).toBeDefined();
    await guard.complete();
  });

  it('should record multiple spans in sequence', async () => {
    const guard = shield.createGuard({ agentId: 'test-agent' });

    await guard.execute('tool_call', { name: 'step1', input: {} }, async () => 'a');
    await guard.execute('llm_call', { name: 'step2', input: {} }, async () => 'b');
    await guard.execute('decision', { name: 'step3', input: {} }, async () => 'c');

    const trace = guard.getCurrentTrace()!;
    expect(trace.spans).toHaveLength(3);
    expect(trace.spans[0].action_type).toBe('tool_call');
    expect(trace.spans[1].action_type).toBe('llm_call');
    expect(trace.spans[2].action_type).toBe('decision');

    await guard.complete();
  });

  it('should complete trace with correct status', async () => {
    const guard = shield.createGuard({ agentId: 'test-agent' });

    await guard.execute('tool_call', { name: 'ok', input: {} }, async () => 'done');
    const trace = await guard.complete('completed');

    expect(trace).toBeDefined();
    expect(trace!.status).toBe('completed');
    expect(trace!.ended_at).toBeDefined();
    expect(trace!.integrity_hash.length).toBe(64);
  });

  it('should support hooks', async () => {
    const violations: unknown[] = [];
    const spanStarts: unknown[] = [];

    const hookedShield = new TraceShield({
      policies: testPolicies,
      storage: { type: 'memory' },
      hooks: {
        onViolation: (v) => { violations.push(v); },
        onSpanStart: (s) => { spanStarts.push(s); },
      },
    });

    const guard = hookedShield.createGuard({ agentId: 'test-agent' });

    // Trigger a warning
    await guard.execute(
      'tool_call',
      { name: 'http_post', input: {} },
      async () => 'ok',
    );

    expect(violations.length).toBeGreaterThan(0);
    expect(spanStarts.length).toBeGreaterThan(0);

    await guard.complete();
  });
});

describe('TraceShield integration', () => {
  it('should analyze failed traces', async () => {
    const shield = new TraceShield({
      policies: testPolicies,
      storage: { type: 'memory' },
    });

    const guard = shield.createGuard({ agentId: 'test-agent' });

    await guard.execute('tool_call', { name: 'search', input: {} }, async () => 'ok');

    try {
      await guard.execute(
        'tool_call',
        { name: 'delete_user', input: {} },
        async () => 'bad',
      );
    } catch {
      // Expected
    }

    const trace = await guard.complete('failed');
    const report = shield.analyzeTrace(trace!);

    expect(report.severity).toBe('critical');
    expect(report.root_causes.length).toBeGreaterThan(0);
    expect(report.root_causes[0].type).toBe('policy_violation');
    expect(report.recommendations.length).toBeGreaterThan(0);
  });

  it('should verify trace integrity', async () => {
    const shield = new TraceShield({ storage: { type: 'memory' } });
    const guard = shield.createGuard({ agentId: 'test-agent' });

    await guard.execute('tool_call', { name: 'a', input: {} }, async () => 1);
    await guard.execute('tool_call', { name: 'b', input: {} }, async () => 2);
    await guard.execute('tool_call', { name: 'c', input: {} }, async () => 3);

    const trace = await guard.complete();
    const verification = shield.verifyTrace(trace!);

    expect(verification.valid).toBe(true);
    expect(verification.span_count).toBe(3);
  });
});
