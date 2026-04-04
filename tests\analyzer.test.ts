import { describe, it, expect } from 'vitest';
import { AttributionAnalyzer } from '../src/attribution-analyzer.js';
import type { Trace, Span } from '../src/types.js';

function makeSpan(overrides: Partial<Span> & { id: string; sequence: number }): Span {
  return {
    trace_id: 'trace-1',
    action_type: 'tool_call',
    name: 'test_action',
    input: {},
    started_at: new Date(Date.now() - 1000).toISOString(),
    ended_at: new Date().toISOString(),
    duration_ms: 100,
    status: 'completed',
    policy_evaluations: [],
    hash: 'abc',
    previous_hash: '000',
    ...overrides,
  };
}

function makeTrace(spans: Span[], status: 'failed' | 'aborted' = 'failed'): Trace {
  return {
    id: 'trace-1',
    agent_id: 'agent-1',
    started_at: new Date(Date.now() - 5000).toISOString(),
    ended_at: new Date().toISOString(),
    status,
    spans,
    integrity_hash: 'test-hash',
  };
}

describe('AttributionAnalyzer', () => {
  const analyzer = new AttributionAnalyzer();

  it('should throw for non-failed traces', () => {
    const trace: Trace = {
      id: 'trace-1',
      agent_id: 'agent-1',
      started_at: new Date().toISOString(),
      status: 'completed',
      spans: [],
      integrity_hash: '',
    };

    expect(() => analyzer.analyze(trace)).toThrow();
  });

  it('should identify policy violations as root cause', () => {
    const spans: Span[] = [
      makeSpan({ id: 's1', sequence: 0, status: 'completed', name: 'search' }),
      makeSpan({
        id: 's2', sequence: 1, status: 'failed', name: 'delete_user',
        policy_evaluations: [{
          policy_name: 'tool-restrictions',
          rule_id: 'block-delete',
          effect: 'deny',
          result: 'deny',
          message: 'Delete operations blocked',
          evaluated_at: new Date().toISOString(),
        }],
      }),
    ];

    const report = analyzer.analyze(makeTrace(spans));

    expect(report.severity).toBe('critical');
    expect(report.root_causes).toHaveLength(1);
    expect(report.root_causes[0].type).toBe('policy_violation');
    expect(report.root_causes[0].confidence).toBe(0.95);
    expect(report.recommendations.length).toBeGreaterThan(0);
  });

  it('should identify tool errors as root cause', () => {
    const spans: Span[] = [
      makeSpan({ id: 's1', sequence: 0, status: 'completed', name: 'search' }),
      makeSpan({
        id: 's2', sequence: 1, status: 'failed', name: 'api_call',
        action_type: 'tool_call',
        error: { type: 'ConnectionError', message: 'Connection refused' },
      }),
    ];

    const report = analyzer.analyze(makeTrace(spans));

    expect(report.root_causes[0].type).toBe('tool_error');
    expect(report.root_causes[0].description).toContain('Connection refused');
  });

  it('should identify LLM errors as root cause', () => {
    const spans: Span[] = [
      makeSpan({
        id: 's1', sequence: 0, status: 'failed', name: 'gpt-4',
        action_type: 'llm_call',
        error: { type: 'RateLimitError', message: 'Rate limit exceeded' },
      }),
    ];

    const report = analyzer.analyze(makeTrace(spans));

    expect(report.root_causes[0].type).toBe('model_error');
    expect(report.root_causes[0].description).toContain('Rate limit exceeded');
  });

  it('should detect timeout issues', () => {
    const spans: Span[] = [
      makeSpan({
        id: 's1', sequence: 0, status: 'failed', name: 'slow_api',
        duration_ms: 60000,
      }),
    ];

    const report = analyzer.analyze(makeTrace(spans));

    expect(report.root_causes[0].type).toBe('timeout');
    expect(report.root_causes[0].description).toContain('60000ms');
  });

  it('should build a timeline of events', () => {
    const spans: Span[] = [
      makeSpan({ id: 's1', sequence: 0, name: 'search', status: 'completed' }),
      makeSpan({
        id: 's2', sequence: 1, name: 'process', status: 'failed',
        error: { type: 'Error', message: 'Processing failed' },
      }),
    ];

    const report = analyzer.analyze(makeTrace(spans));

    expect(report.timeline.length).toBeGreaterThan(0);
    const eventTypes = report.timeline.map((e) => e.event_type);
    expect(eventTypes).toContain('action_start');
    expect(eventTypes).toContain('action_end');
    expect(eventTypes).toContain('error');
  });

  it('should build causal chains for parent-child failures', () => {
    const spans: Span[] = [
      makeSpan({
        id: 's1', sequence: 0, name: 'parent_task', status: 'failed',
        error: { type: 'Error', message: 'Parent failed' },
      }),
      makeSpan({
        id: 's2', sequence: 1, name: 'child_task', status: 'failed',
        parent_span_id: 's1',
        error: { type: 'Error', message: 'Child failed' },
      }),
    ];

    const report = analyzer.analyze(makeTrace(spans));

    expect(report.causal_chain.length).toBeGreaterThan(0);
    const link = report.causal_chain.find((l) => l.from_span_id === 's2' && l.to_span_id === 's1');
    expect(link).toBeDefined();
    expect(link?.relationship).toBe('caused_by');
  });

  it('should assess severity based on failure patterns', () => {
    // Single non-policy failure with low ratio => low
    const singleFail: Span[] = [
      makeSpan({ id: 's1', sequence: 0, status: 'completed' }),
      makeSpan({ id: 's2', sequence: 1, status: 'completed' }),
      makeSpan({ id: 's3', sequence: 2, status: 'completed' }),
      makeSpan({ id: 's4', sequence: 3, status: 'completed' }),
      makeSpan({ id: 's5', sequence: 4, status: 'completed' }),
      makeSpan({
        id: 's6', sequence: 5, status: 'failed',
        error: { type: 'Error', message: 'minor error' },
      }),
    ];
    const lowReport = analyzer.analyze(makeTrace(singleFail));
    expect(lowReport.severity).toBe('low');

    // Majority failures => high
    const majorityFail: Span[] = [
      makeSpan({
        id: 's1', sequence: 0, status: 'failed',
        error: { type: 'Error', message: 'fail 1' },
      }),
      makeSpan({
        id: 's2', sequence: 1, status: 'failed',
        error: { type: 'Error', message: 'fail 2' },
      }),
      makeSpan({ id: 's3', sequence: 2, status: 'completed' }),
    ];
    const highReport = analyzer.analyze(makeTrace(majorityFail));
    expect(highReport.severity).toBe('high');
  });

  it('should generate actionable recommendations', () => {
    const spans: Span[] = [
      makeSpan({
        id: 's1', sequence: 0, status: 'failed', name: 'api_call',
        action_type: 'tool_call',
        error: { type: 'NetworkError', message: 'Timeout' },
      }),
    ];

    const report = analyzer.analyze(makeTrace(spans));
    expect(report.recommendations.length).toBeGreaterThan(0);
    expect(report.recommendations[0]).toContain('error handling');
  });

  it('should flag warnings in recommendations', () => {
    const spans: Span[] = [
      makeSpan({
        id: 's1', sequence: 0, status: 'completed', name: 'http_call',
        policy_evaluations: [{
          policy_name: 'p1', rule_id: 'r1', effect: 'warn', result: 'warn',
          message: 'External call', evaluated_at: new Date().toISOString(),
        }],
      }),
      makeSpan({
        id: 's2', sequence: 1, status: 'failed', name: 'process',
        error: { type: 'Error', message: 'fail' },
      }),
    ];

    const report = analyzer.analyze(makeTrace(spans));
    const warningRec = report.recommendations.find((r) => r.includes('warning'));
    expect(warningRec).toBeDefined();
  });
});
