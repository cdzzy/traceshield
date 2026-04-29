import { describe, it, expect, beforeEach } from 'vitest';
import { TraceRecorder } from '../src/trace-recorder.js';
import { verifySpanChain, computeTraceIntegrityHash } from '../src/hash-chain.js';

describe('TraceRecorder', () => {
  let recorder: TraceRecorder;

  beforeEach(() => {
    recorder = new TraceRecorder();
  });

  describe('trace lifecycle', () => {
    it('should create a new trace', async () => {
      const trace = await recorder.startTrace('agent-1', {
        sessionId: 'session-1',
        metadata: { env: 'test' },
      });

      expect(trace.id).toBeDefined();
      expect(trace.agent_id).toBe('agent-1');
      expect(trace.session_id).toBe('session-1');
      expect(trace.status).toBe('running');
      expect(trace.spans).toHaveLength(0);
    });

    it('should end a trace', async () => {
      const trace = await recorder.startTrace('agent-1');
      const ended = await recorder.endTrace(trace.id, 'completed');

      expect(ended.status).toBe('completed');
      expect(ended.ended_at).toBeDefined();
      expect(ended.integrity_hash).toBeDefined();
      expect(ended.integrity_hash.length).toBeGreaterThan(0);
    });

    it('should throw when ending a non-existent trace', async () => {
      await expect(recorder.endTrace('nonexistent', 'completed')).rejects.toThrow();
    });
  });

  describe('span operations', () => {
    it('should create spans with sequential ordering', async () => {
      const trace = await recorder.startTrace('agent-1');

      const span1 = recorder.startSpan(trace.id, 'tool_call', 'search', { query: 'hello' });
      const span2 = recorder.startSpan(trace.id, 'llm_call', 'gpt-4', { prompt: 'hi' });

      expect(span1.sequence).toBe(0);
      expect(span2.sequence).toBe(1);
      expect(span1.trace_id).toBe(trace.id);
      expect(span2.trace_id).toBe(trace.id);
    });

    it('should compute span hashes', async () => {
      const trace = await recorder.startTrace('agent-1');
      const span = recorder.startSpan(trace.id, 'tool_call', 'test', {});

      expect(span.hash).toBeDefined();
      expect(span.hash.length).toBe(64); // SHA-256 hex length
    });

    it('should link spans with previous_hash', async () => {
      const trace = await recorder.startTrace('agent-1');
      const span1 = recorder.startSpan(trace.id, 'tool_call', 'tool1', {});
      const span2 = recorder.startSpan(trace.id, 'tool_call', 'tool2', {});

      expect(span2.previous_hash).toBe(span1.hash);
    });

    it('should end spans with output and status', async () => {
      const trace = await recorder.startTrace('agent-1');
      const span = recorder.startSpan(trace.id, 'tool_call', 'search', { q: 'test' });

      const ended = await recorder.endSpan(trace.id, span.id, {
        output: { results: ['a', 'b'] },
        status: 'completed',
      });

      expect(ended.output).toEqual({ results: ['a', 'b'] });
      expect(ended.status).toBe('completed');
      expect(ended.ended_at).toBeDefined();
      expect(ended.duration_ms).toBeGreaterThanOrEqual(0);
    });

    it('should end spans with errors', async () => {
      const trace = await recorder.startTrace('agent-1');
      const span = recorder.startSpan(trace.id, 'tool_call', 'failing', {});

      const ended = await recorder.endSpan(trace.id, span.id, {
        status: 'failed',
        error: { type: 'Error', message: 'Something went wrong' },
      });

      expect(ended.status).toBe('failed');
      expect(ended.error?.message).toBe('Something went wrong');
    });

    it('should support parent-child spans', async () => {
      const trace = await recorder.startTrace('agent-1');
      const parent = recorder.startSpan(trace.id, 'decision', 'plan', {});
      const child = recorder.startSpan(trace.id, 'tool_call', 'execute', {}, {
        parentSpanId: parent.id,
      });

      expect(child.parent_span_id).toBe(parent.id);
    });

    it('should throw when adding span to non-existent trace', () => {
      expect(() => recorder.startSpan('nonexistent', 'tool_call', 'x', {})).toThrow();
    });

    it('should throw when adding span to ended trace', async () => {
      const trace = await recorder.startTrace('agent-1');
      await recorder.endTrace(trace.id, 'completed');

      expect(() => recorder.startSpan(trace.id, 'tool_call', 'x', {})).toThrow();
    });
  });

  describe('trace retrieval', () => {
    it('should get trace by id', async () => {
      const trace = await recorder.startTrace('agent-1');
      const found = recorder.getTrace(trace.id);
      expect(found).toBeDefined();
      expect(found?.id).toBe(trace.id);
    });

    it('should return undefined for non-existent trace', () => {
      expect(recorder.getTrace('nonexistent')).toBeUndefined();
    });

    it('should list active traces', async () => {
      await recorder.startTrace('agent-1');
      await recorder.startTrace('agent-2');
      const t3 = await recorder.startTrace('agent-3');
      await recorder.endTrace(t3.id, 'completed');

      const active = recorder.getActiveTraces();
      expect(active).toHaveLength(2);
    });
  });
});

describe('Hash Chain', () => {
  let recorder: TraceRecorder;

  beforeEach(() => {
    recorder = new TraceRecorder();
  });

  it('should verify a valid span chain', async () => {
    const trace = await recorder.startTrace('agent-1');

    recorder.startSpan(trace.id, 'tool_call', 'tool1', { a: 1 });
    recorder.startSpan(trace.id, 'tool_call', 'tool2', { b: 2 });
    recorder.startSpan(trace.id, 'llm_call', 'gpt-4', { c: 3 });

    const currentTrace = recorder.getTrace(trace.id)!;
    const result = verifySpanChain(currentTrace.spans);

    expect(result.valid).toBe(true);
    expect(result.span_count).toBe(3);
    expect(result.errors).toHaveLength(0);
  });

  it('should detect tampered span data', async () => {
    const trace = await recorder.startTrace('agent-1');

    recorder.startSpan(trace.id, 'tool_call', 'tool1', { a: 1 });
    recorder.startSpan(trace.id, 'tool_call', 'tool2', { b: 2 });

    const currentTrace = recorder.getTrace(trace.id)!;

    // Tamper with a span's input
    currentTrace.spans[0].input = { a: 999 };

    const result = verifySpanChain(currentTrace.spans);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].type).toBe('hash_mismatch');
  });

  it('should compute trace integrity hash', async () => {
    const trace = await recorder.startTrace('agent-1');
    recorder.startSpan(trace.id, 'tool_call', 'tool1', {});
    recorder.startSpan(trace.id, 'tool_call', 'tool2', {});

    const ended = await recorder.endTrace(trace.id, 'completed');
    expect(ended.integrity_hash).toBeDefined();
    expect(ended.integrity_hash.length).toBe(64);

    // Recompute and verify
    const recomputed = computeTraceIntegrityHash(ended.spans);
    expect(recomputed).toBe(ended.integrity_hash);
  });
});

