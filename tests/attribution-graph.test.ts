/**
 * Tests for the attribution graph visualization (v0.4.0).
 */

import { describe, it, expect } from 'vitest';
import { buildAttributionGraph, renderMermaid, renderDot } from '../src/attribution-graph.js';
import type { Trace, Span } from '../src/types.js';

function makeSpan(overrides: Partial<Span> = {}): Span {
  return {
    id: 's1',
    trace_id: 't1',
    sequence: 0,
    action_type: 'tool_call',
    name: 'search',
    input: {},
    started_at: new Date().toISOString(),
    status: 'completed',
    policy_evaluations: [],
    hash: 'abc',
    previous_hash: '000',
    ...overrides,
  };
}

function makeTrace(agentId: string, spans: Span[]): Trace {
  return {
    id: `t-${agentId}-${spans.length}`,
    agent_id: agentId,
    started_at: new Date().toISOString(),
    status: 'completed',
    spans,
    integrity_hash: '',
  };
}

function sampleTraces(): Trace[] {
  return [
    makeTrace('agent-1', [
      makeSpan({ name: 'search' }),
      makeSpan({
        id: 's2', sequence: 1, name: 'export', action_type: 'tool_call',
        policy_evaluations: [{
          policy_name: 'no-export', rule_id: 'block-export', effect: 'deny', result: 'deny',
          message: 'blocked', evaluated_at: new Date().toISOString(),
        }],
      }),
    ]),
    makeTrace('agent-2', [
      makeSpan({ id: 's3', name: 'search' }),
    ]),
    makeTrace('agent-1', [
      makeSpan({ id: 's4', name: 'search' }),
    ]),
  ];
}

describe('buildAttributionGraph', () => {
  it('creates agent, action, and policy nodes', () => {
    const graph = buildAttributionGraph(sampleTraces());
    const kinds = graph.nodes.map((n) => n.kind);
    expect(kinds).toContain('agent');
    expect(kinds).toContain('action');
    expect(kinds).toContain('policy');
  });

  it('counts repeated agent-action pairs', () => {
    const graph = buildAttributionGraph(sampleTraces());
    // agent-1 -> tool_call:search appears in 2 traces
    const edge = graph.edges.find(
      (e) => e.from === 'agent:agent-1' && e.to === 'action:tool_call:search',
    );
    expect(edge).toBeDefined();
    expect(edge!.count).toBe(2);
  });

  it('links violating actions to policies', () => {
    const graph = buildAttributionGraph(sampleTraces());
    const edge = graph.edges.find(
      (e) => e.from === 'action:tool_call:export' && e.to === 'policy:block-export',
    );
    expect(edge).toBeDefined();
  });
});

describe('renderMermaid', () => {
  it('renders nodes and edges', () => {
    const mermaid = renderMermaid(buildAttributionGraph(sampleTraces()));
    expect(mermaid).toContain('graph LR');
    expect(mermaid).toContain('-->');
    expect(mermaid).toContain('agent_1');
    expect(mermaid).toContain('block-export');
  });

  it('sanitizes special characters in labels', () => {
    const graph = buildAttributionGraph([
      makeTrace('agent<x>', [makeSpan({ name: 'a"b' })]),
    ]);
    const mermaid = renderMermaid(graph);
    expect(mermaid).not.toContain('<x>');
  });

  it('labels multi-count edges', () => {
    const mermaid = renderMermaid(buildAttributionGraph(sampleTraces()));
    expect(mermaid).toContain('|2x|');
  });
});

describe('renderDot', () => {
  it('renders DOT with shapes', () => {
    const dot = renderDot(buildAttributionGraph(sampleTraces()));
    expect(dot).toContain('digraph attribution');
    expect(dot).toContain('shape=ellipse');
    expect(dot).toContain('shape=diamond');
  });
});
