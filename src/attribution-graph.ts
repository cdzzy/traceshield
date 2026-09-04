/**
 * Multi-agent attribution graph visualization (Roadmap).
 *
 * Aggregates traces into an attribution graph — which agent performed which
 * actions, and which policy rules fired — and renders it as a Mermaid
 * diagram (or Graphviz DOT) for dashboards and audit reports.
 */

import type { Trace } from './types.js';

export type GraphNodeKind = 'agent' | 'action' | 'policy';

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  count: number;
}

export interface GraphEdge {
  from: string;   // node id
  to: string;     // node id
  count: number;
}

export interface AttributionGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

function nodeId(kind: GraphNodeKind, label: string): string {
  return `${kind}:${label}`;
}

function sanitize(s: string): string {
  return s.replace(/[\[\]{}()"<>|]/g, ' ').replace(/\s+/g, ' ').trim();
}

/** Build an attribution graph from a set of traces. */
export function buildAttributionGraph(traces: Trace[]): AttributionGraph {
  const nodes = new Map<string, GraphNode>();
  const edgeCounts = new Map<string, number>();

  const addNode = (kind: GraphNodeKind, label: string): string => {
    const id = nodeId(kind, label);
    const existing = nodes.get(id);
    if (existing) existing.count += 1;
    else nodes.set(id, { id, kind, label, count: 1 });
    return id;
  };

  const addEdge = (from: string, to: string): void => {
    const key = `${from}->${to}`;
    edgeCounts.set(key, (edgeCounts.get(key) ?? 0) + 1);
  };

  for (const trace of traces) {
    const agentId = addNode('agent', trace.agent_id);

    for (const span of trace.spans) {
      const actionId = addNode('action', `${span.action_type}:${span.name}`);
      addEdge(agentId, actionId);

      for (const evaluation of span.policy_evaluations) {
        if (evaluation.result === 'allow') continue;
        const policyId = addNode('policy', evaluation.rule_id);
        addEdge(actionId, policyId);
      }
    }
  }

  const edges: GraphEdge[] = [...edgeCounts.entries()].map(([key, count]) => {
    const [from, to] = key.split('->');
    return { from: from!, to: to!, count };
  });

  return { nodes: [...nodes.values()], edges };
}

/** Render the attribution graph as a Mermaid flowchart. */
export function renderMermaid(graph: AttributionGraph): string {
  const lines = ['graph LR'];

  for (const node of graph.nodes) {
    const label = sanitize(node.label);
    if (node.kind === 'agent') {
      lines.push(`  ${mermaidId(node.id)}(["${label}"])`);
    } else if (node.kind === 'action') {
      lines.push(`  ${mermaidId(node.id)}["${label}"]`);
    } else {
      lines.push(`  ${mermaidId(node.id)}{{"${label}"}}`);
    }
  }

  for (const edge of graph.edges) {
    const label = edge.count > 1 ? `|${edge.count}x|` : '';
    lines.push(`  ${mermaidId(edge.from)} -->${label} ${mermaidId(edge.to)}`);
  }

  return lines.join('\n');
}

/** Render the attribution graph in Graphviz DOT format. */
export function renderDot(graph: AttributionGraph): string {
  const lines = ['digraph attribution {', '  rankdir=LR;'];

  for (const node of graph.nodes) {
    const label = sanitize(node.label);
    const shape = node.kind === 'agent' ? 'ellipse' : node.kind === 'policy' ? 'diamond' : 'box';
    lines.push(`  "${node.id}" [label="${label}", shape=${shape}];`);
  }

  for (const edge of graph.edges) {
    const label = edge.count > 1 ? ` [label="${edge.count}x"]` : '';
    lines.push(`  "${edge.from}" -> "${edge.to}"${label};`);
  }

  lines.push('}');
  return lines.join('\n');
}

/** Mermaid node ids must be alphanumeric-safe. */
function mermaidId(id: string): string {
  return id.replace(/[^A-Za-z0-9_]/g, '_');
}
