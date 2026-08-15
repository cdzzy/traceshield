/**
 * Tamper-evident audit log export (Issue #2).
 *
 * Export recorded traces/violations in compliance-friendly formats (JSON-LD,
 * CEF for SIEM, and plain JSON) with optional integrity verification.
 */

import type { Trace } from './types.js';
import { verifySpanChain } from './hash-chain.js';

export interface ExportOptions {
  format: 'json' | 'json-ld' | 'cef';
  includeIntegrityProof?: boolean;
}

export interface ExportVerification {
  integrityValid: boolean;
  spanCount: number;
  errors: string[];
}

export class TraceShieldExporter {
  private readonly traces: Trace[];

  constructor(traces: Trace[]) {
    this.traces = traces;
  }

  /**
   * Export the traces in the requested format.
   */
  export(options: ExportOptions): string {
    switch (options.format) {
      case 'json-ld':
        return JSON.stringify(this.toJsonLd(), null, 2);
      case 'cef':
        return this.toCef();
      case 'json':
      default:
        return JSON.stringify(this.toJson(options.includeIntegrityProof), null, 2);
    }
  }

  /**
   * Verify the integrity of all spans (hash-chain check).
   */
  verify(): ExportVerification {
    let spanCount = 0;
    const errors: string[] = [];
    for (const trace of this.traces) {
      const result = verifySpanChain(trace.spans);
      spanCount += result.span_count;
      for (const e of result.errors) {
        errors.push(`${trace.id}/${e.span_id}: ${e.message}`);
      }
    }
    return { integrityValid: errors.length === 0, spanCount, errors };
  }

  private toJson(includeIntegrityProof?: boolean): Record<string, unknown> {
    return {
      exported_at: new Date().toISOString(),
      trace_count: this.traces.length,
      integrity_proof: includeIntegrityProof ? this.verify() : undefined,
      traces: this.traces.map((t) => ({
        id: t.id,
        agent_id: t.agent_id,
        started_at: t.started_at,
        status: t.status,
        integrity_hash: t.integrity_hash,
        span_count: t.spans.length,
      })),
    };
  }

  private toJsonLd(): Record<string, unknown> {
    return {
      '@context': 'https://www.w3.org/ns/prov#',
      '@type': 'Bundle',
      generatedAtTime: new Date().toISOString(),
      has_provenance: this.traces.map((t) => ({
        '@type': 'Activity',
        '@id': `trace:${t.id}`,
        startedAtTime: t.started_at,
        endedAtTime: t.ended_at,
        agent: { '@id': `agent:${t.agent_id}` },
        status: t.status,
        integrity_hash: t.integrity_hash,
      })),
    };
  }

  private toCef(): string {
    // Common Event Format (CEF) — consumable by Splunk / ArcSight / QRadar.
    const lines: string[] = [];
    for (const trace of this.traces) {
      for (const span of trace.spans) {
        lines.push(
          `CEF:0|traceshield|agent-guard|1.0|100|${span.action_type}|5|` +
            `msg=${escape(span.name)} agent=${trace.agent_id} status=${span.status} ` +
            `traceId=${trace.id} spanId=${span.id}`,
        );
      }
    }
    return lines.join('\n');
  }
}

function escape(s: string): string {
  return s.replace(/([\\|=])/g, '\\$1').replace(/\s+/g, ' ');
}
