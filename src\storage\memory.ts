import type {
  Trace,
  Span,
  StorageBackend,
  TraceQuery,
  ViolationQuery,
  StoredViolation,
  AttributionReport,
} from '../types.js';

/**
 * In-memory storage backend. Zero dependencies.
 * Suitable for development, testing, and short-lived agent sessions.
 */
export class MemoryStorage implements StorageBackend {
  private traces = new Map<string, Trace>();
  private spans = new Map<string, Span[]>(); // traceId -> spans
  private violations: StoredViolation[] = [];
  private reports = new Map<string, AttributionReport>();

  async initialize(): Promise<void> {
    // No-op for in-memory storage
  }

  async close(): Promise<void> {
    this.traces.clear();
    this.spans.clear();
    this.violations = [];
    this.reports.clear();
  }

  // ---- Trace operations ----

  async saveTrace(trace: Trace): Promise<void> {
    this.traces.set(trace.id, structuredClone(trace));
  }

  async getTrace(traceId: string): Promise<Trace | null> {
    const trace = this.traces.get(traceId);
    if (!trace) return null;

    // Attach spans
    const spans = this.spans.get(traceId) ?? [];
    return { ...structuredClone(trace), spans: structuredClone(spans) };
  }

  async queryTraces(query: TraceQuery): Promise<Trace[]> {
    let results = [...this.traces.values()];

    if (query.agent_id) {
      results = results.filter((t) => t.agent_id === query.agent_id);
    }
    if (query.session_id) {
      results = results.filter((t) => t.session_id === query.session_id);
    }
    if (query.status) {
      results = results.filter((t) => t.status === query.status);
    }
    if (query.from) {
      const fromDate = new Date(query.from).getTime();
      results = results.filter((t) => new Date(t.started_at).getTime() >= fromDate);
    }
    if (query.to) {
      const toDate = new Date(query.to).getTime();
      results = results.filter((t) => new Date(t.started_at).getTime() <= toDate);
    }

    // Sort by started_at descending
    results.sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());

    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;
    results = results.slice(offset, offset + limit);

    // Attach spans to each trace
    return results.map((t) => {
      const spans = this.spans.get(t.id) ?? [];
      return { ...structuredClone(t), spans: structuredClone(spans) };
    });
  }

  async updateTrace(traceId: string, updates: Partial<Trace>): Promise<void> {
    const existing = this.traces.get(traceId);
    if (!existing) throw new Error(`Trace ${traceId} not found`);
    Object.assign(existing, updates);
  }

  // ---- Span operations ----

  async saveSpan(span: Span): Promise<void> {
    const existing = this.spans.get(span.trace_id) ?? [];
    const idx = existing.findIndex((s) => s.id === span.id);
    if (idx >= 0) {
      existing[idx] = structuredClone(span);
    } else {
      existing.push(structuredClone(span));
    }
    this.spans.set(span.trace_id, existing);
  }

  async getSpansByTrace(traceId: string): Promise<Span[]> {
    return structuredClone(this.spans.get(traceId) ?? []);
  }

  // ---- Violation operations ----

  async saveViolation(violation: StoredViolation): Promise<void> {
    this.violations.push(structuredClone(violation));
  }

  async queryViolations(query: ViolationQuery): Promise<StoredViolation[]> {
    let results = [...this.violations];

    if (query.agent_id) {
      results = results.filter((v) => v.agent_id === query.agent_id);
    }
    if (query.policy_name) {
      results = results.filter((v) => v.policy_name === query.policy_name);
    }
    if (query.effect) {
      results = results.filter((v) => v.effect === query.effect);
    }
    if (query.from) {
      const fromDate = new Date(query.from).getTime();
      results = results.filter((v) => new Date(v.occurred_at).getTime() >= fromDate);
    }
    if (query.to) {
      const toDate = new Date(query.to).getTime();
      results = results.filter((v) => new Date(v.occurred_at).getTime() <= toDate);
    }

    results.sort((a, b) => new Date(b.occurred_at).getTime() - new Date(a.occurred_at).getTime());

    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;
    return results.slice(offset, offset + limit);
  }

  // ---- Attribution operations ----

  async saveReport(report: AttributionReport): Promise<void> {
    this.reports.set(report.id, structuredClone(report));
  }

  async getReport(reportId: string): Promise<AttributionReport | null> {
    const report = this.reports.get(reportId);
    return report ? structuredClone(report) : null;
  }

  async getReportsByTrace(traceId: string): Promise<AttributionReport[]> {
    return [...this.reports.values()]
      .filter((r) => r.trace_id === traceId)
      .map((r) => structuredClone(r));
  }
}
