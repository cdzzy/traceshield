import type {
  Trace,
  Span,
  StorageBackend,
  TraceQuery,
  ViolationQuery,
  StoredViolation,
  AttributionReport,
} from '../types.js';

type PgPool = {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  end(): Promise<void>;
};

/**
 * PostgreSQL storage backend using pg (node-postgres).
 * Requires: npm install pg
 */
export class PostgresStorage implements StorageBackend {
  private pool!: PgPool;

  constructor(private readonly connectionString: string) {}

  async initialize(): Promise<void> {
    let PgPool: new (config: { connectionString: string }) => PgPool;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const pg = require('pg');
      PgPool = pg.Pool;
    } catch {
      throw new Error(
        'PostgreSQL storage requires "pg" package. Install it with: npm install pg',
      );
    }

    this.pool = new PgPool({ connectionString: this.connectionString });
    await this.createTables();
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  private async createTables(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS traces (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        agent_id TEXT NOT NULL,
        started_at TIMESTAMPTZ NOT NULL,
        ended_at TIMESTAMPTZ,
        status TEXT NOT NULL,
        metadata JSONB,
        integrity_hash TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_traces_agent_id ON traces(agent_id);
      CREATE INDEX IF NOT EXISTS idx_traces_status ON traces(status);
      CREATE INDEX IF NOT EXISTS idx_traces_started_at ON traces(started_at);

      CREATE TABLE IF NOT EXISTS spans (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
        parent_span_id TEXT,
        sequence INTEGER NOT NULL,
        action_type TEXT NOT NULL,
        name TEXT NOT NULL,
        input JSONB,
        output JSONB,
        started_at TIMESTAMPTZ NOT NULL,
        ended_at TIMESTAMPTZ,
        duration_ms INTEGER,
        status TEXT NOT NULL,
        policy_evaluations JSONB NOT NULL DEFAULT '[]',
        error JSONB,
        metadata JSONB,
        hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_spans_trace_id ON spans(trace_id);

      CREATE TABLE IF NOT EXISTS violations (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
        span_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        effect TEXT NOT NULL,
        message TEXT,
        context JSONB,
        occurred_at TIMESTAMPTZ NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_violations_agent_id ON violations(agent_id);
      CREATE INDEX IF NOT EXISTS idx_violations_policy ON violations(policy_name);

      CREATE TABLE IF NOT EXISTS attribution_reports (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
        failure_span_id TEXT,
        root_causes JSONB,
        causal_chain JSONB,
        timeline JSONB,
        summary TEXT,
        severity TEXT,
        recommendations JSONB,
        generated_at TIMESTAMPTZ NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_reports_trace_id ON attribution_reports(trace_id);
    `);
  }

  // ---- Trace operations ----

  async saveTrace(trace: Trace): Promise<void> {
    await this.pool.query(
      `INSERT INTO traces (id, session_id, agent_id, started_at, ended_at, status, metadata, integrity_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (id) DO UPDATE SET
         ended_at = EXCLUDED.ended_at, status = EXCLUDED.status,
         metadata = EXCLUDED.metadata, integrity_hash = EXCLUDED.integrity_hash`,
      [
        trace.id,
        trace.session_id ?? null,
        trace.agent_id,
        trace.started_at,
        trace.ended_at ?? null,
        trace.status,
        trace.metadata ? JSON.stringify(trace.metadata) : null,
        trace.integrity_hash,
      ],
    );
  }

  async getTrace(traceId: string): Promise<Trace | null> {
    const result = await this.pool.query('SELECT * FROM traces WHERE id = $1', [traceId]);
    if (result.rows.length === 0) return null;

    const spans = await this.getSpansByTrace(traceId);
    return this.rowToTrace(result.rows[0], spans);
  }

  async queryTraces(query: TraceQuery): Promise<Trace[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIdx = 1;

    if (query.agent_id) {
      conditions.push(`agent_id = $${paramIdx++}`);
      params.push(query.agent_id);
    }
    if (query.session_id) {
      conditions.push(`session_id = $${paramIdx++}`);
      params.push(query.session_id);
    }
    if (query.status) {
      conditions.push(`status = $${paramIdx++}`);
      params.push(query.status);
    }
    if (query.from) {
      conditions.push(`started_at >= $${paramIdx++}`);
      params.push(query.from);
    }
    if (query.to) {
      conditions.push(`started_at <= $${paramIdx++}`);
      params.push(query.to);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = query.limit ?? 100;
    const offset = query.offset ?? 0;

    params.push(limit, offset);
    const result = await this.pool.query(
      `SELECT * FROM traces ${where} ORDER BY started_at DESC LIMIT $${paramIdx++} OFFSET $${paramIdx}`,
      params,
    );

    const results: Trace[] = [];
    for (const row of result.rows) {
      const spans = await this.getSpansByTrace(row['id'] as string);
      results.push(this.rowToTrace(row, spans));
    }
    return results;
  }

  async updateTrace(traceId: string, updates: Partial<Trace>): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [];
    let paramIdx = 1;

    if (updates.ended_at !== undefined) {
      sets.push(`ended_at = $${paramIdx++}`);
      params.push(updates.ended_at);
    }
    if (updates.status !== undefined) {
      sets.push(`status = $${paramIdx++}`);
      params.push(updates.status);
    }
    if (updates.integrity_hash !== undefined) {
      sets.push(`integrity_hash = $${paramIdx++}`);
      params.push(updates.integrity_hash);
    }

    if (sets.length === 0) return;

    params.push(traceId);
    await this.pool.query(
      `UPDATE traces SET ${sets.join(', ')} WHERE id = $${paramIdx}`,
      params,
    );
  }

  // ---- Span operations ----

  async saveSpan(span: Span): Promise<void> {
    await this.pool.query(
      `INSERT INTO spans
        (id, trace_id, parent_span_id, sequence, action_type, name, input, output,
         started_at, ended_at, duration_ms, status, policy_evaluations, error, metadata, hash, previous_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
       ON CONFLICT (id) DO UPDATE SET
         output = EXCLUDED.output, ended_at = EXCLUDED.ended_at, duration_ms = EXCLUDED.duration_ms,
         status = EXCLUDED.status, policy_evaluations = EXCLUDED.policy_evaluations,
         error = EXCLUDED.error, hash = EXCLUDED.hash`,
      [
        span.id,
        span.trace_id,
        span.parent_span_id ?? null,
        span.sequence,
        span.action_type,
        span.name,
        JSON.stringify(span.input),
        span.output !== undefined ? JSON.stringify(span.output) : null,
        span.started_at,
        span.ended_at ?? null,
        span.duration_ms ?? null,
        span.status,
        JSON.stringify(span.policy_evaluations),
        span.error ? JSON.stringify(span.error) : null,
        span.metadata ? JSON.stringify(span.metadata) : null,
        span.hash,
        span.previous_hash,
      ],
    );
  }

  async getSpansByTrace(traceId: string): Promise<Span[]> {
    const result = await this.pool.query(
      'SELECT * FROM spans WHERE trace_id = $1 ORDER BY sequence ASC',
      [traceId],
    );
    return result.rows.map((row) => this.rowToSpan(row));
  }

  // ---- Violation operations ----

  async saveViolation(violation: StoredViolation): Promise<void> {
    await this.pool.query(
      `INSERT INTO violations
        (id, trace_id, span_id, agent_id, policy_name, rule_id, effect, message, context, occurred_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (id) DO NOTHING`,
      [
        violation.id,
        violation.trace_id,
        violation.span_id,
        violation.agent_id,
        violation.policy_name,
        violation.rule_id,
        violation.effect,
        violation.message ?? null,
        JSON.stringify(violation.context),
        violation.occurred_at,
      ],
    );
  }

  async queryViolations(query: ViolationQuery): Promise<StoredViolation[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIdx = 1;

    if (query.agent_id) {
      conditions.push(`agent_id = $${paramIdx++}`);
      params.push(query.agent_id);
    }
    if (query.policy_name) {
      conditions.push(`policy_name = $${paramIdx++}`);
      params.push(query.policy_name);
    }
    if (query.effect) {
      conditions.push(`effect = $${paramIdx++}`);
      params.push(query.effect);
    }
    if (query.from) {
      conditions.push(`occurred_at >= $${paramIdx++}`);
      params.push(query.from);
    }
    if (query.to) {
      conditions.push(`occurred_at <= $${paramIdx++}`);
      params.push(query.to);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = query.limit ?? 100;
    const offset = query.offset ?? 0;

    params.push(limit, offset);
    const result = await this.pool.query(
      `SELECT * FROM violations ${where} ORDER BY occurred_at DESC LIMIT $${paramIdx++} OFFSET $${paramIdx}`,
      params,
    );

    return result.rows.map((row) => this.rowToViolation(row));
  }

  // ---- Attribution operations ----

  async saveReport(report: AttributionReport): Promise<void> {
    await this.pool.query(
      `INSERT INTO attribution_reports
        (id, trace_id, failure_span_id, root_causes, causal_chain, timeline, summary, severity, recommendations, generated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (id) DO NOTHING`,
      [
        report.id,
        report.trace_id,
        report.failure_span_id,
        JSON.stringify(report.root_causes),
        JSON.stringify(report.causal_chain),
        JSON.stringify(report.timeline),
        report.summary,
        report.severity,
        JSON.stringify(report.recommendations),
        report.generated_at,
      ],
    );
  }

  async getReport(reportId: string): Promise<AttributionReport | null> {
    const result = await this.pool.query(
      'SELECT * FROM attribution_reports WHERE id = $1',
      [reportId],
    );
    if (result.rows.length === 0) return null;
    return this.rowToReport(result.rows[0]);
  }

  async getReportsByTrace(traceId: string): Promise<AttributionReport[]> {
    const result = await this.pool.query(
      'SELECT * FROM attribution_reports WHERE trace_id = $1 ORDER BY generated_at DESC',
      [traceId],
    );
    return result.rows.map((row) => this.rowToReport(row));
  }

  // ---- Row mapping helpers ----

  private rowToTrace(row: Record<string, unknown>, spans: Span[]): Trace {
    return {
      id: row['id'] as string,
      session_id: row['session_id'] as string | undefined,
      agent_id: row['agent_id'] as string,
      started_at: (row['started_at'] as Date).toISOString(),
      ended_at: row['ended_at'] ? (row['ended_at'] as Date).toISOString() : undefined,
      status: row['status'] as Trace['status'],
      spans,
      metadata: row['metadata'] as Record<string, unknown> | undefined,
      integrity_hash: row['integrity_hash'] as string,
    };
  }

  private rowToSpan(row: Record<string, unknown>): Span {
    return {
      id: row['id'] as string,
      trace_id: row['trace_id'] as string,
      parent_span_id: row['parent_span_id'] as string | undefined,
      sequence: row['sequence'] as number,
      action_type: row['action_type'] as Span['action_type'],
      name: row['name'] as string,
      input: row['input'],
      output: row['output'] ?? undefined,
      started_at: (row['started_at'] as Date).toISOString(),
      ended_at: row['ended_at'] ? (row['ended_at'] as Date).toISOString() : undefined,
      duration_ms: row['duration_ms'] as number | undefined,
      status: row['status'] as Span['status'],
      policy_evaluations: row['policy_evaluations'] as Span['policy_evaluations'],
      error: row['error'] as Span['error'] | undefined,
      metadata: row['metadata'] as Record<string, unknown> | undefined,
      hash: row['hash'] as string,
      previous_hash: row['previous_hash'] as string,
    };
  }

  private rowToViolation(row: Record<string, unknown>): StoredViolation {
    return {
      id: row['id'] as string,
      trace_id: row['trace_id'] as string,
      span_id: row['span_id'] as string,
      agent_id: row['agent_id'] as string,
      policy_name: row['policy_name'] as string,
      rule_id: row['rule_id'] as string,
      effect: row['effect'] as StoredViolation['effect'],
      message: row['message'] as string | undefined,
      context: row['context'] as StoredViolation['context'],
      occurred_at: (row['occurred_at'] as Date).toISOString(),
    };
  }

  private rowToReport(row: Record<string, unknown>): AttributionReport {
    return {
      id: row['id'] as string,
      trace_id: row['trace_id'] as string,
      failure_span_id: row['failure_span_id'] as string,
      root_causes: row['root_causes'] as AttributionReport['root_causes'],
      causal_chain: row['causal_chain'] as AttributionReport['causal_chain'],
      timeline: row['timeline'] as AttributionReport['timeline'],
      summary: row['summary'] as string,
      severity: row['severity'] as AttributionReport['severity'],
      recommendations: row['recommendations'] as string[],
      generated_at: (row['generated_at'] as Date).toISOString(),
    };
  }
}

