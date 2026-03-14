import type {
  Trace,
  Span,
  StorageBackend,
  TraceQuery,
  ViolationQuery,
  StoredViolation,
  AttributionReport,
} from '../types.js';

type BetterSqlite3Database = {
  pragma(sql: string): void;
  exec(sql: string): void;
  prepare(sql: string): {
    run(...params: unknown[]): { changes: number };
    get(...params: unknown[]): Record<string, unknown> | undefined;
    all(...params: unknown[]): Record<string, unknown>[];
  };
  close(): void;
};

/**
 * SQLite storage backend using better-sqlite3.
 * Requires: npm install better-sqlite3
 */
export class SqliteStorage implements StorageBackend {
  private db!: BetterSqlite3Database;

  constructor(private readonly dbPath: string) {}

  async initialize(): Promise<void> {
    let Database: new (path: string) => BetterSqlite3Database;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      Database = require('better-sqlite3');
    } catch {
      throw new Error(
        'SQLite storage requires "better-sqlite3" package. Install it with: npm install better-sqlite3',
      );
    }

    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.createTables();
  }

  async close(): Promise<void> {
    this.db.close();
  }

  private createTables(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS traces (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        agent_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        status TEXT NOT NULL,
        metadata TEXT,
        integrity_hash TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_traces_agent_id ON traces(agent_id);
      CREATE INDEX IF NOT EXISTS idx_traces_status ON traces(status);
      CREATE INDEX IF NOT EXISTS idx_traces_started_at ON traces(started_at);

      CREATE TABLE IF NOT EXISTS spans (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL,
        parent_span_id TEXT,
        sequence INTEGER NOT NULL,
        action_type TEXT NOT NULL,
        name TEXT NOT NULL,
        input TEXT,
        output TEXT,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        duration_ms INTEGER,
        status TEXT NOT NULL,
        policy_evaluations TEXT,
        error TEXT,
        metadata TEXT,
        hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        FOREIGN KEY (trace_id) REFERENCES traces(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_spans_trace_id ON spans(trace_id);

      CREATE TABLE IF NOT EXISTS violations (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL,
        span_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        effect TEXT NOT NULL,
        message TEXT,
        context TEXT,
        occurred_at TEXT NOT NULL,
        FOREIGN KEY (trace_id) REFERENCES traces(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_violations_agent_id ON violations(agent_id);
      CREATE INDEX IF NOT EXISTS idx_violations_policy ON violations(policy_name);

      CREATE TABLE IF NOT EXISTS attribution_reports (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL,
        failure_span_id TEXT,
        root_causes TEXT,
        causal_chain TEXT,
        timeline TEXT,
        summary TEXT,
        severity TEXT,
        recommendations TEXT,
        generated_at TEXT NOT NULL,
        FOREIGN KEY (trace_id) REFERENCES traces(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_reports_trace_id ON attribution_reports(trace_id);
    `);
  }

  // ---- Trace operations ----

  async saveTrace(trace: Trace): Promise<void> {
    this.db.prepare(`
      INSERT OR REPLACE INTO traces (id, session_id, agent_id, started_at, ended_at, status, metadata, integrity_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      trace.id,
      trace.session_id ?? null,
      trace.agent_id,
      trace.started_at,
      trace.ended_at ?? null,
      trace.status,
      trace.metadata ? JSON.stringify(trace.metadata) : null,
      trace.integrity_hash,
    );
  }

  async getTrace(traceId: string): Promise<Trace | null> {
    const row = this.db.prepare('SELECT * FROM traces WHERE id = ?').get(traceId);
    if (!row) return null;

    const spans = await this.getSpansByTrace(traceId);
    return this.rowToTrace(row, spans);
  }

  async queryTraces(query: TraceQuery): Promise<Trace[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (query.agent_id) {
      conditions.push('agent_id = ?');
      params.push(query.agent_id);
    }
    if (query.session_id) {
      conditions.push('session_id = ?');
      params.push(query.session_id);
    }
    if (query.status) {
      conditions.push('status = ?');
      params.push(query.status);
    }
    if (query.from) {
      conditions.push('started_at >= ?');
      params.push(query.from);
    }
    if (query.to) {
      conditions.push('started_at <= ?');
      params.push(query.to);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = query.limit ?? 100;
    const offset = query.offset ?? 0;

    const rows = this.db.prepare(
      `SELECT * FROM traces ${where} ORDER BY started_at DESC LIMIT ? OFFSET ?`,
    ).all(...params, limit, offset);

    const results: Trace[] = [];
    for (const row of rows) {
      const spans = await this.getSpansByTrace(row['id'] as string);
      results.push(this.rowToTrace(row, spans));
    }
    return results;
  }

  async updateTrace(traceId: string, updates: Partial<Trace>): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [];

    if (updates.ended_at !== undefined) {
      sets.push('ended_at = ?');
      params.push(updates.ended_at);
    }
    if (updates.status !== undefined) {
      sets.push('status = ?');
      params.push(updates.status);
    }
    if (updates.integrity_hash !== undefined) {
      sets.push('integrity_hash = ?');
      params.push(updates.integrity_hash);
    }

    if (sets.length === 0) return;

    params.push(traceId);
    this.db.prepare(`UPDATE traces SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  }

  // ---- Span operations ----

  async saveSpan(span: Span): Promise<void> {
    this.db.prepare(`
      INSERT OR REPLACE INTO spans
        (id, trace_id, parent_span_id, sequence, action_type, name, input, output,
         started_at, ended_at, duration_ms, status, policy_evaluations, error, metadata, hash, previous_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
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
    );
  }

  async getSpansByTrace(traceId: string): Promise<Span[]> {
    const rows = this.db.prepare(
      'SELECT * FROM spans WHERE trace_id = ? ORDER BY sequence ASC',
    ).all(traceId);

    return rows.map((row) => this.rowToSpan(row));
  }

  // ---- Violation operations ----

  async saveViolation(violation: StoredViolation): Promise<void> {
    this.db.prepare(`
      INSERT OR REPLACE INTO violations
        (id, trace_id, span_id, agent_id, policy_name, rule_id, effect, message, context, occurred_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
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
    );
  }

  async queryViolations(query: ViolationQuery): Promise<StoredViolation[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (query.agent_id) {
      conditions.push('agent_id = ?');
      params.push(query.agent_id);
    }
    if (query.policy_name) {
      conditions.push('policy_name = ?');
      params.push(query.policy_name);
    }
    if (query.effect) {
      conditions.push('effect = ?');
      params.push(query.effect);
    }
    if (query.from) {
      conditions.push('occurred_at >= ?');
      params.push(query.from);
    }
    if (query.to) {
      conditions.push('occurred_at <= ?');
      params.push(query.to);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = query.limit ?? 100;
    const offset = query.offset ?? 0;

    const rows = this.db.prepare(
      `SELECT * FROM violations ${where} ORDER BY occurred_at DESC LIMIT ? OFFSET ?`,
    ).all(...params, limit, offset);

    return rows.map((row) => this.rowToViolation(row));
  }

  // ---- Attribution operations ----

  async saveReport(report: AttributionReport): Promise<void> {
    this.db.prepare(`
      INSERT OR REPLACE INTO attribution_reports
        (id, trace_id, failure_span_id, root_causes, causal_chain, timeline, summary, severity, recommendations, generated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
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
    );
  }

  async getReport(reportId: string): Promise<AttributionReport | null> {
    const row = this.db.prepare('SELECT * FROM attribution_reports WHERE id = ?').get(reportId);
    if (!row) return null;
    return this.rowToReport(row);
  }

  async getReportsByTrace(traceId: string): Promise<AttributionReport[]> {
    const rows = this.db.prepare(
      'SELECT * FROM attribution_reports WHERE trace_id = ? ORDER BY generated_at DESC',
    ).all(traceId);
    return rows.map((row) => this.rowToReport(row));
  }

  // ---- Row mapping helpers ----

  private rowToTrace(row: Record<string, unknown>, spans: Span[]): Trace {
    return {
      id: row['id'] as string,
      session_id: row['session_id'] as string | undefined,
      agent_id: row['agent_id'] as string,
      started_at: row['started_at'] as string,
      ended_at: row['ended_at'] as string | undefined,
      status: row['status'] as Trace['status'],
      spans,
      metadata: row['metadata'] ? JSON.parse(row['metadata'] as string) : undefined,
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
      input: JSON.parse(row['input'] as string),
      output: row['output'] ? JSON.parse(row['output'] as string) : undefined,
      started_at: row['started_at'] as string,
      ended_at: row['ended_at'] as string | undefined,
      duration_ms: row['duration_ms'] as number | undefined,
      status: row['status'] as Span['status'],
      policy_evaluations: JSON.parse(row['policy_evaluations'] as string),
      error: row['error'] ? JSON.parse(row['error'] as string) : undefined,
      metadata: row['metadata'] ? JSON.parse(row['metadata'] as string) : undefined,
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
      context: JSON.parse(row['context'] as string),
      occurred_at: row['occurred_at'] as string,
    };
  }

  private rowToReport(row: Record<string, unknown>): AttributionReport {
    return {
      id: row['id'] as string,
      trace_id: row['trace_id'] as string,
      failure_span_id: row['failure_span_id'] as string,
      root_causes: JSON.parse(row['root_causes'] as string),
      causal_chain: JSON.parse(row['causal_chain'] as string),
      timeline: JSON.parse(row['timeline'] as string),
      summary: row['summary'] as string,
      severity: row['severity'] as AttributionReport['severity'],
      recommendations: JSON.parse(row['recommendations'] as string),
      generated_at: row['generated_at'] as string,
    };
  }
}
