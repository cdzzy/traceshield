import type {
  Trace,
  TraceId,
  AgentId,
  TraceType,
  TraceLevel,
  TraceData,
  TraceShieldConfig,
  ShieldRule,
  ShieldAction,
  ShieldCondition,
  AuditRecord,
  AnomalyAlert,
} from './types.js';
import { TypedEventEmitter } from './types.js';

/**
 * TraceShield — Agent behavior tracing and protection system.
 * 
 * Provides:
 * - Comprehensive trace recording with hierarchical spans
 * - Shield rules for blocking/warning/masking sensitive operations
 * - Audit logging for compliance
 * - Anomaly detection
 */
export class TraceShield extends TypedEventEmitter {
  private config: Required<TraceShieldConfig>;
  private traces = new Map<TraceId, Trace>();
  private agentSpans = new Map<AgentId, TraceId[]>();  // Active spans per agent
  private shieldRules: ShieldRule[] = [];
  private auditRecords: AuditRecord[] = [];
  private traceIdCounter = 0;

  // Anomaly detection state
  private errorCount = 0;
  private actionCount = 0;
  private lastAnomalyCheck = Date.now();
  private anomalyWindowMs = 60_000;

  constructor(config: TraceShieldConfig = {}) {
    super();

    this.config = {
      tracing: {
        enabled: config.tracing?.enabled ?? true,
        level: config.tracing?.level ?? 'info',
        maxTraces: config.tracing?.maxTraces ?? 100_000,
        retentionMs: config.tracing?.retentionMs ?? 24 * 60 * 60 * 1000,
        sampleRate: config.tracing?.sampleRate ?? 1.0,
      },
      shielding: {
        enabled: config.shielding?.enabled ?? true,
        failClosed: config.shielding?.failClosed ?? false,
      },
      audit: {
        enabled: config.audit?.enabled ?? true,
        storage: config.audit?.storage ?? 'memory',
      },
    };
  }

  // ---- Tracing ----

  /**
   * Record a new trace entry.
   */
  record(agentId: AgentId, type: TraceType, data: TraceData, options?: {
    level?: TraceLevel;
    parentId?: TraceId;
    tags?: Record<string, string>;
  }): Trace {
    // Sampling check
    if (Math.random() > this.config.tracing.sampleRate) {
      const dummyTrace: Trace = {
        id: `sampled-${this.traceIdCounter++}`,
        agentId,
        type,
        level: 'debug',
        timestamp: Date.now(),
        data,
      };
      return dummyTrace;
    }

    const trace: Trace = {
      id: `trace-${this.traceIdCounter++}`,
      agentId,
      type,
      level: options?.level ?? 'info',
      timestamp: Date.now(),
      parentId: options?.parentId,
      data,
      tags: options?.tags,
    };

    // Check shield rules before recording
    if (this.config.shielding.enabled) {
      const shieldResult = this.checkShields(trace);
      if (shieldResult.blocked) {
        this.recordAudit({
          id: `audit-${trace.id}`,
          timestamp: trace.timestamp,
          agentId: trace.agentId,
          traceId: trace.id,
          ruleId: shieldResult.rule?.id,
          action: shieldResult.rule?.action ?? 'block',
          result: 'blocked',
          details: { reason: shieldResult.reason },
        });
        
        this.emit('shield:blocked', trace, shieldResult.rule!);
        
        if (this.config.shielding.failClosed) {
          return { ...trace, redacted: true, data: { error: 'Blocked by shield rule' } as any };
        }
      } else if (shieldResult.warned) {
        this.emit('shield:warned', trace, shieldResult.rule!);
      }
    }

    // Store trace
    this.traces.set(trace.id, trace);

    // Track active span
    if (!this.agentSpans.has(agentId)) {
      this.agentSpans.set(agentId, []);
    }
    if (trace.parentId) {
      this.agentSpans.get(agentId)!.push(trace.parentId);
    }

    // Update stats
    this.actionCount++;
    if (type === 'error') {
      this.errorCount++;
    }

    // Cleanup old traces if needed
    this.cleanupTraces();

    // Check for anomalies
    this.checkAnomalies();

    this.emit('trace:recorded', trace);
    return trace;
  }

  /**
   * Start a new span (for hierarchical tracing).
   */
  startSpan(agentId: AgentId, name: string, parentId?: TraceId): Trace {
    return this.record(agentId, 'action', {
      action: name,
      result: 'pending',
    }, { parentId });
  }

  /**
   * End a span with result.
   */
  endSpan(trace: Trace, result: unknown, duration?: number): void {
    if (trace.data && typeof trace.data === 'object' && 'action' in trace.data) {
      (trace.data as any).result = result;
      (trace.data as any).duration = duration;
    }
  }

  /**
   * Get traces for an agent.
   */
  getTraces(agentId: AgentId, options?: {
    type?: TraceType;
    level?: TraceLevel;
    since?: number;
    limit?: number;
  }): Trace[] {
    let results: Trace[] = [];

    for (const trace of this.traces.values()) {
      if (trace.agentId !== agentId) continue;
      if (options?.type && trace.type !== options.type) continue;
      if (options?.level && this.compareLevel(trace.level, options.level) < 0) continue;
      if (options?.since && trace.timestamp < options.since) continue;
      
      results.push(trace);
    }

    results.sort((a, b) => b.timestamp - a.timestamp);

    if (options?.limit) {
      results = results.slice(0, options.limit);
    }

    return results;
  }

  // ---- Shielding ----

  /**
   * Add a shield rule.
   */
  addRule(rule: ShieldRule): void {
    this.shieldRules.push(rule);
    this.shieldRules.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Remove a shield rule.
   */
  removeRule(ruleId: string): boolean {
    const index = this.shieldRules.findIndex(r => r.id === ruleId);
    if (index >= 0) {
      this.shieldRules.splice(index, 1);
      return true;
    }
    return false;
  }

  /**
   * Get all shield rules.
   */
  getRules(): ShieldRule[] {
    return [...this.shieldRules];
  }

  private checkShields(trace: Trace): {
    blocked: boolean;
    warned: boolean;
    rule?: ShieldRule;
    reason?: string;
  } {
    for (const rule of this.shieldRules) {
      if (!rule.enabled) continue;

      const matched = this.matchRule(rule, trace);
      if (matched) {
        if (rule.action === 'block' || rule.action === 'mask') {
          return { blocked: true, warned: false, rule, reason: rule.response };
        } else if (rule.action === 'warn') {
          return { blocked: false, warned: true, rule, reason: rule.response };
        }
      }
    }

    return { blocked: false, warned: false };
  }

  private matchRule(rule: ShieldRule, trace: Trace): boolean {
    for (const condition of rule.conditions) {
      if (!this.matchCondition(condition, trace)) {
        return false;
      }
    }
    return true;
  }

  private matchCondition(condition: ShieldCondition, trace: Trace): boolean {
    switch (condition.type) {
      case 'data': {
        const fieldValue = this.getFieldValue(condition.field, trace);
        if (fieldValue === undefined) return false;
        
        if (condition.operator === 'contains') {
          return String(fieldValue).includes(condition.value as string);
        } else if (condition.operator === 'equals') {
          return fieldValue === condition.value;
        } else if (condition.operator === 'matches') {
          return new RegExp(condition.value as string).test(String(fieldValue));
        } else if (condition.operator === 'in') {
          return (condition.value as string[]).includes(String(fieldValue));
        }
        return false;
      }

      case 'action': {
        if (condition.agentId && trace.agentId !== condition.agentId) return false;
        if (condition.action && trace.data && typeof trace.data === 'object' && 'action' in trace.data) {
          return (trace.data as any).action === condition.action;
        }
        return !condition.action;  // Pass if no action specified
      }

      case 'time': {
        const now = new Date();
        const currentTime = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
        const currentDay = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][now.getDay()];
        
        if (condition.start && currentTime < condition.start) return false;
        if (condition.end && currentTime > condition.end) return false;
        if (condition.days && !condition.days.includes(currentDay)) return false;
        return true;
      }

      case 'rate': {
        // Simplified rate limiting check
        const windowStart = Date.now() - condition.window;
        let count = 0;
        for (const t of this.traces.values()) {
          if (t.agentId === trace.agentId && t.timestamp > windowStart) {
            count++;
          }
        }
        return count < condition.maxCount;
      }

      case 'pattern': {
        const fieldValue = this.getFieldValue(condition.field, trace);
        if (fieldValue === undefined) return false;
        return new RegExp(condition.pattern).test(String(fieldValue));
      }

      default:
        return true;
    }
  }

  private getFieldValue(field: string, trace: Trace): unknown {
    switch (field) {
      case 'agentId': return trace.agentId;
      case 'type': return trace.type;
      case 'level': return trace.level;
      case 'timestamp': return trace.timestamp;
      default:
        if (trace.data && typeof trace.data === 'object') {
          return (trace.data as any)[field];
        }
        return undefined;
    }
  }

  private compareLevel(a: TraceLevel, b: TraceLevel): number {
    const levels: Record<TraceLevel, number> = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3,
      critical: 4,
    };
    return levels[a] - levels[b];
  }

  // ---- Audit ----

  private recordAudit(record: AuditRecord): void {
    this.auditRecords.push(record);
    this.emit('audit:created', record);
  }

  /**
   * Get audit records.
   */
  getAuditRecords(options?: {
    agentId?: AgentId;
    since?: number;
    limit?: number;
  }): AuditRecord[] {
    let results = this.auditRecords;

    if (options?.agentId) {
      results = results.filter(r => r.agentId === options.agentId);
    }
    if (options?.since) {
      results = results.filter(r => r.timestamp >= options.since);
    }

    results.sort((a, b) => b.timestamp - a.timestamp);

    if (options?.limit) {
      results = results.slice(0, options.limit);
    }

    return results;
  }

  // ---- Anomaly Detection ----

  private checkAnomalies(): void {
    const now = Date.now();
    if (now - this.lastAnomalyCheck < this.anomalyWindowMs) return;

    const errorRate = this.errorCount / this.actionCount;
    
    // Detect error rate spike
    if (errorRate > 0.1) {
      this.emit('anomaly:detected', {
        id: `anomaly-${now}`,
        timestamp: now,
        type: 'error_spike',
        severity: errorRate > 0.3 ? 'critical' : 'high',
        description: `Error rate ${(errorRate * 100).toFixed(1)}% exceeds threshold`,
        relatedTraces: [],
      });
    }

    this.errorCount = 0;
    this.actionCount = 0;
    this.lastAnomalyCheck = now;
  }

  // ---- Cleanup ----

  private cleanupTraces(): void {
    if (this.traces.size < this.config.tracing.maxTraces) return;

    const cutoff = Date.now() - this.config.tracing.retentionMs;
    for (const [id, trace] of this.traces) {
      if (trace.timestamp < cutoff) {
        this.traces.delete(id);
      }
    }

    // If still too many, remove oldest
    while (this.traces.size > this.config.tracing.maxTraces * 0.9) {
      const oldest = this.traces.keys().next().value;
      if (oldest) this.traces.delete(oldest);
    }
  }

  // ---- Metrics ----

  /**
   * Get system metrics.
   */
  getMetrics() {
    return {
      traces: {
        total: this.traces.size,
        byType: this.getTraceCountsByType(),
        byLevel: this.getTraceCountsByLevel(),
      },
      audit: {
        total: this.auditRecords.length,
      },
      shields: {
        active: this.shieldRules.filter(r => r.enabled).length,
      },
    };
  }

  private getTraceCountsByType(): Record<TraceType, number> {
    const counts: Record<TraceType, number> = {
      action: 0,
      decision: 0,
      tool_call: 0,
      message: 0,
      resource: 0,
      security: 0,
      error: 0,
    };
    for (const trace of this.traces.values()) {
      counts[trace.type]++;
    }
    return counts;
  }

  private getTraceCountsByLevel(): Record<TraceLevel, number> {
    const counts: Record<TraceLevel, number> = {
      debug: 0,
      info: 0,
      warn: 0,
      error: 0,
      critical: 0,
    };
    for (const trace of this.traces.values()) {
      counts[trace.level]++;
    }
    return counts;
  }
}
