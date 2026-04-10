// ============================================================
// TraceShield - Anomaly Detection Engine
// Inspired by shannon's white-box security scanning
// ============================================================

import { EventEmitter } from 'node:events';
import type { Trace, TraceId, AgentId, TraceType, TraceLevel } from './types.js';

// ---- Anomaly Types ----

export type AnomalyType =
  | 'rate_spike'
  | 'error_spike'
  | 'permission_denied_spike'
  | 'latency_anomaly'
  | 'behavioral_drift'
  | 'security_event'
  | 'unusual_pattern';

export type AnomalySeverity = 'low' | 'medium' | 'high' | 'critical';

export interface AnomalyDetectionConfig {
  /** Enable/disable anomaly detection */
  enabled: boolean;
  /** Window size in milliseconds for rate calculations */
  windowMs: number;
  /** Number of standard deviations above mean to trigger rate spike */
  rateSpikeThreshold: number;
  /** Number of errors in window to trigger error spike */
  errorSpikeThreshold: number;
  /** Minimum samples before anomaly detection kicks in */
  minSamples: number;
  /** Latency percentile threshold (e.g., 99th percentile) */
  latencyPercentile: number;
  /** Latency threshold multiplier (alert if current > historical * multiplier) */
  latencyMultiplier: number;
  /** Check interval in milliseconds */
  checkIntervalMs: number;
}

export const DEFAULT_ANOMALY_CONFIG: AnomalyDetectionConfig = {
  enabled: true,
  windowMs: 60_000,          // 1 minute
  rateSpikeThreshold: 3.0,   // 3 standard deviations
  errorSpikeThreshold: 10,    // 10 errors in window
  minSamples: 20,
  latencyPercentile: 95,
  latencyMultiplier: 3.0,
  checkIntervalMs: 10_000,    // 10 seconds
};

export interface Anomaly {
  id: string;
  type: AnomalyType;
  severity: AnomalySeverity;
  timestamp: number;
  agentId: AgentId | 'global';
  description: string;
  metric: string;
  value: number;
  threshold: number;
  relatedTraceIds: TraceId[];
  suggestions: string[];
  resolved: boolean;
  resolvedAt: number | null;
}

export interface AnomalyStats {
  totalDetected: number;
  byType: Record<AnomalyType, number>;
  bySeverity: Record<AnomalySeverity, number>;
  byAgent: Record<string, number>;
  unresolvedCount: number;
  lastDetectedAt: number | null;
}

// ---- Events ----

export interface AnomalyEvents {
  'anomaly:detected': (anomaly: Anomaly) => void;
  'anomaly:resolved': (anomaly: Anomaly) => void;
  'anomaly:stats-updated': (stats: AnomalyStats) => void;
}

export class TypedEventEmitter extends EventEmitter {
  override emit<K extends keyof AnomalyEvents>(
    event: K, ...args: Parameters<AnomalyEvents[K]>
  ): boolean;
  override emit(event: string, ...args: unknown[]): boolean {
    return super.emit(event, ...args);
  }

  override on<K extends keyof AnomalyEvents>(
    event: K, listener: AnomalyEvents[K]
  ): this;
  override on(event: string, listener: (...args: unknown[]) => void): this {
    return super.on(event, listener);
  }

  override off<K extends keyof AnomalyEvents>(
    event: K, listener: AnomalyEvents[K]
  ): this;
  override off(event: string, listener: (...args: unknown[]) => void): this {
    return super.off(event, listener);
  }
}

// ---- Internal data structures ----

interface TraceWindow {
  count: number;
  errors: number;
  securityEvents: number;
  permissionDenied: number;
  latencySum: number;
  latencies: number[];
  traceIds: TraceId[];
  byType: Record<TraceType, number>;
}

// ---- AnomalyDetector ----

export class AnomalyDetector {
  private config: AnomalyDetectionConfig;
  private events: TypedEventEmitter;
  private traces: Trace[] = [];
  private anomalies: Anomaly[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  private historicalRateStats: { mean: number; stddev: number } | null = null;

  constructor(config?: Partial<AnomalyDetectionConfig>) {
    this.config = { ...DEFAULT_ANOMALY_CONFIG, ...config };
    this.events = new TypedEventEmitter();
  }

  /**
   * Feed a trace into the detector for analysis.
   */
  ingest(trace: Trace): void {
    this.traces.push(trace);

    // Prune old traces beyond 2x window
    const cutoff = Date.now() - this.config.windowMs * 2;
    this.traces = this.traces.filter(t => t.timestamp >= cutoff);
  }

  /**
   * Run a single anomaly detection pass.
   */
  detect(): Anomaly[] {
    if (!this.config.enabled) return [];
    if (this.traces.length < this.config.minSamples) return [];

    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const windowTraces = this.traces.filter(t => t.timestamp >= windowStart);

    const detected: Anomaly[] = [];

    // Check rate spike
    const rateAnomaly = this._checkRateSpike(windowTraces, now);
    if (rateAnomaly) detected.push(rateAnomaly);

    // Check error spike
    const errorAnomaly = this._checkErrorSpike(windowTraces, now);
    if (errorAnomaly) detected.push(errorAnomaly);

    // Check permission denied spike
    const permAnomaly = this._checkPermissionDenied(windowTraces, now);
    if (permAnomaly) detected.push(permAnomaly);

    // Check latency anomaly
    const latencyAnomaly = this._checkLatencyAnomaly(windowTraces, now);
    if (latencyAnomaly) detected.push(latencyAnomaly);

    // Check per-agent anomalies
    const agentGroups = this._groupByAgent(windowTraces);
    for (const [agentId, agentTraces] of agentGroups) {
      if (agentTraces.length >= this.config.minSamples) {
        const agentAnomaly = this._checkAgentBehavioralDrift(agentId, agentTraces, now);
        if (agentAnomaly) detected.push(agentAnomaly);
      }
    }

    // Store and emit
    for (const anomaly of detected) {
      this.anomalies.push(anomaly);
      this.events.emit('anomaly:detected', anomaly);
    }

    if (detected.length > 0) {
      this.events.emit('anomaly:stats-updated', this.getStats());
    }

    return detected;
  }

  /**
   * Resolve an anomaly by ID.
   */
  resolve(anomalyId: string): boolean {
    const anomaly = this.anomalies.find(a => a.id === anomalyId);
    if (!anomaly || anomaly.resolved) return false;

    anomaly.resolved = true;
    anomaly.resolvedAt = Date.now();
    this.events.emit('anomaly:resolved', anomaly);
    this.events.emit('anomaly:stats-updated', this.getStats());
    return true;
  }

  /**
   * Start automatic periodic detection.
   */
  startAuto(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.detect().catch(() => {});
    }, this.config.checkIntervalMs);
  }

  /**
   * Stop automatic detection.
   */
  stopAuto(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  getAnomalies(options?: { unresolved?: boolean; severity?: AnomalySeverity; limit?: number }): Anomaly[] {
    let results = [...this.anomalies];
    if (options?.unresolved) results = results.filter(a => !a.resolved);
    if (options?.severity) results = results.filter(a => a.severity === options.severity);
    results.sort((a, b) => b.timestamp - a.timestamp);
    return options?.limit ? results.slice(0, options.limit) : results;
  }

  getStats(): AnomalyStats {
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byAgent: Record<string, number> = {};

    for (const a of this.anomalies) {
      byType[a.type] = (byType[a.type] || 0) + 1;
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
      if (a.agentId !== 'global') {
        byAgent[a.agentId] = (byAgent[a.agentId] || 0) + 1;
      }
    }

    return {
      totalDetected: this.anomalies.length,
      byType: byType as Record<AnomalyType, number>,
      bySeverity: bySeverity as Record<AnomalySeverity, number>,
      byAgent,
      unresolvedCount: this.anomalies.filter(a => !a.resolved).length,
      lastDetectedAt: this.anomalies.length > 0
        ? this.anomalies[this.anomalies.length - 1].timestamp
        : null,
    };
  }

  getEventEmitter(): TypedEventEmitter {
    return this.events;
  }

  // ---- Detection Methods ----

  private _checkRateSpike(traces: Trace[], now: number): Anomaly | null {
    const rate = traces.length / (this.config.windowMs / 1000);
    if (this.historicalRateStats) {
      const { mean, stddev } = this.historicalRateStats;
      const zScore = stddev > 0 ? (rate - mean) / stddev : 0;
      if (zScore > this.config.rateSpikeThreshold) {
        return this._createAnomaly({
          type: 'rate_spike',
          severity: zScore > 6 ? 'critical' : zScore > 4 ? 'high' : 'medium',
          agentId: 'global',
          description: `Trace rate spike: ${rate.toFixed(1)}/s ` +
            `(${zScore.toFixed(1)} sigma above mean ${mean.toFixed(1)}/s)`,
          metric: 'trace_rate_per_second',
          value: rate,
          threshold: mean + this.config.rateSpikeThreshold * stddev,
          relatedTraceIds: traces.slice(-10).map(t => t.id),
          suggestions: [
            'Check for runaway agent loops or recursive calls',
            'Verify rate limiting is properly configured',
            'Review recent deployments or configuration changes',
          ],
          now,
        });
      }
    }
    // Update running stats
    this._updateRateStats(rate);
    return null;
  }

  private _checkErrorSpike(traces: Trace[], now: number): Anomaly | null {
    const errorTraces = traces.filter(t =>
      t.type === 'error' || t.level === 'error' || t.level === 'critical'
    );
    if (errorTraces.length >= this.config.errorSpikeThreshold) {
      return this._createAnomaly({
        type: 'error_spike',
        severity: errorTraces.length > 30 ? 'critical' : 'high',
        agentId: 'global',
        description: `Error spike detected: ${errorTraces.length} errors in last ` +
          `${this.config.windowMs / 1000}s`,
        metric: 'error_count',
        value: errorTraces.length,
        threshold: this.config.errorSpikeThreshold,
        relatedTraceIds: errorTraces.slice(-10).map(t => t.id),
        suggestions: [
          'Review error traces for common root causes',
          'Check if external dependencies are failing',
          'Verify agent health checks are passing',
        ],
        now,
      });
    }
    return null;
  }

  private _checkPermissionDenied(traces: Trace[], now: number): Anomaly | null {
    const denied = traces.filter(t =>
      t.type === 'security' && t.data &&
      'event' in t.data &&
      (t.data as { event: string }).event === 'permission'
    );
    if (denied.length >= 5) {
      const agentIds = [...new Set(denied.map(t => t.agentId))];
      return this._createAnomaly({
        type: 'permission_denied_spike',
        severity: 'high',
        agentId: agentIds.length === 1 ? agentIds[0] : 'global',
        description: `Permission denied spike: ${denied.length} denials ` +
          `from ${agentIds.length} agent(s)`,
        metric: 'permission_denied_count',
        value: denied.length,
        threshold: 5,
        relatedTraceIds: denied.map(t => t.id),
        suggestions: [
          'Review permission policies for recently added agents',
          'Check if agents are attempting unauthorized operations',
          'Consider updating ACL rules if behavior is expected',
        ],
        now,
      });
    }
    return null;
  }

  private _checkLatencyAnomaly(traces: Trace[], now: number): Anomaly | null {
    // Extract action/tool_call traces with duration
    const timedTraces = traces.filter(t =>
      t.data && 'duration' in t.data
    );
    if (timedTraces.length < 5) return null;

    const latencies = timedTraces.map(t => (t.data as { duration?: number }).duration || 0);
    const avgLatency = latencies.reduce((s, l) => s + l, 0) / latencies.length;
    const maxLatency = Math.max(...latencies);

    // Simple heuristic: if max latency is significantly above average
    if (avgLatency > 0 && maxLatency > avgLatency * this.config.latencyMultiplier) {
      const slowTraces = timedTraces.filter(t =>
        (t.data as { duration?: number }).duration! > avgLatency * this.config.latencyMultiplier
      );
      return this._createAnomaly({
        type: 'latency_anomaly',
        severity: maxLatency > avgLatency * 10 ? 'high' : 'medium',
        agentId: 'global',
        description: `Latency anomaly: max ${maxLatency.toFixed(0)}ms ` +
          `(avg ${avgLatency.toFixed(0)}ms, ${this.config.latencyMultiplier}x threshold)`,
        metric: 'latency_ms',
        value: maxLatency,
        threshold: avgLatency * this.config.latencyMultiplier,
        relatedTraceIds: slowTraces.slice(-5).map(t => t.id),
        suggestions: [
          'Investigate slow tool calls or external API requests',
          'Check for resource contention or queue buildup',
          'Review agent timeout configurations',
        ],
        now,
      });
    }
    return null;
  }

  private _checkAgentBehavioralDrift(
    agentId: string,
    traces: Trace[],
    now: number,
  ): Anomaly | null {
    // Check if an agent is producing unusual trace type distribution
    const typeCounts: Record<string, number> = {};
    for (const t of traces) {
      typeCounts[t.type] = (typeCounts[t.type] || 0) + 1;
    }

    // Detect if one type dominates unusually
    const total = traces.length;
    for (const [type, count] of Object.entries(typeCounts)) {
      const ratio = count / total;
      if (ratio > 0.8 && total > 10) {
        return this._createAnomaly({
          type: 'behavioral_drift',
          severity: 'medium',
          agentId,
          description: `Agent behavioral drift: ${type} traces make up ` +
            `${(ratio * 100).toFixed(0)}% of all activity (${count}/${total})`,
          metric: 'trace_type_ratio',
          value: ratio,
          threshold: 0.8,
          relatedTraceIds: traces.filter(t => t.type === type).slice(-5).map(t => t.id),
          suggestions: [
            'Review agent logic for potential infinite loops',
            'Check if the agent is stuck in a retry pattern',
            'Verify agent task completion criteria',
          ],
          now,
        });
      }
    }

    return null;
  }

  private _createAnomaly(params: {
    type: AnomalyType;
    severity: AnomalySeverity;
    agentId: string;
    description: string;
    metric: string;
    value: number;
    threshold: number;
    relatedTraceIds: TraceId[];
    suggestions: string[];
    now: number;
  }): Anomaly {
    return {
      id: `anomaly_${params.now}_${Math.random().toString(36).slice(2, 8)}`,
      type: params.type,
      severity: params.severity,
      timestamp: params.now,
      agentId: params.agentId,
      description: params.description,
      metric: params.metric,
      value: params.value,
      threshold: params.threshold,
      relatedTraceIds: params.relatedTraceIds,
      suggestions: params.suggestions,
      resolved: false,
      resolvedAt: null,
    };
  }

  private _updateRateStats(currentRate: number): void {
    const alpha = 0.1; // smoothing factor
    if (this.historicalRateStats) {
      const diff = currentRate - this.historicalRateStats.mean;
      this.historicalRateStats.mean += alpha * diff;
      this.historicalRateStats.stddev = Math.sqrt(
        (1 - alpha) * this.historicalRateStats.stddev ** 2 + alpha * diff ** 2
      );
    } else {
      this.historicalRateStats = { mean: currentRate, stddev: 0 };
    }
  }

  private _groupByAgent(traces: Trace[]): Map<AgentId, Trace[]> {
    const groups = new Map<AgentId, Trace[]>();
    for (const t of traces) {
      if (!groups.has(t.agentId)) groups.set(t.agentId, []);
      groups.get(t.agentId)!.push(t);
    }
    return groups;
  }
}
