/**
 * Agent behavior baseline learning for anomaly detection (Issue #5).
 *
 * Learns normal per-agent behavior (tool usage distribution, action rates) over
 * a learning period, then flags deviations (e.g. an agent suddenly using a tool
 * it never touched before) as anomalies.
 */

import type { Trace } from './types.js';

export interface BehaviorAnomaly {
  agentId: string;
  tool: string;
  kind: 'new_tool' | 'rate_spike';
  baselineCount: number;
  observedCount: number;
  description: string;
  detectedAt: number;
}

interface AgentProfile {
  toolCounts: Map<string, number>;
  totalActions: number;
}

export class BehaviorBaseline {
  private profiles = new Map<string, AgentProfile>();
  private learning = true;
  private readonly learningPeriodMs: number;
  private readonly anomalyThreshold: number;

  constructor(options: { learningPeriodMs?: number; anomalyThreshold?: number } = {}) {
    this.learningPeriodMs = options.learningPeriodMs ?? 0; // 0 = learn on demand
    this.anomalyThreshold = options.anomalyThreshold ?? 3; // times above baseline
  }

  /**
   * Feed a trace into the baseline. During the learning phase, only the profile
   * is updated; afterwards, anomalies are detected.
   */
  observe(trace: Trace): BehaviorAnomaly[] {
    const agentId = trace.agent_id;
    let profile = this.profiles.get(agentId);
    if (!profile) {
      profile = { toolCounts: new Map(), totalActions: 0 };
      this.profiles.set(agentId, profile);
    }

    const anomalies: BehaviorAnomaly[] = [];
    for (const span of trace.spans) {
      const tool = span.action_type === 'tool_call' ? span.name : span.action_type;
      const existing = profile.toolCounts.get(tool) ?? 0;

      if (!this.learning && existing === 0) {
        anomalies.push({
          agentId,
          tool,
          kind: 'new_tool',
          baselineCount: 0,
          observedCount: 1,
          description: `Agent "${agentId}" used "${tool}" for the first time (never in baseline)`,
          detectedAt: Date.now(),
        });
      }

      profile.toolCounts.set(tool, existing + 1);
      profile.totalActions++;
    }

    return anomalies;
  }

  /**
   * End the learning phase — subsequent observations detect anomalies.
   */
  finishLearning(): void {
    this.learning = false;
  }

  /**
   * Reset the baseline.
   */
  reset(): void {
    this.profiles.clear();
    this.learning = true;
  }

  getProfile(agentId: string): Record<string, number> | null {
    const profile = this.profiles.get(agentId);
    if (!profile) return null;
    return Object.fromEntries(profile.toolCounts);
  }
}
