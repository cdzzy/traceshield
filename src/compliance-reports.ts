/**
 * Compliance Report Templates for TraceShield.
 *
 * Generates audit reports for SOC2 and GDPR compliance from a set of
 * recorded traces (new architecture: Trace / Span model).
 */

import type { Trace, Span } from './types.js';

export interface ComplianceReport {
  title: string;
  generatedAt: string;
  period: { from: number; to: number };
  summary: ComplianceSummary;
  violations: ViolationSummary[];
  agents: AgentSummary[];
  recommendations: string[];
  rawData?: Record<string, unknown>;
}

export interface ComplianceSummary {
  totalTraces: number;
  totalViolations: number;
  blockedActions: number;
  flaggedActions: number;
  complianceRate: number;
  averageLatencyMs: number;
  agentsCovered: number;
}

export interface ViolationSummary {
  ruleName: string;
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  lastOccurred: string;
  affectedAgents: string[];
  examples: string[];
}

export interface AgentSummary {
  agentId: string;
  totalActions: number;
  violations: number;
  complianceRate: number;
  topCapabilities: string[];
}

function collectViolations(traces: Trace[]): { blocked: number; flagged: number; total: number; spans: Span[]; violations: { rule_id: string; policy_name: string; message?: string; agent_id: string; occurred_at: string; span: Span }[] } {
  let blocked = 0;
  let flagged = 0;
  let total = 0;
  const violations: { rule_id: string; policy_name: string; message?: string; agent_id: string; occurred_at: string; span: Span }[] = [];

  for (const trace of traces) {
    for (const span of trace.spans) {
      for (const evaluation of span.policy_evaluations) {
        if (evaluation.result === 'deny') blocked++;
        else if (evaluation.result === 'warn') flagged++;
        else continue;
        total++;
        violations.push({
          rule_id: evaluation.rule_id,
          policy_name: evaluation.policy_name,
          message: evaluation.message,
          agent_id: trace.agent_id,
          occurred_at: evaluation.evaluated_at,
          span,
        });
      }
    }
  }

  return { blocked, flagged, total, spans: traces.flatMap((t) => t.spans), violations };
}

// ─── SOC 2 Compliance Report ─────────────────────────────────────────────────

export function generateSOC2Report(
  traces: Trace[],
  options: { from?: number; to?: number; orgName?: string; auditorName?: string } = {},
): ComplianceReport {
  const { from = Date.now() - 30 * 24 * 3600 * 1000, to = Date.now(), orgName = 'Your Organization', auditorName = 'External Auditor' } = options;

  const { blocked, flagged, total, violations } = collectViolations(traces);

  const violationSummaries: ViolationSummary[] = [];
  const byRule = new Map<string, ViolationSummary>();
  for (const v of violations) {
    const existing = byRule.get(v.rule_id);
    if (existing) {
      existing.count++;
      if (!existing.affectedAgents.includes(v.agent_id)) existing.affectedAgents.push(v.agent_id);
    } else {
      const summary: ViolationSummary = {
        ruleName: v.rule_id,
        count: 1,
        severity: 'medium',
        lastOccurred: v.occurred_at,
        affectedAgents: [v.agent_id],
        examples: [v.message ?? v.policy_name],
      };
      byRule.set(v.rule_id, summary);
      violationSummaries.push(summary);
    }
  }

  const agentMap = new Map<string, AgentSummary>();
  for (const trace of traces) {
    if (!agentMap.has(trace.agent_id)) {
      agentMap.set(trace.agent_id, {
        agentId: trace.agent_id,
        totalActions: 0,
        violations: 0,
        complianceRate: 100,
        topCapabilities: [],
      });
    }
    agentMap.get(trace.agent_id)!.totalActions += trace.spans.length;
  }
  for (const v of violations) {
    const agent = agentMap.get(v.agent_id);
    if (agent) agent.violations++;
  }
  for (const agent of agentMap.values()) {
    agent.complianceRate = agent.totalActions > 0
      ? ((agent.totalActions - agent.violations) / agent.totalActions) * 100
      : 100;
  }

  const totalActions = traces.reduce((s, t) => s + t.spans.length, 0);
  const complianceRate = totalActions > 0 ? ((totalActions - total) / totalActions) * 100 : 100;
  const avgLatency = traces.flatMap((t) => t.spans).reduce((s, span) => s + (span.duration_ms ?? 0), 0) / Math.max(totalActions, 1);

  return {
    title: 'SOC 2 Compliance Audit Report',
    generatedAt: new Date().toISOString(),
    period: { from, to },
    summary: {
      totalTraces: traces.length,
      totalViolations: total,
      blockedActions: blocked,
      flaggedActions: flagged,
      complianceRate,
      averageLatencyMs: avgLatency,
      agentsCovered: agentMap.size,
    },
    violations: violationSummaries.sort((a, b) => b.count - a.count),
    agents: [...agentMap.values()],
    recommendations: generateRecommendations(complianceRate, violationSummaries),
    rawData: { orgName, auditorName, standard: 'SOC 2 Type II' },
  };
}

// ─── GDPR Compliance Report ──────────────────────────────────────────────────

export function generateGDPRReport(
  traces: Trace[],
  options: { from?: number; to?: number; dataController?: string } = {},
): ComplianceReport {
  const { from = Date.now() - 30 * 24 * 3600 * 1000, to = Date.now(), dataController = 'Data Controller' } = options;

  const { blocked, flagged, total, violations } = collectViolations(traces);

  const complianceRate = traces.reduce((s, t) => s + t.spans.length, 0) > 0
    ? ((traces.reduce((s, t) => s + t.spans.length, 0) - total) / traces.reduce((s, t) => s + t.spans.length, 0)) * 100
    : 100;

  return {
    title: 'GDPR Compliance Report',
    generatedAt: new Date().toISOString(),
    period: { from, to },
    summary: {
      totalTraces: traces.length,
      totalViolations: total,
      blockedActions: blocked,
      flaggedActions: flagged,
      complianceRate,
      averageLatencyMs: 0,
      agentsCovered: new Set(violations.map((v) => v.agent_id)).size,
    },
    violations: [],
    agents: [],
    recommendations: generateGDPRRecommendations(blocked, flagged),
    rawData: { dataController, standard: 'GDPR Article 30, 35' },
  };
}

// ─── Report Formatting ────────────────────────────────────────────────────────

export function formatReportAsMarkdown(report: ComplianceReport): string {
  const lines: string[] = [];
  lines.push(`# ${report.title}`);
  lines.push('');
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push(`**Period:** ${new Date(report.period.from).toISOString()} → ${new Date(report.period.to).toISOString()}`);
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total Traces | ${report.summary.totalTraces} |`);
  lines.push(`| Total Violations | ${report.summary.totalViolations} |`);
  lines.push(`| Blocked Actions | ${report.summary.blockedActions} |`);
  lines.push(`| Flagged Actions | ${report.summary.flaggedActions} |`);
  lines.push(`| Compliance Rate | ${report.summary.complianceRate.toFixed(1)}% |`);
  lines.push(`| Agents Covered | ${report.summary.agentsCovered} |`);
  lines.push('');

  if (report.violations.length > 0) {
    lines.push('## Violations');
    lines.push('');
    for (const v of report.violations) {
      lines.push(`- **${v.ruleName}**: ${v.count} occurrences (${v.severity})`);
      lines.push(`  - Last: ${v.lastOccurred}`);
      lines.push(`  - Affected: ${v.affectedAgents.join(', ')}`);
    }
    lines.push('');
  }

  if (report.agents.length > 0) {
    lines.push('## Agent Breakdown');
    lines.push('');
    lines.push('| Agent | Actions | Violations | Compliance |');
    lines.push('|-------|---------|------------|------------|');
    for (const a of report.agents) {
      lines.push(`| ${a.agentId} | ${a.totalActions} | ${a.violations} | ${a.complianceRate.toFixed(1)}% |`);
    }
    lines.push('');
  }

  if (report.recommendations.length > 0) {
    lines.push('## Recommendations');
    lines.push('');
    for (const rec of report.recommendations) {
      lines.push(`- ${rec}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function generateRecommendations(complianceRate: number, violations: ViolationSummary[]): string[] {
  const recs: string[] = [];
  if (complianceRate < 95) {
    recs.push(`URGENT: Compliance rate (${complianceRate.toFixed(1)}%) below 95% threshold.`);
  }
  if (violations.filter((v) => v.severity === 'critical').length > 0) {
    recs.push(`CRITICAL violations detected. Review: ${violations.filter((v) => v.severity === 'critical').map((v) => v.ruleName).join(', ')}`);
  }
  recs.push('Implement quarterly automated compliance reviews.');
  return recs;
}

function generateGDPRRecommendations(blocked: number, flagged: number): string[] {
  const recs: string[] = [];
  if (blocked > 0) recs.push(`WARNING: ${blocked} unauthorized data access attempts were blocked.`);
  if (flagged > 0) recs.push(`NOTICE: ${flagged} actions flagged for data-access review.`);
  recs.push('Conduct Data Protection Impact Assessment (DPIA) for all agent data access patterns.');
  return recs;
}
