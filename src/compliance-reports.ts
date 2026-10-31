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

// ─── Shared aggregation across standards ─────────────────────────────────────

export type ComplianceStandard = 'soc2' | 'gdpr' | 'hipaa';

interface Aggregated {
  blocked: number;
  flagged: number;
  totalViolations: number;
  violationSummaries: ViolationSummary[];
  agentSummaries: AgentSummary[];
  totalActions: number;
  complianceRate: number;
  averageLatencyMs: number;
}

/**
 * Roll a set of traces into the per-rule and per-agent breakdown shared by
 * every compliance report. Kept in one place so SOC 2, GDPR and HIPAA cannot
 * drift into slightly different arithmetic.
 */
function aggregate(traces: Trace[]): Aggregated {
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

  const totalActions = traces.reduce((s, t) => s + t.spans.length, 0);
  for (const agent of agentMap.values()) {
    agent.complianceRate = agent.totalActions > 0
      ? ((agent.totalActions - agent.violations) / agent.totalActions) * 100
      : 100;
  }

  const complianceRate = totalActions > 0 ? ((totalActions - total) / totalActions) * 100 : 100;
  const averageLatencyMs = traces
    .flatMap((t) => t.spans)
    .reduce((s, span) => s + (span.duration_ms ?? 0), 0) / Math.max(totalActions, 1);

  return {
    blocked,
    flagged,
    totalViolations: total,
    violationSummaries: violationSummaries.sort((a, b) => b.count - a.count),
    agentSummaries: [...agentMap.values()],
    totalActions,
    complianceRate,
    averageLatencyMs,
  };
}

// ─── SOC 2 Compliance Report ─────────────────────────────────────────────────

export function generateSOC2Report(
  traces: Trace[],
  options: { from?: number; to?: number; orgName?: string; auditorName?: string } = {},
): ComplianceReport {
  const { from = Date.now() - 30 * 24 * 3600 * 1000, to = Date.now(), orgName = 'Your Organization', auditorName = 'External Auditor' } = options;

  const agg = aggregate(traces);

  return {
    title: 'SOC 2 Compliance Audit Report',
    generatedAt: new Date().toISOString(),
    period: { from, to },
    summary: {
      totalTraces: traces.length,
      totalViolations: agg.totalViolations,
      blockedActions: agg.blocked,
      flaggedActions: agg.flagged,
      complianceRate: agg.complianceRate,
      averageLatencyMs: agg.averageLatencyMs,
      agentsCovered: agg.agentSummaries.length,
    },
    violations: agg.violationSummaries,
    agents: agg.agentSummaries,
    recommendations: generateRecommendations(agg.complianceRate, agg.violationSummaries),
    rawData: { orgName, auditorName, standard: 'SOC 2 Type II' },
  };
}

// ─── GDPR Compliance Report ──────────────────────────────────────────────────

export function generateGDPRReport(
  traces: Trace[],
  options: { from?: number; to?: number; dataController?: string } = {},
): ComplianceReport {
  const { from = Date.now() - 30 * 24 * 3600 * 1000, to = Date.now(), dataController = 'Data Controller' } = options;

  const agg = aggregate(traces);

  return {
    title: 'GDPR Compliance Report',
    generatedAt: new Date().toISOString(),
    period: { from, to },
    summary: {
      totalTraces: traces.length,
      totalViolations: agg.totalViolations,
      blockedActions: agg.blocked,
      flaggedActions: agg.flagged,
      complianceRate: agg.complianceRate,
      averageLatencyMs: agg.averageLatencyMs,
      agentsCovered: agg.agentSummaries.length,
    },
    // Previously these were hardcoded to [] — the report showed a total
    // violation count but no breakdown, which is useless to an auditor.
    violations: agg.violationSummaries,
    agents: agg.agentSummaries,
    recommendations: generateGDPRRecommendations(agg.blocked, agg.flagged),
    rawData: { dataController, standard: 'GDPR Article 30, 35' },
  };
}

// ─── HIPAA Compliance Report ─────────────────────────────────────────────────

/** Matches span names / policy rule ids that suggest PHI (ePHI) involvement. */
const PHI_KEYWORD_PATTERN = /(phi|e?phi|patient|medical|health|hipaa|ehr|medical_record)/i;

/** Metadata keys commonly used to tag data classification. */
const PHI_METADATA_KEYS = ['data_classification', 'dataClass', 'classification', 'phi'];
const PHI_METADATA_VALUES = /(phi|ephi|restricted|sensitive)/i;

/**
 * Count spans that touch Protected Health Information.
 *
 * A span counts as PHI-touching when any of these hold:
 *   - its name matches a PHI keyword (patient / medical / ehr / ...),
 *   - a policy rule id or policy name on it matches the same keywords,
 *   - its metadata tags the data classification as PHI / restricted.
 */
function collectPhiAccess(traces: Trace[]): {
  phiEvents: number;
  phiViolations: number;
  phiAgents: string[];
  phiRuleIds: string[];
} {
  let phiEvents = 0;
  let phiViolations = 0;
  const phiAgents = new Set<string>();
  const phiRuleIds = new Set<string>();

  for (const trace of traces) {
    for (const span of trace.spans) {
      let touchesPhi = PHI_KEYWORD_PATTERN.test(span.name ?? '');

      if (!touchesPhi) {
        for (const key of PHI_METADATA_KEYS) {
          const value = span.metadata?.[key];
          if (typeof value === 'string' && PHI_METADATA_VALUES.test(value)) {
            touchesPhi = true;
            break;
          }
          if (value === true && key === 'phi') {
            touchesPhi = true;
            break;
          }
        }
      }

      const matchedRules: string[] = [];
      for (const evaluation of span.policy_evaluations) {
        const haystack = `${evaluation.rule_id} ${evaluation.policy_name}`;
        if (PHI_KEYWORD_PATTERN.test(haystack)) {
          touchesPhi = true;
          matchedRules.push(evaluation.rule_id);
        }
      }

      if (matchedRules.length > 0 && (span.policy_evaluations.some(
        (e) => matchedRules.includes(e.rule_id) && e.result !== 'allow',
      ))) {
        phiViolations++;
      }

      if (touchesPhi) {
        phiEvents++;
        phiAgents.add(trace.agent_id);
        for (const ruleId of matchedRules) phiRuleIds.add(ruleId);
      }
    }
  }

  return { phiEvents, phiViolations, phiAgents: [...phiAgents], phiRuleIds: [...phiRuleIds] };
}

export function generateHIPAAReport(
  traces: Trace[],
  options: { from?: number; to?: number; coveredEntity?: string } = {},
): ComplianceReport {
  const { from = Date.now() - 30 * 24 * 3600 * 1000, to = Date.now(), coveredEntity = 'Covered Entity' } = options;

  const agg = aggregate(traces);
  const phi = collectPhiAccess(traces);

  return {
    title: 'HIPAA Compliance Report',
    generatedAt: new Date().toISOString(),
    period: { from, to },
    summary: {
      totalTraces: traces.length,
      totalViolations: agg.totalViolations,
      blockedActions: agg.blocked,
      flaggedActions: agg.flagged,
      complianceRate: agg.complianceRate,
      averageLatencyMs: agg.averageLatencyMs,
      agentsCovered: agg.agentSummaries.length,
    },
    violations: agg.violationSummaries,
    agents: agg.agentSummaries,
    recommendations: generateHIPAARecommendations(agg.complianceRate, phi),
    rawData: {
      coveredEntity,
      standard: 'HIPAA Security Rule §164.312',
      provisions: {
        'access-control': '§164.312(a)(1)',
        'audit-controls': '§164.312(b)',
        'integrity': '§164.312(c)(1)',
        'transmission-security': '§164.312(e)(1)',
      },
      phiAccessEvents: phi.phiEvents,
      phiViolations: phi.phiViolations,
      phiAgents: phi.phiAgents,
      phiRules: phi.phiRuleIds,
    },
  };
}

/**
 * Generate a report for any supported standard. Convenience entry point for
 * callers that pick the framework at runtime (CLI flag, config value, ...).
 */
export function generateComplianceReport(
  traces: Trace[],
  standard: ComplianceStandard,
  options: { from?: number; to?: number; orgName?: string } = {},
): ComplianceReport {
  switch (standard) {
    case 'soc2':
      return generateSOC2Report(traces, options);
    case 'gdpr':
      return generateGDPRReport(traces, { from: options.from, to: options.to, dataController: options.orgName });
    case 'hipaa':
      return generateHIPAAReport(traces, { from: options.from, to: options.to, coveredEntity: options.orgName });
    default: {
      const unreachable: never = standard;
      throw new Error(`Unsupported compliance standard: ${String(unreachable)}`);
    }
  }
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

  // HIPAA reports carry PHI accounting in rawData; surface it so auditors do
  // not have to dig into the JSON payload.
  const raw = report.rawData;
  if (raw && typeof raw.phiAccessEvents === 'number') {
    lines.push('## PHI Access (§164.312(b) Audit Controls)');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('|--------|-------|');
    lines.push(`| PHI Access Events | ${raw.phiAccessEvents} |`);
    lines.push(`| PHI Policy Violations | ${raw.phiViolations ?? 0} |`);
    const phiAgents = raw.phiAgents;
    lines.push(`| Agents Touching PHI | ${Array.isArray(phiAgents) ? phiAgents.length : 0} |`);
    if (Array.isArray(phiAgents) && phiAgents.length > 0) {
      lines.push(`| PHI Agent IDs | ${phiAgents.join(', ')} |`);
    }
    if (typeof raw.coveredEntity === 'string') {
      lines.push(`| Covered Entity | ${raw.coveredEntity} |`);
    }
    if (typeof raw.standard === 'string') {
      lines.push(`| Standard | ${raw.standard} |`);
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

function generateHIPAARecommendations(
  complianceRate: number,
  phi: { phiEvents: number; phiViolations: number; phiAgents: string[] },
): string[] {
  const recs: string[] = [];
  if (complianceRate < 95) {
    recs.push(`URGENT: Compliance rate (${complianceRate.toFixed(1)}%) below the 95% threshold required for PHI-handling systems.`);
  }
  if (phi.phiViolations > 0) {
    recs.push(`CRITICAL: ${phi.phiViolations} policy violation(s) on PHI-touching actions. §164.312(b) audit controls require immediate review.`);
  }
  if (phi.phiEvents > 0) {
    recs.push(
      `NOTICE: ${phi.phiEvents} PHI access event(s) across ${phi.phiAgents.length} agent(s) (${phi.phiAgents.join(', ')}). Retain these audit records for 6 years under §164.316(b)(2)(i).`,
    );
  } else {
    recs.push('No PHI access detected in this period. Confirm PHI classification tags are applied to all clinical data flows.');
  }
  recs.push('Verify encryption in transit and at rest for all ePHI stores (§164.312(e)(1)).');
  recs.push('Run an annual HIPAA risk assessment and document remediation (§164.308(a)(1)(ii)(A)).');
  return recs;
}
