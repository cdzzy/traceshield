/**
 * Compliance Report Templates for TraceShield.
 * 
 * Generates audit reports for SOC2, GDPR, and HIPAA compliance.
 * 
 * Reference: Inspired by enterprise compliance automation patterns.
 * 
 * Usage:
 *   import { generateSOC2Report, generateGDPRReport } from './compliance-reports';
 */

import { TraceRecorder } from './trace-recorder';
import type { TraceRecord, PolicyOutcome } from './types';

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
  complianceRate: number; // percentage
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

// ─── SOC 2 Compliance Report ─────────────────────────────────────────────────

export async function generateSOC2Report(
  recorder: TraceRecorder,
  options: {
    from?: number;
    to?: number;
    orgName?: string;
   auditorName?: string;
  } = {}
): Promise<ComplianceReport> {
  const { from = Date.now() - 30 * 24 * 3600 * 1000, to = Date.now(), orgName = "Your Organization", auditorName = "External Auditor" } = options;

  const traces = await recorder.query({ from, to: to + 1 });
  
  const violations: ViolationSummary[] = [];
  const agentMap = new Map<string, AgentSummary>();
  
  let totalViolations = 0;
  let blockedActions = 0;
  let flaggedActions = 0;
  
  for (const trace of traces) {
    if (trace.policy?.outcome === 'blocked') blockedActions++;
    else if (trace.policy?.outcome === 'flagged') flaggedActions++;
    
    if (trace.policy?.outcome === 'blocked' || trace.policy?.outcome === 'flagged') {
      totalViolations++;
      
      const ruleName = trace.policy?.rule ?? 'unknown';
      const existing = violations.find(v => v.ruleName === ruleName);
      if (existing) {
        existing.count++;
      } else {
        violations.push({
          ruleName,
          count: 1,
          severity: 'medium',
          lastOccurred: new Date(trace.timestamp).toISOString(),
          affectedAgents: [trace.agentId],
          examples: [trace.action],
        });
      }
    }
    
    // Agent summary
    if (!agentMap.has(trace.agentId)) {
      agentMap.set(trace.agentId, {
        agentId: trace.agentId,
        totalActions: 0,
        violations: 0,
        complianceRate: 100,
        topCapabilities: [],
      });
    }
    const agent = agentMap.get(trace.agentId)!;
    agent.totalActions++;
    if (trace.policy?.outcome === 'blocked' || trace.policy?.outcome === 'flagged') {
      agent.violations++;
    }
  }
  
  // Calculate compliance rates
  const complianceRate = traces.length > 0
    ? ((traces.length - totalViolations) / traces.length) * 100
    : 100;

  for (const agent of agentMap.values()) {
    agent.complianceRate = agent.totalActions > 0
      ? ((agent.totalActions - agent.violations) / agent.totalActions) * 100
      : 100;
  }
  
  const avgLatency = traces.length > 0
    ? traces.reduce((s, t) => s + (t.durationMs ?? 0), 0) / traces.length
    : 0;

  const report: ComplianceReport = {
    title: `SOC 2 Compliance Audit Report`,
    generatedAt: new Date().toISOString(),
    period: { from, to },
    summary: {
      totalTraces: traces.length,
      totalViolations,
      blockedActions,
      flaggedActions,
      complianceRate,
      averageLatencyMs: avgLatency,
      agentsCovered: agentMap.size,
    },
    violations: violations.sort((a, b) => b.count - a.count),
    agents: Array.from(agentMap.values()),
    recommendations: generateRecommendations(complianceRate, violations),
    rawData: {
      orgName,
      auditorName,
      standard: 'SOC 2 Type II',
    },
  };

  return report;
}

// ─── GDPR Compliance Report ──────────────────────────────────────────────────

export async function generateGDPRReport(
  recorder: TraceRecorder,
  options: {
    from?: number;
    to?: number;
    dataController?: string;
  } = {}
): Promise<ComplianceReport> {
  const { from = Date.now() - 30 * 24 * 3600 * 1000, to = Date.now(), dataController = "Data Controller" } = options;

  const traces = await recorder.query({ from, to: to + 1 });
  
  // GDPR-specific: look for data access traces
  const dataAccessTraces = traces.filter(t =>
    t.action.includes('data-read') ||
    t.action.includes('pii') ||
    (t.tags?.includes('pii')) ||
    (t.tags?.includes('personal-data'))
  );
  
  const consentViolations = dataAccessTraces.filter(t =>
    !t.metadata?.consentGiven
  );
  
  const unauthorizedAccess = dataAccessTraces.filter(t =>
    t.policy?.outcome === 'blocked'
  );

  const complianceRate = dataAccessTraces.length > 0
    ? ((dataAccessTraces.length - consentViolations.length - unauthorizedAccess.length) / dataAccessTraces.length) * 100
    : 100;

  const report: ComplianceReport = {
    title: `GDPR Compliance Report`,
    generatedAt: new Date().toISOString(),
    period: { from, to },
    summary: {
      totalTraces: dataAccessTraces.length,
      totalViolations: consentViolations.length + unauthorizedAccess.length,
      blockedActions: unauthorizedAccess.length,
      flaggedActions: consentViolations.length,
      complianceRate,
      averageLatencyMs: 0,
      agentsCovered: new Set(dataAccessTraces.map(t => t.agentId)).size,
    },
    violations: [
      {
        ruleName: 'consent-required',
        count: consentViolations.length,
        severity: 'critical',
        lastOccurred: consentViolations.length > 0
          ? new Date(Math.max(...consentViolations.map(t => t.timestamp))).toISOString()
          : new Date().toISOString(),
        affectedAgents: [...new Set(consentViolations.map(t => t.agentId))],
        examples: consentViolations.slice(0, 3).map(t => t.action),
      },
      {
        ruleName: 'unauthorized-data-access',
        count: unauthorizedAccess.length,
        severity: 'critical',
        lastOccurred: unauthorizedAccess.length > 0
          ? new Date(Math.max(...unauthorizedAccess.map(t => t.timestamp))).toISOString()
          : new Date().toISOString(),
        affectedAgents: [...new Set(unauthorizedAccess.map(t => t.agentId))],
        examples: unauthorizedAccess.slice(0, 3).map(t => t.action),
      },
    ].filter(v => v.count > 0),
    agents: [],
    recommendations: generateGDPRRecommendations(consentViolations.length, unauthorizedAccess.length),
    rawData: { dataController, standard: 'GDPR Article 30, 35' },
  };

  return report;
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
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
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
    lines.push(`| Agent | Actions | Violations | Compliance |`);
    lines.push(`|-------|---------|------------|------------|`);
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateRecommendations(
  complianceRate: number,
  violations: ViolationSummary[]
): string[] {
  const recs: string[] = [];
  
  if (complianceRate < 95) {
    recs.push(`URGENT: Compliance rate (${complianceRate.toFixed(1)}%) below 95% threshold. Review blocking rules and agent training.`);
  }
  
  if (violations.filter(v => v.severity === 'critical').length > 0) {
    recs.push(`CRITICAL violations detected. Implement immediate remediation for: ${violations.filter(v => v.severity === 'critical').map(v => v.ruleName).join(', ')}`);
  }
  
  const highVolumeViolations = violations.filter(v => v.count > 10);
  if (highVolumeViolations.length > 0) {
    recs.push(`High-volume violations (${highVolumeViolations.map(v => `${v.ruleName} (${v.count})`).join(', ')}) suggest systemic issues. Consider policy tuning.`);
  }
  
  recs.push('Implement quarterly automated compliance reviews.');
  recs.push('Consider adding LLM-as-judge for semantic policy evaluation.');
  
  return recs;
}

function generateGDPRRecommendations(
  consentViolations: number,
  unauthorizedAccess: number
): string[] {
  const recs: string[] = [];

  if (consentViolations > 0) {
    recs.push(`CRITICAL: ${consentViolations} data access actions without recorded consent. Implement consent tracking immediately.`);
  }

  if (unauthorizedAccess > 0) {
    recs.push(`WARNING: ${unauthorizedAccess} unauthorized data access attempts were blocked. Verify blocking rules are correctly configured.`);
  }

  recs.push('Conduct Data Protection Impact Assessment (DPIA) for all agent data access patterns.');
  recs.push('Implement data minimization: restrict agents to minimum necessary data access.');
  recs.push('Schedule quarterly GDPR compliance reviews using this report.');

  return recs;
}

// ─── AI Agent Security Report (AISEC) ─────────────────────────────────────────
// NIST AI Risk Management Framework aligned report

export interface AISecurityReport extends ComplianceReport {
  framework: 'NIST AI RMF' | 'ISO 42001';
  riskLevel: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
  controlsAssessed: ControlAssessment[];
}

export interface ControlAssessment {
  controlId: string;
  name: string;
  category: 'govern' | 'map' | 'measure' | 'manage';
  status: 'implemented' | 'partial' | 'not-implemented' | 'not-applicable';
  evidence: string[];
  gaps: string[];
}

export async function generateAISecurityReport(
  recorder: TraceRecorder,
  options: {
    from?: number;
    to?: number;
    framework?: 'NIST AI RMF' | 'ISO 42001';
  } = {}
): Promise<AISecurityReport> {
  const now = Date.now();
  const from = options.from ?? now - 30 * 24 * 60 * 60 * 1000; // Default: 30 days
  const to = options.to ?? now;
  const framework = options.framework ?? 'NIST AI RMF';

  const traces = recorder.query({ from, to });

  // Calculate risk metrics
  const blockedActions = traces.filter(t => t.outcome === 'blocked');
  const flaggedActions = traces.filter(t => t.outcome === 'flagged');
  const policyViolations = traces.filter(t => t.outcome === 'violated');

  const totalRisky = blockedActions.length + flaggedActions.length + policyViolations.length;
  const complianceRate = traces.length > 0
    ? ((traces.length - totalRisky) / traces.length) * 100
    : 100;

  // Assess controls based on trace patterns
  const controls = assessAIControls(traces, framework);

  // Determine overall risk level
  const riskLevel = determineRiskLevel(complianceRate, controls);

  const report: AISecurityReport = {
    title: `AI Agent Security Assessment Report`,
    generatedAt: new Date().toISOString(),
    period: { from, to },
    framework,
    riskLevel,
    summary: {
      totalTraces: traces.length,
      totalViolations: totalRisky,
      blockedActions: blockedActions.length,
      flaggedActions: flaggedActions.length,
      complianceRate,
      averageLatencyMs: 0,
      agentsCovered: new Set(traces.map(t => t.agentId)).size,
    },
    violations: aggregateViolations(traces),
    agents: aggregateAgentMetrics(traces),
    recommendations: generateAISecurityRecommendations(riskLevel, controls),
    controlsAssessed: controls,
    rawData: { framework, standard: framework === 'NIST AI RMF' ? 'NIST AI RMF 1.0' : 'ISO/IEC 42001:2023' },
  };

  return report;
}

function assessAIControls(traces: TraceRecord[], framework: string): ControlAssessment[] {
  const controls: ControlAssessment[] = [];

  // GOVERN controls (for NIST)
  controls.push({
    controlId: framework === 'NIST AI RMF' ? 'GV-1' : 'A.5.1',
    name: 'Organizational accountability for AI systems',
    category: 'govern',
    status: traces.length > 0 ? 'implemented' : 'not-implemented',
    evidence: traces.length > 0 ? [`${traces.length} traces recorded in reporting period`] : [],
    gaps: [],
  });

  // MAP controls
  controls.push({
    controlId: framework === 'NIST AI RMF' ? 'MAP-1' : 'A.7.1',
    name: 'Stakeholder consultation for AI use cases',
    category: 'map',
    status: 'partial',
    evidence: [],
    gaps: ['No documented stakeholder consultation records found'],
  });

  // MEASURE controls
  controls.push({
    controlId: framework === 'NIST AI RMF' ? 'MS-2' : 'A.8.2',
    name: 'AI system testing and monitoring',
    category: 'measure',
    status: traces.length > 0 ? 'implemented' : 'partial',
    evidence: traces.length > 0 ? [`TraceShield monitoring active with ${traces.length} traces`] : [],
    gaps: [],
  });

  // MANAGE controls
  controls.push({
    controlId: framework === 'NIST AI RMF' ? 'MG-3' : 'A.9.3',
    name: 'Incident response for AI failures',
    category: 'manage',
    status: 'partial',
    evidence: [],
    gaps: ['No AI-specific incident response plan documented'],
  });

  return controls;
}

function determineRiskLevel(
  complianceRate: number,
  controls: ControlAssessment[]
): AISecurityReport['riskLevel'] {
  const unimplementedControls = controls.filter(
    c => c.status === 'not-implemented' || c.status === 'partial'
  ).length;

  if (complianceRate < 80 || unimplementedControls > 3) return 'critical';
  if (complianceRate < 90 || unimplementedControls > 2) return 'high';
  if (complianceRate < 95 || unimplementedControls > 1) return 'medium';
  if (complianceRate < 99) return 'low';
  return 'minimal';
}

function aggregateViolations(traces: TraceRecord[]): ViolationSummary[] {
  const violations = traces.filter(t => t.outcome !== 'success');
  const grouped = new Map<string, TraceRecord[]>();

  for (const trace of violations) {
    const key = trace.policyId || 'unknown';
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(trace);
  }

  return Array.from(grouped.entries()).map(([ruleName, items]) => ({
    ruleName,
    count: items.length,
    severity: 'high' as const,
    lastOccurred: new Date(Math.max(...items.map(t => t.timestamp))).toISOString(),
    affectedAgents: [...new Set(items.map(t => t.agentId))],
    examples: items.slice(0, 3).map(t => t.action),
  }));
}

function aggregateAgentMetrics(traces: TraceRecord[]): AgentSummary[] {
  const byAgent = new Map<string, TraceRecord[]>();

  for (const trace of traces) {
    if (!byAgent.has(trace.agentId)) byAgent.set(trace.agentId, []);
    byAgent.get(trace.agentId)!.push(trace);
  }

  return Array.from(byAgent.entries()).map(([agentId, items]) => {
    const violations = items.filter(t => t.outcome !== 'success').length;
    return {
      agentId,
      totalActions: items.length,
      violations,
      complianceRate: ((items.length - violations) / items.length) * 100,
      topCapabilities: [...new Set(items.map(t => t.capability))].slice(0, 5),
    };
  });
}

function generateAISecurityRecommendations(
  riskLevel: AISecurityReport['riskLevel'],
  controls: ControlAssessment[]
): string[] {
  const recs: string[] = [];

  if (riskLevel === 'critical' || riskLevel === 'high') {
    recs.push(`URGENT: AI system risk level is ${riskLevel}. Immediate review required.`);
  }

  const gaps = controls.flatMap(c => c.gaps);
  if (gaps.length > 0) {
    recs.push(`Control gaps identified: ${gaps.join('; ')}`);
  }

  const unimplemented = controls.filter(c => c.status === 'not-implemented');
  if (unimplemented.length > 0) {
    recs.push(`Implement missing controls: ${unimplemented.map(c => c.controlId).join(', ')}`);
  }

  recs.push('Establish AI governance board with cross-functional stakeholders.');
  recs.push('Conduct red team exercises for AI-specific attack vectors.');
  recs.push('Implement continuous AI model monitoring and drift detection.');

  return recs;
}
