import { describe, it, expect } from 'vitest';
import {
  formatReportAsMarkdown,
  generateComplianceReport,
  generateGDPRReport,
  generateHIPAAReport,
  generateSOC2Report,
} from '../src/compliance-reports.js';
import type { PolicyEvaluation, Span, Trace } from '../src/types.js';

function makeSpan(overrides: Partial<Span> & { id: string; sequence: number }): Span {
  return {
    trace_id: 'trace-1',
    action_type: 'tool_call',
    name: 'test_action',
    input: {},
    started_at: new Date(Date.now() - 1000).toISOString(),
    ended_at: new Date().toISOString(),
    duration_ms: 100,
    status: 'completed',
    policy_evaluations: [],
    hash: 'abc',
    previous_hash: '000',
    ...overrides,
  };
}

function makeTrace(
  spans: Span[],
  overrides: Partial<Trace> & { id: string; agent_id: string },
): Trace {
  return {
    started_at: new Date(Date.now() - 5000).toISOString(),
    ended_at: new Date().toISOString(),
    status: 'completed',
    integrity_hash: 'test-hash',
    ...overrides,
    spans,
  };
}

function denial(ruleId: string, policyName = 'policy'): PolicyEvaluation {
  return {
    rule_id: ruleId,
    policy_name: policyName,
    result: 'deny',
    evaluated_at: new Date().toISOString(),
  } as PolicyEvaluation;
}

function cleanTraces(): Trace[] {
  return [
    makeTrace([makeSpan({ id: 's1', sequence: 0, name: 'search' })], {
      id: 't1',
      agent_id: 'agent-a',
    }),
    makeTrace([makeSpan({ id: 's2', sequence: 0, name: 'summarize' })], {
      id: 't2',
      agent_id: 'agent-b',
    }),
  ];
}

function violatingTraces(): Trace[] {
  return [
    makeTrace(
      [
        makeSpan({
          id: 's1',
          sequence: 0,
          name: 'delete_user',
          policy_evaluations: [denial('no_delete')],
        }),
        makeSpan({ id: 's2', sequence: 1, name: 'search' }),
      ],
      { id: 't1', agent_id: 'agent-a' },
    ),
  ];
}

describe('SOC 2 report', () => {
  it('reports a clean run with 100% compliance', () => {
    const report = generateSOC2Report(cleanTraces());

    expect(report.title).toContain('SOC 2');
    expect(report.summary.totalTraces).toBe(2);
    expect(report.summary.totalViolations).toBe(0);
    expect(report.summary.complianceRate).toBe(100);
    expect(report.summary.agentsCovered).toBe(2);
    expect(report.violations).toEqual([]);
    expect(report.agents.map((a) => a.agentId).sort()).toEqual(['agent-a', 'agent-b']);
  });

  it('aggregates violations per rule and per agent', () => {
    const report = generateSOC2Report(violatingTraces());

    expect(report.summary.totalViolations).toBe(1);
    expect(report.summary.blockedActions).toBe(1);
    expect(report.violations[0].ruleName).toBe('no_delete');
    expect(report.violations[0].count).toBe(1);
    expect(report.violations[0].affectedAgents).toEqual(['agent-a']);

    const agent = report.agents.find((a) => a.agentId === 'agent-a')!;
    expect(agent.totalActions).toBe(2);
    expect(agent.violations).toBe(1);
    expect(agent.complianceRate).toBe(50);
  });

  it('computes average latency from spans', () => {
    const report = generateSOC2Report(cleanTraces());
    expect(report.summary.averageLatencyMs).toBe(100);
  });

  it('carries auditor metadata in rawData', () => {
    const report = generateSOC2Report(cleanTraces(), {
      orgName: 'Acme',
      auditorName: 'Deloitte',
    });
    expect(report.rawData).toMatchObject({
      orgName: 'Acme',
      auditorName: 'Deloitte',
      standard: 'SOC 2 Type II',
    });
  });
});

describe('GDPR report', () => {
  it('includes the violation and agent breakdown', () => {
    // Regression: these were hardcoded to [] so an auditor saw a violation
    // total with no breakdown.
    const report = generateGDPRReport(violatingTraces());

    expect(report.title).toContain('GDPR');
    expect(report.summary.totalViolations).toBe(1);
    expect(report.violations).toHaveLength(1);
    expect(report.violations[0].ruleName).toBe('no_delete');
    expect(report.agents).toHaveLength(1);
  });

  it('reports latency instead of a hardcoded zero', () => {
    const report = generateGDPRReport(cleanTraces());
    expect(report.summary.averageLatencyMs).toBe(100);
  });

  it('names the data controller', () => {
    const report = generateGDPRReport(cleanTraces(), { dataController: 'Acme GmbH' });
    expect(report.rawData).toMatchObject({ dataController: 'Acme GmbH' });
  });

  it('recommends a DPIA always', () => {
    const report = generateGDPRReport(cleanTraces());
    expect(report.recommendations.some((r) => r.includes('DPIA'))).toBe(true);
  });
});

describe('HIPAA report', () => {
  function phiTraces(): Trace[] {
    return [
      makeTrace(
        [
          makeSpan({ id: 's1', sequence: 0, name: 'read_patient_record' }),
          makeSpan({ id: 's2', sequence: 1, name: 'search' }),
          makeSpan({
            id: 's3',
            sequence: 2,
            name: 'update_ehr',
            policy_evaluations: [denial('phi_write_block', 'phi-protection')],
          }),
        ],
        { id: 't1', agent_id: 'agent-clinical' },
      ),
    ];
  }

  it('detects PHI access by span name', () => {
    const report = generateHIPAAReport(phiTraces());
    expect(report.rawData?.phiAccessEvents).toBe(2); // read_patient_record + update_ehr
    expect(report.rawData?.phiAgents).toEqual(['agent-clinical']);
  });

  it('counts PHI policy violations', () => {
    const report = generateHIPAAReport(phiTraces());
    expect(report.rawData?.phiViolations).toBe(1);
    expect(report.rawData?.phiRules).toEqual(['phi_write_block']);
  });

  it('detects PHI via data-classification metadata', () => {
    const traces = [
      makeTrace(
        [makeSpan({ id: 's1', sequence: 0, name: 'fetch', metadata: { data_classification: 'PHI' } })],
        { id: 't1', agent_id: 'agent-x' },
      ),
    ];
    const report = generateHIPAAReport(traces);
    expect(report.rawData?.phiAccessEvents).toBe(1);
    expect(report.rawData?.phiAgents).toEqual(['agent-x']);
  });

  it('detects PHI via booleans metadata flag', () => {
    const traces = [
      makeTrace([makeSpan({ id: 's1', sequence: 0, name: 'fetch', metadata: { phi: true } })], {
        id: 't1',
        agent_id: 'agent-y',
      }),
    ];
    expect(generateHIPAAReport(traces).rawData?.phiAccessEvents).toBe(1);
  });

  it('reports zero PHI when no clinical signals are present', () => {
    const report = generateHIPAAReport(cleanTraces());
    expect(report.rawData?.phiAccessEvents).toBe(0);
    expect(report.rawData?.phiAgents).toEqual([]);
    expect(report.recommendations.some((r) => r.includes('No PHI access detected'))).toBe(true);
  });

  it('references the HIPAA Security Rule provisions', () => {
    const report = generateHIPAAReport(cleanTraces(), { coveredEntity: 'Acme Health' });
    expect(report.rawData).toMatchObject({
      coveredEntity: 'Acme Health',
      standard: 'HIPAA Security Rule §164.312',
    });
    expect(report.rawData?.provisions).toMatchObject({
      'access-control': '§164.312(a)(1)',
      'audit-controls': '§164.312(b)',
    });
  });

  it('flags PHI violations as critical in recommendations', () => {
    const report = generateHIPAAReport(phiTraces());
    expect(
      report.recommendations.some((r) => r.startsWith('CRITICAL') && r.includes('§164.312(b)')),
    ).toBe(true);
  });

  it('recommends 6-year retention when PHI was touched', () => {
    const report = generateHIPAAReport(phiTraces());
    expect(report.recommendations.some((r) => r.includes('6 years'))).toBe(true);
  });

  it('always recommends encryption and an annual risk assessment', () => {
    const report = generateHIPAAReport(cleanTraces());
    expect(report.recommendations.some((r) => r.includes('§164.312(e)(1)'))).toBe(true);
    expect(report.recommendations.some((r) => r.includes('risk assessment'))).toBe(true);
  });
});

describe('generateComplianceReport dispatcher', () => {
  it('routes to each standard', () => {
    const traces = cleanTraces();
    expect(generateComplianceReport(traces, 'soc2').title).toContain('SOC 2');
    expect(generateComplianceReport(traces, 'gdpr').title).toContain('GDPR');
    expect(generateComplianceReport(traces, 'hipaa').title).toContain('HIPAA');
  });

  it('passes orgName through to the right field per standard', () => {
    const gdpr = generateComplianceReport(cleanTraces(), 'gdpr', { orgName: 'Acme' });
    expect(gdpr.rawData?.dataController).toBe('Acme');

    const hipaa = generateComplianceReport(cleanTraces(), 'hipaa', { orgName: 'Acme' });
    expect(hipaa.rawData?.coveredEntity).toBe('Acme');
  });
});

describe('formatReportAsMarkdown', () => {
  it('renders summary, violations and agents', () => {
    const md = formatReportAsMarkdown(generateSOC2Report(violatingTraces()));
    expect(md).toContain('# SOC 2 Compliance Audit Report');
    expect(md).toContain('| Compliance Rate |');
    expect(md).toContain('## Violations');
    expect(md).toContain('no_delete');
    expect(md).toContain('## Agent Breakdown');
    expect(md).toContain('agent-a');
  });

  it('renders the PHI section for HIPAA reports', () => {
    const traces = [
      makeTrace([makeSpan({ id: 's1', sequence: 0, name: 'read_patient_record' })], {
        id: 't1',
        agent_id: 'agent-clinical',
      }),
    ];
    const md = formatReportAsMarkdown(generateHIPAAReport(traces));
    expect(md).toContain('## PHI Access');
    expect(md).toContain('PHI Access Events | 1');
    expect(md).toContain('agent-clinical');
  });

  it('does not render the PHI section for non-HIPAA reports', () => {
    const md = formatReportAsMarkdown(generateSOC2Report(cleanTraces()));
    expect(md).not.toContain('## PHI Access');
  });
});