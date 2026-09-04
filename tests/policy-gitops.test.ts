/**
 * Tests for policy-as-code validation and diffing (v0.5.0).
 */

import { describe, it, expect } from 'vitest';
import { validatePolicySet, diffPolicySets, renderDiffMarkdown } from '../src/policy-gitops.js';
import type { Policy, PolicySet } from '../src/types.js';

function rule(id: string, overrides: Record<string, unknown> = {}): PolicyRule {
  return {
    id,
    action: 'tool_call',
    condition: { tool_name: { pattern: '^x' } },
    effect: 'deny',
    message: 'blocked',
    ...overrides,
  } as PolicyRule;
}

function policy(name: string, rules: PolicyRule[]): Policy {
  return { name, rules };
}

const BASE: PolicySet = {
  version: '1.0',
  policies: [policy('tool-restrictions', [rule('block-delete'), rule('warn-http', { effect: 'warn' })])],
};

describe('validatePolicySet', () => {
  it('accepts a clean policy set', () => {
    const report = validatePolicySet(BASE);
    expect(report.valid).toBe(true);
    expect(report.errorCount).toBe(0);
    expect(report.stats.policies).toBe(1);
    expect(report.stats.rules).toBe(2);
  });

  it('flags duplicate policy names', () => {
    const set: PolicySet = { version: '1.0', policies: [policy('p', []), policy('p', [])] };
    const report = validatePolicySet(set);
    expect(report.valid).toBe(false);
    expect(report.issues.some((i) => i.code === 'duplicate-policy')).toBe(true);
  });

  it('flags duplicate rule ids across policies', () => {
    const set: PolicySet = { version: '1.0', policies: [policy('p1', [rule('r1')]), policy('p2', [rule('r1')])] };
    const report = validatePolicySet(set);
    expect(report.issues.some((i) => i.code === 'duplicate-rule-id')).toBe(true);
  });

  it('flags unknown action types and effects as errors', () => {
    const set: PolicySet = {
      version: '1.0',
      policies: [policy('p', [rule('bad-action', { action: 'fly' }), rule('bad-effect', { effect: 'explode' })])],
    };
    const report = validatePolicySet(set);
    expect(report.valid).toBe(false);
    expect(report.issues.some((i) => i.code === 'unknown-action-type')).toBe(true);
    expect(report.issues.some((i) => i.code === 'unknown-effect')).toBe(true);
  });

  it('warns on unconditional rules', () => {
    const set: PolicySet = { version: '1.0', policies: [policy('p', [rule('catch-all', { condition: {} })])] };
    const report = validatePolicySet(set);
    expect(report.valid).toBe(true); // warn, not error
    expect(report.warningCount).toBeGreaterThan(0);
    expect(report.issues.some((i) => i.code === 'unconditional-rule')).toBe(true);
  });

  it('warns on deny rules without a message', () => {
    const set: PolicySet = {
      version: '1.0',
      policies: [policy('p', [rule('silent-deny', { message: undefined })])],
    };
    const report = validatePolicySet(set);
    expect(report.issues.some((i) => i.code === 'deny-without-message')).toBe(true);
  });

  it('flags rules missing ids', () => {
    const set: PolicySet = { version: '1.0', policies: [policy('p', [rule('')])] };
    const report = validatePolicySet(set);
    expect(report.issues.some((i) => i.code === 'rule-id-missing')).toBe(true);
  });
});

describe('diffPolicySets', () => {
  it('detects added rules', () => {
    const after: PolicySet = {
      version: '1.0',
      policies: [policy('tool-restrictions', [rule('block-delete'), rule('warn-http', { effect: 'warn' }), rule('new-rule')])],
    };
    const diff = diffPolicySets(BASE, after);
    expect(diff.addedRules).toHaveLength(1);
    expect(diff.addedRules[0]!.rule.id).toBe('new-rule');
  });

  it('detects removed rules', () => {
    const after: PolicySet = {
      version: '1.0',
      policies: [policy('tool-restrictions', [rule('block-delete')])],
    };
    const diff = diffPolicySets(BASE, after);
    expect(diff.removedRules).toHaveLength(1);
    expect(diff.removedRules[0]!.rule.id).toBe('warn-http');
  });

  it('detects changed rules', () => {
    const after: PolicySet = {
      version: '1.0',
      policies: [policy('tool-restrictions', [rule('block-delete', { effect: 'warn' }), rule('warn-http', { effect: 'warn' })])],
    };
    const diff = diffPolicySets(BASE, after);
    expect(diff.changedRules).toHaveLength(1);
    expect(diff.changedRules[0]!.ruleId).toBe('block-delete');
    expect(diff.changedRules[0]!.after.effect).toBe('warn');
  });

  it('detects added and removed policies', () => {
    const after: PolicySet = {
      version: '1.0',
      policies: [policy('brand-new', []), policy('tool-restrictions', [rule('block-delete'), rule('warn-http', { effect: 'warn' })])],
    };
    const diff = diffPolicySets(BASE, after);
    expect(diff.addedPolicies).toEqual(['brand-new']);
  });

  it('renders markdown for PR comments', () => {
    const after: PolicySet = {
      version: '1.0',
      policies: [policy('tool-restrictions', [rule('block-delete'), rule('new-rule')])],
    };
    const md = renderDiffMarkdown(diffPolicySets(BASE, after));
    expect(md).toContain('# Policy changes');
    expect(md).toContain('## Added rules');
    expect(md).toContain('new-rule');
  });

  it('renders a no-changes placeholder', () => {
    const md = renderDiffMarkdown(diffPolicySets(BASE, BASE));
    expect(md).toContain('No policy changes');
  });
});
