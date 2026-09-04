/**
 * Policy-as-code toolkit for GitOps workflows (Roadmap).
 *
 * Validates policy sets structurally (so a CI pipeline can fail a PR that
 * breaks policy code) and diffs two policy sets (so a PR comment can show
 * exactly which rules changed).
 *
 * Usage::
 *   import { validatePolicySet, diffPolicySets, renderDiffMarkdown } from 'traceshield';
 *   import { readFileSync } from 'node:fs';
 *
 *   // CI gate
 *   const candidate = JSON.parse(readFileSync('policies/new.json', 'utf-8'));
 *   const report = validatePolicySet(candidate);
 *   if (!report.valid) process.exit(1);
 *
 *   // PR review
 *   const before = JSON.parse(readFileSync('policies/main.json', 'utf-8'));
 *   console.log(renderDiffMarkdown(diffPolicySets(before, candidate)));
 */

import type { Policy, PolicyRule, PolicySet } from './types.js';

const KNOWN_ACTION_TYPES = new Set([
  'tool_call', 'llm_call', 'decision', 'message', 'resource', 'retrieval', 'output', '*',
]);
const KNOWN_EFFECTS = new Set(['deny', 'warn', 'audit']);

// ── Validation ───────────────────────────────────────────────────────────

export interface PolicyIssue {
  severity: 'error' | 'warn';
  code: string;
  message: string;
  policy?: string;
  rule?: string;
}

export interface PolicyValidationReport {
  valid: boolean;
  errorCount: number;
  warningCount: number;
  issues: PolicyIssue[];
  stats: { policies: number; rules: number };
}

/** Validate a policy set for GitOps CI gates. */
export function validatePolicySet(policySet: PolicySet): PolicyValidationReport {
  const issues: PolicyIssue[] = [];
  const policies = policySet?.policies ?? [];

  const seenPolicyNames = new Set<string>();
  const seenRuleIds = new Set<string>();
  let ruleCount = 0;

  for (const policy of policies) {
    if (!policy.name || typeof policy.name !== 'string') {
      issues.push({ severity: 'error', code: 'policy-name-missing', message: 'Policy is missing a name' });
      continue;
    }
    if (seenPolicyNames.has(policy.name)) {
      issues.push({
        severity: 'error', code: 'duplicate-policy',
        message: `Duplicate policy name "${policy.name}"`, policy: policy.name,
      });
    }
    seenPolicyNames.add(policy.name);

    if (!Array.isArray(policy.rules)) {
      issues.push({
        severity: 'error', code: 'rules-not-array',
        message: `Policy "${policy.name}" has no rules array`, policy: policy.name,
      });
      continue;
    }

    for (const rule of policy.rules) {
      ruleCount += 1;
      const where = { policy: policy.name, rule: rule.id };

      if (!rule.id || typeof rule.id !== 'string') {
        issues.push({
          severity: 'error', code: 'rule-id-missing',
          message: `Rule in "${policy.name}" is missing an id`, policy: policy.name,
        });
      } else {
        if (seenRuleIds.has(rule.id)) {
          issues.push({
            severity: 'error', code: 'duplicate-rule-id',
            message: `Duplicate rule id "${rule.id}"`, ...where,
          });
        }
        seenRuleIds.add(rule.id);
      }

      if (!KNOWN_ACTION_TYPES.has(rule.action)) {
        issues.push({
          severity: 'error', code: 'unknown-action-type',
          message: `Rule "${rule.id}" has unknown action "${rule.action}"`, ...where,
        });
      }

      if (!KNOWN_EFFECTS.has(rule.effect)) {
        issues.push({
          severity: 'error', code: 'unknown-effect',
          message: `Rule "${rule.id}" has unknown effect "${rule.effect}"`, ...where,
        });
      }

      const condition = rule.condition ?? {};
      const hasConditions = Object.keys(condition).length > 0;
      if (!hasConditions) {
        issues.push({
          severity: 'warn', code: 'unconditional-rule',
          message: `Rule "${rule.id}" has an empty condition — it matches EVERY action`, ...where,
        });
      }

      if (rule.effect === 'deny' && !rule.message) {
        issues.push({
          severity: 'warn', code: 'deny-without-message',
          message: `Deny rule "${rule.id}" has no message — callers see a generic error`, ...where,
        });
      }
    }
  }

  const errorCount = issues.filter((i) => i.severity === 'error').length;
  const warningCount = issues.filter((i) => i.severity === 'warn').length;

  return {
    valid: errorCount === 0,
    errorCount,
    warningCount,
    issues,
    stats: { policies: policies.length, rules: ruleCount },
  };
}

// ── Diff ─────────────────────────────────────────────────────────────────

export interface PolicyDiff {
  addedRules: Array<{ policy: string; rule: PolicyRule }>;
  removedRules: Array<{ policy: string; rule: PolicyRule }>;
  changedRules: Array<{ policy: string; ruleId: string; before: PolicyRule; after: PolicyRule }>;
  addedPolicies: string[];
  removedPolicies: string[];
}

function ruleKey(policy: string, rule: PolicyRule): string {
  return `${policy}/${rule.id}`;
}

function rulesByKeys(policySet: PolicySet): Map<string, { policy: string; rule: PolicyRule }> {
  const map = new Map<string, { policy: string; rule: PolicyRule }>();
  for (const policy of policySet?.policies ?? []) {
    for (const rule of policy.rules ?? []) {
      map.set(ruleKey(policy.name, rule), { policy: policy.name, rule });
    }
  }
  return map;
}

/** Diff two policy sets for PR-style review. */
export function diffPolicySets(before: PolicySet, after: PolicySet): PolicyDiff {
  const beforeMap = rulesByKeys(before);
  const afterMap = rulesByKeys(after);

  const beforePolicies = new Set((before?.policies ?? []).map((p) => p.name));
  const afterPolicies = new Set((after?.policies ?? []).map((p) => p.name));

  const addedRules: PolicyDiff['addedRules'] = [];
  const removedRules: PolicyDiff['removedRules'] = [];
  const changedRules: PolicyDiff['changedRules'] = [];

  for (const [key, entry] of afterMap) {
    const old = beforeMap.get(key);
    if (!old) {
      addedRules.push(entry);
    } else if (JSON.stringify(old.rule) !== JSON.stringify(entry.rule)) {
      changedRules.push({
        policy: entry.policy,
        ruleId: entry.rule.id,
        before: old.rule,
        after: entry.rule,
      });
    }
  }
  for (const [key, entry] of beforeMap) {
    if (!afterMap.has(key)) removedRules.push(entry);
  }

  return {
    addedRules,
    removedRules,
    changedRules,
    addedPolicies: [...afterPolicies].filter((p) => !beforePolicies.has(p)),
    removedPolicies: [...beforePolicies].filter((p) => !afterPolicies.has(p)),
  };
}

/** Render a policy diff as Markdown for PR comments. */
export function renderDiffMarkdown(diff: PolicyDiff): string {
  const lines: string[] = ['# Policy changes', ''];

  if (diff.addedPolicies.length) lines.push(`**New policies:** ${diff.addedPolicies.join(', ')}`);
  if (diff.removedPolicies.length) lines.push(`**Removed policies:** ${diff.removedPolicies.join(', ')}`);
  if (lines.length > 2) lines.push('');

  if (diff.addedRules.length) {
    lines.push('## Added rules');
    for (const { policy, rule } of diff.addedRules) {
      lines.push(`- \`${policy}/${rule.id}\` — ${rule.effect} on \`${rule.action}\``);
    }
    lines.push('');
  }

  if (diff.removedRules.length) {
    lines.push('## Removed rules');
    for (const { policy, rule } of diff.removedRules) {
      lines.push(`- \`${policy}/${rule.id}\` — ${rule.effect} on \`${rule.action}\``);
    }
    lines.push('');
  }

  if (diff.changedRules.length) {
    lines.push('## Changed rules');
    for (const change of diff.changedRules) {
      lines.push(`- \`${change.policy}/${change.ruleId}\``);
      lines.push('  ```json');
      lines.push(`  before: ${JSON.stringify(change.before)}`);
      lines.push(`  after:  ${JSON.stringify(change.after)}`);
      lines.push('  ```');
    }
    lines.push('');
  }

  if (lines.length === 2) lines.push('_No policy changes._');
  return lines.join('\n');
}
