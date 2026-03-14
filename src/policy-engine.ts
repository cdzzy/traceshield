import { readFileSync } from 'node:fs';
import type {
  PolicySet,
  Policy,
  PolicyRule,
  PolicyEffect,
  PolicyEvaluation,
  PolicyDecision,
  EvalContext,
  RuleCondition,
  PatternMatch,
  NumericConstraint,
  ActionType,
} from './types.js';

export class PolicyEngine {
  private policies: Policy[] = [];

  constructor(policySet?: PolicySet) {
    if (policySet) {
      this.loadPolicySet(policySet);
    }
  }

  static fromFile(filePath: string): PolicyEngine {
    const content = readFileSync(filePath, 'utf-8');
    const ext = filePath.split('.').pop()?.toLowerCase();
    let parsed: PolicySet;

    if (ext === 'yaml' || ext === 'yml') {
      // Dynamic import would be async; use require-style for sync loading
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const yamlModule = (() => { try { return require('yaml'); } catch { throw new Error('Install "yaml" package to load YAML policy files: npm install yaml'); } })();
      parsed = yamlModule.parse(content) as PolicySet;
    } else {
      parsed = JSON.parse(content) as PolicySet;
    }

    return new PolicyEngine(parsed);
  }

  static fromYaml(yamlContent: string): PolicyEngine {
    const yamlModule = (() => { try { return require('yaml'); } catch { throw new Error('Install "yaml" package to parse YAML: npm install yaml'); } })();
    const parsed = yamlModule.parse(yamlContent) as PolicySet;
    return new PolicyEngine(parsed);
  }

  loadPolicySet(policySet: PolicySet): void {
    this.policies = [];
    for (const policy of policySet.policies) {
      this.addPolicy(policy);
    }
  }

  addPolicy(policy: Policy): void {
    // Assign rule IDs if missing
    const enriched: Policy = {
      ...policy,
      enabled: policy.enabled ?? true,
      priority: policy.priority ?? 0,
      rules: policy.rules.map((rule, idx) => ({
        ...rule,
        id: rule.id || `${policy.name}:rule-${idx}`,
      })),
    };
    this.policies.push(enriched);
    // Sort by priority descending (higher priority evaluated first)
    this.policies.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  }

  removePolicy(name: string): boolean {
    const idx = this.policies.findIndex((p) => p.name === name);
    if (idx >= 0) {
      this.policies.splice(idx, 1);
      return true;
    }
    return false;
  }

  getPolicies(): ReadonlyArray<Policy> {
    return this.policies;
  }

  /**
   * Evaluate an action BEFORE execution (pre-check).
   * Only evaluates conditions that can be checked before execution (input-side).
   */
  evaluatePre(context: EvalContext): PolicyDecision {
    return this.evaluate(context, 'pre');
  }

  /**
   * Evaluate an action AFTER execution (post-check).
   * Evaluates all conditions including output-side checks.
   */
  evaluatePost(context: EvalContext): PolicyDecision {
    return this.evaluate(context, 'post');
  }

  private evaluate(context: EvalContext, phase: 'pre' | 'post'): PolicyDecision {
    const evaluations: PolicyEvaluation[] = [];
    let blockedBy: PolicyEvaluation | undefined;

    for (const policy of this.policies) {
      if (!policy.enabled) continue;

      for (const rule of policy.rules) {
        if (!this.actionMatches(rule.action, context.action_type)) continue;

        const matches = this.evaluateCondition(rule.condition, context, phase);
        if (!matches) continue;

        // Condition matched — this means the rule triggers
        const evaluation: PolicyEvaluation = {
          policy_name: policy.name,
          rule_id: rule.id,
          effect: rule.effect,
          result: rule.effect === 'deny' ? 'deny' : rule.effect === 'warn' ? 'warn' : 'allow',
          message: rule.message ?? `Rule ${rule.id} in policy "${policy.name}" triggered`,
          evaluated_at: new Date().toISOString(),
        };

        evaluations.push(evaluation);

        if (rule.effect === 'deny' && !blockedBy) {
          blockedBy = evaluation;
        }
      }
    }

    return {
      allowed: !blockedBy,
      evaluations,
      blocked_by: blockedBy,
    };
  }

  private actionMatches(ruleAction: ActionType, contextAction: ActionType): boolean {
    return ruleAction === '*' || ruleAction === contextAction;
  }

  private evaluateCondition(
    condition: RuleCondition,
    context: EvalContext,
    phase: 'pre' | 'post',
  ): boolean {
    // Track whether any pre-phase condition was evaluated
    let hasPreConditions = false;

    // All specified conditions must match (AND logic)
    if (condition.tool_name !== undefined) {
      hasPreConditions = true;
      if (!this.matchPattern(condition.tool_name, context.action_name)) return false;
    }

    if (condition.model !== undefined) {
      hasPreConditions = true;
      const model = (context.metadata?.['model'] as string) ?? '';
      if (!this.matchPattern(condition.model, model)) return false;
    }

    if (condition.input_contains !== undefined) {
      hasPreConditions = true;
      const inputStr = typeof context.input === 'string' ? context.input : JSON.stringify(context.input);
      if (!condition.input_contains.some((term) => inputStr.includes(term))) return false;
    }

    if (condition.input_not_contains !== undefined) {
      hasPreConditions = true;
      const inputStr = typeof context.input === 'string' ? context.input : JSON.stringify(context.input);
      if (condition.input_not_contains.some((term) => inputStr.includes(term))) return false;
    }

    if (condition.token_count !== undefined && context.token_count !== undefined) {
      hasPreConditions = true;
      if (!this.matchNumericExceeds(condition.token_count, context.token_count)) return false;
    }

    if (condition.call_count !== undefined) {
      hasPreConditions = true;
      if (!this.matchNumericExceeds(condition.call_count, context.span_count)) return false;
    }

    // Output-side checks only in post phase
    const hasPostConditions =
      condition.output_contains !== undefined ||
      condition.output_not_contains !== undefined ||
      condition.latency_ms !== undefined;

    if (phase === 'post') {
      if (condition.output_contains !== undefined && context.output !== undefined) {
        const outputStr = typeof context.output === 'string' ? context.output : JSON.stringify(context.output);
        if (!condition.output_contains.some((term) => outputStr.includes(term))) return false;
      }

      if (condition.output_not_contains !== undefined && context.output !== undefined) {
        const outputStr = typeof context.output === 'string' ? context.output : JSON.stringify(context.output);
        if (condition.output_not_contains.some((term) => outputStr.includes(term))) return false;
      }

      if (condition.latency_ms !== undefined) {
        if (!this.matchNumericExceeds(condition.latency_ms, context.elapsed_ms)) return false;
      }
    } else if (hasPostConditions && !hasPreConditions) {
      // In pre-phase, if the rule ONLY has post-phase conditions,
      // don't trigger it — we can't evaluate it yet
      return false;
    }

    return true;
  }

  private matchPattern(pattern: PatternMatch, value: string): boolean {
    if (pattern.exact !== undefined) {
      return value === pattern.exact;
    }
    if (pattern.pattern !== undefined) {
      return new RegExp(pattern.pattern).test(value);
    }
    if (pattern.oneOf !== undefined) {
      return pattern.oneOf.includes(value);
    }
    if (pattern.noneOf !== undefined) {
      return !pattern.noneOf.includes(value);
    }
    return true;
  }

  /**
   * Check if a value EXCEEDS the given numeric constraint.
   * Returns true if the value is outside the allowed bounds (violation detected).
   */
  private matchNumericExceeds(constraint: NumericConstraint, value: number): boolean {
    if (constraint.max !== undefined && value > constraint.max) return true;
    if (constraint.min !== undefined && value < constraint.min) return true;
    return false;
  }
}

export class PolicyViolationError extends Error {
  constructor(
    public readonly evaluation: PolicyEvaluation,
    public readonly context: EvalContext,
  ) {
    super(`Policy violation: ${evaluation.message ?? evaluation.rule_id}`);
    this.name = 'PolicyViolationError';
  }
}
