import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine, PolicyViolationError } from '../src/policy-engine.js';
import type { PolicySet, EvalContext } from '../src/types.js';

function makeContext(overrides: Partial<EvalContext> = {}): EvalContext {
  return {
    action_type: 'tool_call',
    action_name: 'test_tool',
    input: {},
    trace_id: 'test-trace',
    span_count: 0,
    elapsed_ms: 0,
    ...overrides,
  };
}

describe('PolicyEngine', () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine();
  });

  describe('policy loading', () => {
    it('should load a policy set', () => {
      const policySet: PolicySet = {
        version: '1.0',
        policies: [
          {
            name: 'test-policy',
            rules: [
              {
                id: 'rule-1',
                action: 'tool_call',
                condition: { tool_name: { exact: 'dangerous_tool' } },
                effect: 'deny',
                message: 'Dangerous tool blocked',
              },
            ],
          },
        ],
      };

      engine.loadPolicySet(policySet);
      expect(engine.getPolicies()).toHaveLength(1);
      expect(engine.getPolicies()[0].name).toBe('test-policy');
    });

    it('should add individual policies', () => {
      engine.addPolicy({
        name: 'p1',
        rules: [{ id: 'r1', action: '*', condition: {}, effect: 'audit' }],
      });
      engine.addPolicy({
        name: 'p2',
        rules: [{ id: 'r2', action: '*', condition: {}, effect: 'audit' }],
      });
      expect(engine.getPolicies()).toHaveLength(2);
    });

    it('should remove policies by name', () => {
      engine.addPolicy({ name: 'p1', rules: [] });
      engine.addPolicy({ name: 'p2', rules: [] });
      expect(engine.removePolicy('p1')).toBe(true);
      expect(engine.getPolicies()).toHaveLength(1);
      expect(engine.removePolicy('nonexistent')).toBe(false);
    });

    it('should sort policies by priority', () => {
      engine.addPolicy({ name: 'low', priority: 10, rules: [] });
      engine.addPolicy({ name: 'high', priority: 100, rules: [] });
      engine.addPolicy({ name: 'mid', priority: 50, rules: [] });

      const policies = engine.getPolicies();
      expect(policies[0].name).toBe('high');
      expect(policies[1].name).toBe('mid');
      expect(policies[2].name).toBe('low');
    });

    it('should auto-assign rule IDs if missing', () => {
      engine.addPolicy({
        name: 'auto-id',
        rules: [
          { id: '', action: '*', condition: {}, effect: 'audit' },
          { id: '', action: '*', condition: {}, effect: 'audit' },
        ],
      });
      const rules = engine.getPolicies()[0].rules;
      expect(rules[0].id).toBe('auto-id:rule-0');
      expect(rules[1].id).toBe('auto-id:rule-1');
    });
  });

  describe('pattern matching', () => {
    it('should match exact tool name', () => {
      engine.addPolicy({
        name: 'exact-match',
        rules: [{
          id: 'r1', action: 'tool_call',
          condition: { tool_name: { exact: 'delete_user' } },
          effect: 'deny',
        }],
      });

      const blocked = engine.evaluatePre(makeContext({ action_name: 'delete_user' }));
      expect(blocked.allowed).toBe(false);

      const allowed = engine.evaluatePre(makeContext({ action_name: 'get_user' }));
      expect(allowed.allowed).toBe(true);
    });

    it('should match regex pattern', () => {
      engine.addPolicy({
        name: 'pattern-match',
        rules: [{
          id: 'r1', action: 'tool_call',
          condition: { tool_name: { pattern: '^delete_' } },
          effect: 'deny',
        }],
      });

      expect(engine.evaluatePre(makeContext({ action_name: 'delete_user' })).allowed).toBe(false);
      expect(engine.evaluatePre(makeContext({ action_name: 'delete_file' })).allowed).toBe(false);
      expect(engine.evaluatePre(makeContext({ action_name: 'create_user' })).allowed).toBe(true);
    });

    it('should match oneOf list', () => {
      engine.addPolicy({
        name: 'oneof-match',
        rules: [{
          id: 'r1', action: 'tool_call',
          condition: { tool_name: { oneOf: ['tool_a', 'tool_b'] } },
          effect: 'deny',
        }],
      });

      expect(engine.evaluatePre(makeContext({ action_name: 'tool_a' })).allowed).toBe(false);
      expect(engine.evaluatePre(makeContext({ action_name: 'tool_b' })).allowed).toBe(false);
      expect(engine.evaluatePre(makeContext({ action_name: 'tool_c' })).allowed).toBe(true);
    });

    it('should match noneOf list', () => {
      engine.addPolicy({
        name: 'noneof-match',
        rules: [{
          id: 'r1', action: 'tool_call',
          condition: { tool_name: { noneOf: ['safe_tool'] } },
          effect: 'deny',
        }],
      });

      expect(engine.evaluatePre(makeContext({ action_name: 'safe_tool' })).allowed).toBe(true);
      expect(engine.evaluatePre(makeContext({ action_name: 'other_tool' })).allowed).toBe(false);
    });
  });

  describe('action type matching', () => {
    it('should match specific action types', () => {
      engine.addPolicy({
        name: 'llm-only',
        rules: [{
          id: 'r1', action: 'llm_call',
          condition: {},
          effect: 'deny',
        }],
      });

      expect(engine.evaluatePre(makeContext({ action_type: 'llm_call' })).allowed).toBe(false);
      expect(engine.evaluatePre(makeContext({ action_type: 'tool_call' })).allowed).toBe(true);
    });

    it('should match wildcard action type', () => {
      engine.addPolicy({
        name: 'all-actions',
        rules: [{
          id: 'r1', action: '*',
          condition: { input_contains: ['secret'] },
          effect: 'deny',
        }],
      });

      expect(engine.evaluatePre(makeContext({ action_type: 'tool_call', input: 'has secret data' })).allowed).toBe(false);
      expect(engine.evaluatePre(makeContext({ action_type: 'llm_call', input: 'has secret data' })).allowed).toBe(false);
    });
  });

  describe('input/output content checks', () => {
    it('should check input_contains', () => {
      engine.addPolicy({
        name: 'input-check',
        rules: [{
          id: 'r1', action: '*',
          condition: { input_contains: ['password', 'secret'] },
          effect: 'deny',
        }],
      });

      expect(engine.evaluatePre(makeContext({ input: 'my password is 123' })).allowed).toBe(false);
      expect(engine.evaluatePre(makeContext({ input: 'hello world' })).allowed).toBe(true);
    });

    it('should check input_not_contains', () => {
      engine.addPolicy({
        name: 'input-not-check',
        rules: [{
          id: 'r1', action: '*',
          condition: { input_not_contains: ['approved'] },
          effect: 'deny',
        }],
      });

      // If input contains "approved", the not_contains condition fails, so rule doesn't trigger
      expect(engine.evaluatePre(makeContext({ input: 'this is approved' })).allowed).toBe(true);
      // If input does NOT contain "approved", the not_contains condition passes, rule triggers
      expect(engine.evaluatePre(makeContext({ input: 'random text' })).allowed).toBe(false);
    });

    it('should check output_contains only in post-check', () => {
      engine.addPolicy({
        name: 'output-check',
        rules: [{
          id: 'r1', action: '*',
          condition: { output_contains: ['SSN'] },
          effect: 'deny',
        }],
      });

      // Pre-check should not evaluate output conditions
      expect(engine.evaluatePre(makeContext({ output: 'SSN: 123-45-6789' })).allowed).toBe(true);

      // Post-check should
      expect(engine.evaluatePost(makeContext({ output: 'SSN: 123-45-6789' })).allowed).toBe(false);
      expect(engine.evaluatePost(makeContext({ output: 'all clear' })).allowed).toBe(true);
    });
  });

  describe('numeric constraints', () => {
    it('should check token_count max', () => {
      engine.addPolicy({
        name: 'token-limit',
        rules: [{
          id: 'r1', action: 'llm_call',
          condition: { token_count: { max: 1000 } },
          effect: 'deny',
        }],
      });

      expect(engine.evaluatePre(makeContext({
        action_type: 'llm_call', token_count: 1500,
      })).allowed).toBe(false);

      expect(engine.evaluatePre(makeContext({
        action_type: 'llm_call', token_count: 500,
      })).allowed).toBe(true);
    });

    it('should check call_count max', () => {
      engine.addPolicy({
        name: 'call-limit',
        rules: [{
          id: 'r1', action: '*',
          condition: { call_count: { max: 10 } },
          effect: 'warn',
        }],
      });

      const result = engine.evaluatePre(makeContext({ span_count: 15 }));
      expect(result.evaluations.some((e) => e.result === 'warn')).toBe(true);
    });
  });

  describe('effects', () => {
    it('should return deny result for deny effect', () => {
      engine.addPolicy({
        name: 'deny-policy',
        rules: [{
          id: 'r1', action: '*', condition: {},
          effect: 'deny', message: 'All blocked',
        }],
      });

      const decision = engine.evaluatePre(makeContext());
      expect(decision.allowed).toBe(false);
      expect(decision.blocked_by).toBeDefined();
      expect(decision.blocked_by?.result).toBe('deny');
    });

    it('should return warn result for warn effect', () => {
      engine.addPolicy({
        name: 'warn-policy',
        rules: [{
          id: 'r1', action: '*', condition: {},
          effect: 'warn', message: 'Warning issued',
        }],
      });

      const decision = engine.evaluatePre(makeContext());
      expect(decision.allowed).toBe(true);
      expect(decision.evaluations).toHaveLength(1);
      expect(decision.evaluations[0].result).toBe('warn');
    });

    it('should return audit result for audit effect', () => {
      engine.addPolicy({
        name: 'audit-policy',
        rules: [{
          id: 'r1', action: '*', condition: {},
          effect: 'audit',
        }],
      });

      const decision = engine.evaluatePre(makeContext());
      expect(decision.allowed).toBe(true);
      expect(decision.evaluations[0].result).toBe('allow');
      expect(decision.evaluations[0].effect).toBe('audit');
    });
  });

  describe('disabled policies', () => {
    it('should skip disabled policies', () => {
      engine.addPolicy({
        name: 'disabled-policy',
        enabled: false,
        rules: [{
          id: 'r1', action: '*', condition: {},
          effect: 'deny',
        }],
      });

      expect(engine.evaluatePre(makeContext()).allowed).toBe(true);
    });
  });
});
