/**
 * Tests for the AIVSS severity scoring engine (v0.7.0).
 *
 * Expected values are derived from the CVSS v3.1 base-score formula that
 * AIVSS mirrors, and double-checked by hand. The calibration tables lock
 * the invariant that a rule's numeric band matches its built-in severity.
 */

import { describe, it, expect } from 'vitest';
import {
  makeVector,
  toVectorString,
  parseVectorString,
  severityFromScore,
  scoreVector,
  scoreFinding,
  RULE_VECTORS,
  FALLBACK_VECTORS,
} from '../src/aivss.js';

// ── scoreVector: CVSS v3.1 math ───────────────────────────────────────────

describe('scoreVector', () => {
  it('scores the classic all-high network vector at 9.8', () => {
    const score = scoreVector(makeVector('N', 'L', 'N', 'N', 'U', 'H', 'H', 'H'));
    expect(score.baseScore).toBe(9.8);
    expect(score.severity).toBe('critical');
    expect(score.impactSubScore).toBeCloseTo(5.873119, 5);
    expect(score.exploitabilitySubScore).toBeCloseTo(3.887043, 5);
  });

  it('caps the score at 10.0 when scope changes with all-high impact', () => {
    const score = scoreVector(makeVector('N', 'L', 'N', 'N', 'C', 'H', 'H', 'H'));
    expect(score.baseScore).toBe(10);
    expect(score.severity).toBe('critical');
  });

  it('scores the classic local all-high vector at 7.8', () => {
    const score = scoreVector(makeVector('L', 'L', 'L', 'N', 'U', 'H', 'H', 'H'));
    expect(score.baseScore).toBe(7.8);
    expect(score.severity).toBe('high');
  });

  it('scores a confidentiality-only network vector at 7.5', () => {
    const score = scoreVector(makeVector('N', 'L', 'N', 'N', 'U', 'H', 'N', 'N'));
    expect(score.baseScore).toBe(7.5);
    expect(score.severity).toBe('high');
  });

  it('returns 0 / info when every impact metric is none', () => {
    const score = scoreVector(makeVector('N', 'L', 'N', 'N', 'U', 'N', 'N', 'N'));
    expect(score.baseScore).toBe(0);
    expect(score.severity).toBe('info');
    expect(score.impactSubScore).toBe(0);
  });

  it('switches the PR weight table and impact formula when scope changes', () => {
    // Same metrics except scope: S:U uses PR:L=0.62 and 6.42*ISS,
    // S:C uses PR:L=0.68 and the 7.52/3.25 changed-scope formula.
    const unchanged = scoreVector(makeVector('N', 'L', 'L', 'N', 'U', 'H', 'H', 'H'));
    const changed = scoreVector(makeVector('N', 'L', 'L', 'N', 'C', 'H', 'H', 'H'));
    expect(unchanged.baseScore).toBe(8.8);
    expect(unchanged.severity).toBe('high');
    expect(changed.baseScore).toBe(9.2);
    expect(changed.severity).toBe('critical');
  });

  it('produces a one-decimal base score within 0–10 for every canned profile', () => {
    const profiles = [...Object.values(RULE_VECTORS), ...Object.values(FALLBACK_VECTORS)];
    expect(profiles.length).toBeGreaterThanOrEqual(14);
    for (const { vector } of profiles) {
      const { baseScore } = scoreVector(vector);
      expect(baseScore).toBeGreaterThanOrEqual(0);
      expect(baseScore).toBeLessThanOrEqual(10);
      expect(Math.abs(baseScore * 10 - Math.round(baseScore * 10))).toBeLessThan(1e-6);
    }
  });
});

// ── severityFromScore: qualitative bands ──────────────────────────────────

describe('severityFromScore', () => {
  it('maps band boundaries (lower bound inclusive)', () => {
    expect(severityFromScore(0)).toBe('info');
    expect(severityFromScore(0.1)).toBe('low');
    expect(severityFromScore(3.9)).toBe('low');
    expect(severityFromScore(4.0)).toBe('medium');
    expect(severityFromScore(6.9)).toBe('medium');
    expect(severityFromScore(7.0)).toBe('high');
    expect(severityFromScore(8.9)).toBe('high');
    expect(severityFromScore(9.0)).toBe('critical');
    expect(severityFromScore(10)).toBe('critical');
  });
});

// ── Vector string serialization ──────────────────────────────────────────

describe('vector strings', () => {
  it('serializes to the canonical AIVSS form', () => {
    const vector = makeVector('N', 'L', 'N', 'N', 'C', 'L', 'H', 'N');
    expect(toVectorString(vector)).toBe('AIVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N');
  });

  it('round-trips every canned vector through toVectorString/parseVectorString', () => {
    const profiles = [...Object.values(RULE_VECTORS), ...Object.values(FALLBACK_VECTORS)];
    for (const { vector } of profiles) {
      const text = toVectorString(vector);
      expect(parseVectorString(text)).toEqual(vector);
      expect(toVectorString(parseVectorString(text))).toBe(text);
    }
  });

  it('parses case-insensitively', () => {
    const parsed = parseVectorString('aivss:1.0/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:n/a:n');
    expect(parsed).toEqual(makeVector('N', 'L', 'N', 'N', 'U', 'H', 'N', 'N'));
  });

  it('rejects strings that are not AIVSS vectors', () => {
    expect(() => parseVectorString('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(/not an AIVSS vector/);
  });

  it('rejects unknown metrics', () => {
    expect(() => parseVectorString('AIVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U')).toThrow(/unknown AIVSS metric/);
  });

  it('rejects duplicated metrics', () => {
    expect(() => parseVectorString('AIVSS:1.0/AV:N/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(/duplicate AIVSS metric/);
  });

  it('rejects missing metrics', () => {
    expect(() => parseVectorString('AIVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H')).toThrow(/missing metrics: I, A/);
  });

  it('rejects invalid metric values', () => {
    expect(() => parseVectorString('AIVSS:1.0/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(/invalid AIVSS AV value/);
  });

  it('rejects malformed segments', () => {
    expect(() => parseVectorString('AIVSS:1.0/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(/malformed AIVSS metric/);
  });
});

// ── Calibration: canned profiles match scanner severities ──────────────────

describe('rule vector calibration', () => {
  const EXPECTED: Record<string, [number, string]> = {
    MCP000: [4.4, 'medium'],
    MCP001: [8.7, 'high'],
    MCP002: [8.7, 'high'],
    'MCP002@medium': [5.4, 'medium'],
    'MCP002@low': [2.6, 'low'],
    MCP003: [9.7, 'critical'],
    MCP004: [7.8, 'high'],
    MCP005: [7.9, 'high'],
    MCP006: [6.1, 'medium'],
    MCP007: [8.0, 'high'],
  };

  it('bands and scores every canned rule profile as calibrated', () => {
    for (const [ruleId, [base, severity]] of Object.entries(EXPECTED)) {
      const profile = RULE_VECTORS[ruleId];
      expect(profile, ruleId).toBeDefined();
      const score = scoreVector(profile!.vector);
      expect(score.baseScore, ruleId).toBe(base);
      expect(score.severity, ruleId).toBe(severity);
    }
  });

  it('orders the dynamic MCP002 variants below the base profile', () => {
    const base = scoreVector(RULE_VECTORS['MCP002']!.vector).baseScore;
    const medium = scoreVector(RULE_VECTORS['MCP002@medium']!.vector).baseScore;
    const low = scoreVector(RULE_VECTORS['MCP002@low']!.vector).baseScore;
    expect(base).toBeGreaterThan(medium);
    expect(medium).toBeGreaterThan(low);
  });

  it('bands every fallback vector consistently with its key', () => {
    const EXPECTED_FALLBACK: Record<string, [number, string]> = {
      low: [3.7, 'low'],
      medium: [6.1, 'medium'],
      high: [7.8, 'high'],
      critical: [9.7, 'critical'],
    };
    for (const [key, [base, severity]] of Object.entries(EXPECTED_FALLBACK)) {
      const score = scoreVector(FALLBACK_VECTORS[key as keyof typeof FALLBACK_VECTORS].vector);
      expect(score.baseScore, key).toBe(base);
      expect(score.severity, key).toBe(severity);
    }
  });
});

// ── scoreFinding: resolution chain ────────────────────────────────────────

describe('scoreFinding', () => {
  it('uses the canned profile for known rules', () => {
    const score = scoreFinding({ ruleId: 'MCP003', severity: 'critical' });
    expect(score.baseScore).toBe(9.7);
    expect(score.vector).toBe(toVectorString(RULE_VECTORS['MCP003']!.vector));
  });

  it('ignores the finding severity when only a plain canned profile exists', () => {
    const score = scoreFinding({ ruleId: 'MCP001', severity: 'low' });
    expect(score.baseScore).toBe(8.7);
    expect(score.vector).toBe(toVectorString(RULE_VECTORS['MCP001']!.vector));
  });

  it('prefers the rule@severity dynamic profile for varying-severity rules', () => {
    expect(scoreFinding({ ruleId: 'MCP002', severity: 'medium' }).baseScore).toBe(5.4);
    expect(scoreFinding({ ruleId: 'MCP002', severity: 'low' }).baseScore).toBe(2.6);
    // No @high key exists: falls through to the plain canned profile.
    expect(scoreFinding({ ruleId: 'MCP002', severity: 'high' }).baseScore).toBe(8.7);
  });

  it('does not append a second suffix to ids that already carry one', () => {
    expect(scoreFinding({ ruleId: 'MCP002@low', severity: 'low' }).baseScore).toBe(2.6);
  });

  it('falls back by severity for unknown rules', () => {
    expect(scoreFinding({ ruleId: 'CUST-9', severity: 'high' }).baseScore)
      .toBe(scoreVector(FALLBACK_VECTORS.high.vector).baseScore);
    expect(scoreFinding({ ruleId: 'CUST-9', severity: 'critical' }).baseScore).toBe(9.7);
  });

  it('treats missing, info, and unrecognized severities as medium', () => {
    const medium = scoreVector(FALLBACK_VECTORS.medium.vector).baseScore;
    expect(scoreFinding({ ruleId: 'CUST-9' }).baseScore).toBe(medium);
    expect(scoreFinding({ ruleId: 'CUST-9', severity: 'info' }).baseScore).toBe(medium);
    expect(scoreFinding({ ruleId: 'CUST-9', severity: 'bogus' }).baseScore).toBe(medium);
  });

  it('matches severities case-insensitively', () => {
    expect(scoreFinding({ ruleId: 'CUST-9', severity: 'HIGH' }).baseScore).toBe(7.8);
    expect(scoreFinding({ ruleId: 'MCP002', severity: 'Medium' }).baseScore).toBe(5.4);
  });
});
