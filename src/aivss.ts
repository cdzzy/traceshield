/**
 * AIVSS — AI Vulnerability Scoring System (v0.7.0).
 *
 * A CVSS v3.1-style base-metric scoring adapted to agentic attack surface:
 * the exploited "system" is an agent whose tool descriptions, config files
 * and tool outputs are attacker-visible prompt surface. AIVSS quantifies
 * each finding on a 0–10 scale so triage can rank numerically instead of
 * relying on four ordinal buckets.
 *
 * Base metrics (agent-adapted definitions):
 *   AV — Attack Vector: how reachable is the poisoned surface?
 *        `N` network (tool descriptions, marketplaces, remote MCP servers),
 *        `A` adjacent (shared repo / shared config),
 *        `L` local (requires config-write access),
 *        `P` physical.
 *   AC — Attack Complexity: `L` no conditions beyond the attacker's control,
 *        `H` depends on rendering, model behavior or positioning.
 *   PR — Privileges Required: `N` a published description is enough,
 *        `L` limited config/marketplace access, `H` admin or config-write.
 *   UI — User Interaction: `N` the agent consumes the text automatically,
 *        `R` a user must act (render, approve, click).
 *   S  — Scope: `C` changed (impact escapes the agent sandbox into other
 *        systems — credentials, filesystems, downstream services),
 *        `U` unchanged (contained in the agent's own outputs).
 *   C/I/A — impact on Confidentiality (data exposure), Integrity (behavior
 *        hijack) and Availability (denial of the tool/agent). `H`/`L`/`N`.
 *
 * Scoring math mirrors CVSS v3.1: an impact sub-score from the C/I/A chain
 * and an exploitability sub-score from AV×AC×PR×UI, combined and rounded
 * up to one decimal. Qualitative bands: `0` info, `0.1–3.9` low,
 * `4.0–6.9` medium, `7.0–8.9` high, `9.0–10.0` critical.
 */

export const AIVSS_VERSION = '1.0';

export type AivssAttackVector = 'N' | 'A' | 'L' | 'P';
export type AivssAttackComplexity = 'L' | 'H';
export type AivssPrivilegesRequired = 'N' | 'L' | 'H';
export type AivssUserInteraction = 'N' | 'R';
export type AivssScope = 'U' | 'C';
export type AivssImpact = 'H' | 'L' | 'N';

/** Qualitative bands — structurally identical to the scanner's `ScanSeverity`. */
export type AivssSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface AivssVector {
  attackVector: AivssAttackVector;
  attackComplexity: AivssAttackComplexity;
  privilegesRequired: AivssPrivilegesRequired;
  userInteraction: AivssUserInteraction;
  scope: AivssScope;
  confidentiality: AivssImpact;
  integrity: AivssImpact;
  availability: AivssImpact;
}

export interface AivssScore {
  /** Base score, 0–10, rounded up to one decimal. */
  baseScore: number;
  /** Qualitative band derived from the base score. */
  severity: AivssSeverity;
  /** Impact sub-score (C/I/A chain), unrounded. */
  impactSubScore: number;
  /** Exploitability sub-score (AV/AC/PR/UI chain), unrounded. */
  exploitabilitySubScore: number;
  /** Canonical vector string, e.g. `AIVSS:1.0/AV:N/...`. */
  vector: string;
}

// ── Metric weights (CVSS v3.1 math) ──────────────────────────────────────

export const ATTACK_VECTOR_WEIGHT: Record<AivssAttackVector, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
export const ATTACK_COMPLEXITY_WEIGHT: Record<AivssAttackComplexity, number> = { L: 0.77, H: 0.44 };
export const USER_INTERACTION_WEIGHT: Record<AivssUserInteraction, number> = { N: 0.85, R: 0.62 };
export const IMPACT_WEIGHT: Record<AivssImpact, number> = { H: 0.56, L: 0.22, N: 0 };

const PRIVILEGES_WEIGHT_UNCHANGED: Record<AivssPrivilegesRequired, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PRIVILEGES_WEIGHT_CHANGED: Record<AivssPrivilegesRequired, number> = { N: 0.85, L: 0.68, H: 0.5 };

// ── Vector helpers ────────────────────────────────────────────────────────

/**
 * Build a vector positionally for brevity in canned profiles:
 * `makeVector(av, ac, pr, ui, scope, c, i, a)`.
 */
export function makeVector(
  av: AivssAttackVector,
  ac: AivssAttackComplexity,
  pr: AivssPrivilegesRequired,
  ui: AivssUserInteraction,
  scope: AivssScope,
  c: AivssImpact,
  i: AivssImpact,
  a: AivssImpact,
): AivssVector {
  return {
    attackVector: av,
    attackComplexity: ac,
    privilegesRequired: pr,
    userInteraction: ui,
    scope,
    confidentiality: c,
    integrity: i,
    availability: a,
  };
}

export function toVectorString(vector: AivssVector): string {
  return [
    `AIVSS:${AIVSS_VERSION}`,
    `AV:${vector.attackVector}`,
    `AC:${vector.attackComplexity}`,
    `PR:${vector.privilegesRequired}`,
    `UI:${vector.userInteraction}`,
    `S:${vector.scope}`,
    `C:${vector.confidentiality}`,
    `I:${vector.integrity}`,
    `A:${vector.availability}`,
  ].join('/');
}

const VECTOR_PREFIX = `AIVSS:${AIVSS_VERSION}`;

const VECTOR_METRIC_KEYS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;

/**
 * Parse a canonical vector string. Parsing is case-insensitive; unknown,
 * missing or duplicated metrics are rejected so a typo cannot silently
 * skew a score.
 */
export function parseVectorString(input: string): AivssVector {
  const parts = input.trim().split('/');
  if ((parts[0] ?? '').toUpperCase() !== VECTOR_PREFIX) {
    throw new Error(`not an AIVSS vector string: ${input}`);
  }
  const metrics: Record<string, string> = {};
  for (const raw of parts.slice(1)) {
    const part = raw.trim();
    if (part.length === 0) continue;
    const sep = part.indexOf(':');
    if (sep < 1) throw new Error(`malformed AIVSS metric "${part}"`);
    const key = part.slice(0, sep).toUpperCase();
    const value = part.slice(sep + 1).toUpperCase();
    if (!(VECTOR_METRIC_KEYS as readonly string[]).includes(key)) {
      throw new Error(`unknown AIVSS metric "${key}"`);
    }
    if (metrics[key] !== undefined) throw new Error(`duplicate AIVSS metric "${key}"`);
    metrics[key] = value;
  }
  const missing = VECTOR_METRIC_KEYS.filter((k) => metrics[k] === undefined);
  if (missing.length > 0) throw new Error(`AIVSS vector is missing metrics: ${missing.join(', ')}`);

  const pick = <T extends string>(key: string, allowed: readonly T[]): T => {
    const value = metrics[key]!;
    if (!(allowed as readonly string[]).includes(value)) {
      throw new Error(`invalid AIVSS ${key} value "${value}" (expected one of ${allowed.join('|')})`);
    }
    return value as T;
  };

  return {
    attackVector: pick('AV', ['N', 'A', 'L', 'P'] as const),
    attackComplexity: pick('AC', ['L', 'H'] as const),
    privilegesRequired: pick('PR', ['N', 'L', 'H'] as const),
    userInteraction: pick('UI', ['N', 'R'] as const),
    scope: pick('S', ['U', 'C'] as const),
    confidentiality: pick('C', ['H', 'L', 'N'] as const),
    integrity: pick('I', ['H', 'L', 'N'] as const),
    availability: pick('A', ['H', 'L', 'N'] as const),
  };
}

// ── Scoring ───────────────────────────────────────────────────────────────

/** CVSS-style roundup to one decimal, with the standard FP-noise guard. */
function roundup1(value: number): number {
  return Math.ceil((value * 10) - 1e-9) / 10;
}

/** Qualitative band for a base score (lower boundary inclusive). */
export function severityFromScore(score: number): AivssSeverity {
  if (score <= 0) return 'info';
  if (score < 4.0) return 'low';
  if (score < 7.0) return 'medium';
  if (score < 9.0) return 'high';
  return 'critical';
}

/**
 * Compute the AIVSS base score for a metric vector.
 * Formula follows CVSS v3.1 base-score math with agent-adapted semantics.
 */
export function scoreVector(vector: AivssVector): AivssScore {
  const iss = 1
    - (1 - IMPACT_WEIGHT[vector.confidentiality])
    * (1 - IMPACT_WEIGHT[vector.integrity])
    * (1 - IMPACT_WEIGHT[vector.availability]);

  const scopeChanged = vector.scope === 'C';
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(Math.max(iss - 0.02, 0), 15)
    : 6.42 * iss;

  const prWeight = scopeChanged
    ? PRIVILEGES_WEIGHT_CHANGED[vector.privilegesRequired]
    : PRIVILEGES_WEIGHT_UNCHANGED[vector.privilegesRequired];
  const exploitability = 8.22
    * ATTACK_VECTOR_WEIGHT[vector.attackVector]
    * ATTACK_COMPLEXITY_WEIGHT[vector.attackComplexity]
    * prWeight
    * USER_INTERACTION_WEIGHT[vector.userInteraction];

  const base = impact <= 0 ? 0 : roundup1(Math.min(impact + exploitability, 10));
  return {
    baseScore: base,
    severity: severityFromScore(base),
    impactSubScore: impact,
    exploitabilitySubScore: exploitability,
    vector: toVectorString(vector),
  };
}

// ── Canned profiles for scanner rules ────────────────────────────────────

export interface AivssRuleProfile {
  vector: AivssVector;
  /** Why these metrics were chosen — keeps the score auditable. */
  rationale: string;
}

/**
 * Metric choices per scanner rule (MCP000–MCP007). Each canned vector is
 * calibrated so its qualitative band matches the rule's built-in severity,
 * keeping the ordinal and numeric views consistent. Rules with dynamic
 * severity (MCP002 varies per Unicode range) also get `rule@severity` keys.
 */
export const RULE_VECTORS: Record<string, AivssRuleProfile> = {
  MCP000: {
    vector: makeVector('L', 'L', 'L', 'N', 'U', 'N', 'L', 'L'),
    rationale: 'Unreadable/invalid config degrades the server (integrity, availability) and can mask other findings; local access, limited privileges.',
  },
  MCP001: {
    vector: makeVector('N', 'L', 'N', 'N', 'C', 'L', 'H', 'N'),
    rationale: 'Instruction override in attacker-visible text: remote, unprivileged, unattended; hijacks behavior and impact escapes into other systems.',
  },
  MCP002: {
    vector: makeVector('N', 'L', 'N', 'N', 'C', 'L', 'H', 'N'),
    rationale: 'High-severity hidden Unicode defeats visual review like an override does (Trojan-Source style); lower variants score via @medium/@low.',
  },
  'MCP002@medium': {
    vector: makeVector('N', 'L', 'N', 'R', 'U', 'L', 'L', 'N'),
    rationale: 'Mid-severity hidden characters need rendering to matter: user-interaction required, modest disclosure/hijack impact.',
  },
  'MCP002@low': {
    vector: makeVector('N', 'H', 'L', 'R', 'U', 'N', 'N', 'L'),
    rationale: 'Low-severity variants (variation selectors) are conditional and cosmetic-grade; render-dependent tool blips only.',
  },
  MCP003: {
    vector: makeVector('N', 'L', 'N', 'N', 'C', 'H', 'H', 'N'),
    rationale: 'Permission checks globally disabled: every hosted tool acts without confirmation — near-worst case for an agent sandbox.',
  },
  MCP004: {
    vector: makeVector('L', 'L', 'L', 'N', 'C', 'H', 'H', 'N'),
    rationale: 'Shell wrapper grants arbitrary command execution to hosted tools; local config access, but impact escapes the sandbox.',
  },
  MCP005: {
    vector: makeVector('N', 'L', 'L', 'N', 'C', 'H', 'L', 'N'),
    rationale: 'Secrets reachable by a network-capable server: one poisoned description away from credential exfiltration (high confidentiality loss).',
  },
  MCP006: {
    vector: makeVector('L', 'L', 'L', 'N', 'U', 'L', 'H', 'N'),
    rationale: 'Wildcard allowlist auto-approves every tool; behavior-hijack-grade integrity, but impact stays inside the agent sandbox.',
  },
  MCP007: {
    vector: makeVector('L', 'L', 'L', 'N', 'C', 'H', 'H', 'L'),
    rationale: 'Root/home filesystem mount: file tools read and overwrite everything under it — high confidentiality/integrity, some availability.',
  },
};

/**
 * Conservative fallback vectors for rules without a canned profile, keyed by
 * the finding's own severity band so the numeric score never contradicts the
 * ordinal rating. Findings without a severity fall back to `medium`.
 */
export const FALLBACK_VECTORS: Record<Exclude<AivssSeverity, 'info'>, AivssRuleProfile> = {
  low: {
    vector: makeVector('N', 'H', 'L', 'R', 'U', 'L', 'L', 'N'),
    rationale: 'Fallback for low findings: remote but conditional, user-mediated, marginal impact.',
  },
  medium: {
    vector: makeVector('L', 'L', 'L', 'N', 'U', 'L', 'H', 'N'),
    rationale: 'Fallback for medium findings: local config surface, integrity-grade impact inside the sandbox.',
  },
  high: {
    vector: makeVector('L', 'L', 'L', 'N', 'C', 'H', 'H', 'N'),
    rationale: 'Fallback for high findings: local surface, hijack-grade impact escaping the sandbox.',
  },
  critical: {
    vector: makeVector('N', 'L', 'N', 'N', 'C', 'H', 'H', 'N'),
    rationale: 'Fallback for critical findings: remote unprivileged hijack with sandbox escape.',
  },
};

/** Minimal finding shape AIVSS scores — the scanner's findings satisfy it. */
export interface AivssScorable {
  ruleId: string;
  severity?: string;
}

const SCOREABLE_BANDS = ['low', 'medium', 'high', 'critical'] as const;

/**
 * Score a scan finding. Resolution order:
 * 1. `rule@severity` dynamic profile, when the rule has one and the rule id
 *    is not already suffixed (covers MCP002's per-Unicode-range severity);
 * 2. the rule's plain canned profile (static-severity rules always land here);
 * 3. a severity-matched fallback vector for unknown rules.
 *
 * This keeps an unknown rule id from producing a score that contradicts its
 * ordinal severity. An absent or unrecognized severity falls back to `medium`.
 */
export function scoreFinding(finding: AivssScorable): AivssScore {
  const raw = typeof finding.severity === 'string' ? finding.severity.toLowerCase() : undefined;
  const fallbackKey = ((SCOREABLE_BANDS as readonly string[]).includes(raw ?? '')
    ? raw
    : 'medium') as Exclude<AivssSeverity, 'info'>;
  const dynamicKey = finding.ruleId.includes('@') ? undefined : `${finding.ruleId}@${fallbackKey}`;
  const profile = (dynamicKey !== undefined ? RULE_VECTORS[dynamicKey] : undefined)
    ?? RULE_VECTORS[finding.ruleId]
    ?? FALLBACK_VECTORS[fallbackKey];
  return scoreVector(profile.vector);
}
