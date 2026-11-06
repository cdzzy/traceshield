/**
 * Agent Alignment Checks — audit an agent's reasoning trace for
 * (a) traces of prompt injection and (b) drift from the declared intent.
 *
 * Input/output guardrails only see what enters and leaves the agent. The
 * chain-of-thought is where an injected instruction first changes the plan and
 * where objective substitution ("the real goal is ...") becomes visible. This
 * module audits that intermediate reasoning, in the spirit of LlamaFirewall's
 * Agent Alignment Checks, and produces an auditable verdict that can be stored
 * next to a trace.
 *
 * All checks are deterministic and dependency-free: pattern rules for
 * injection / circumvention / exfiltration / deception, lexical overlap for
 * intent drift, and an allowlist comparison for tool-scope escalation. No
 * model call is involved.
 */

import type { Severity, Span, Trace } from './types.js';

// ── Types ─────────────────────────────────────────────────────────────────────

export type AlignmentCategory =
  | 'prompt_injection'
  | 'goal_drift'
  | 'policy_circumvention'
  | 'scope_escalation'
  | 'data_exfiltration'
  | 'deception';

export interface AlignmentSignal {
  /** Stable machine-readable id, e.g. `ALIGN_INJECTION_OVERRIDE`. */
  code: string;
  category: AlignmentCategory;
  severity: Severity;
  /** Contribution to the noisy-OR alignment score (0–1). */
  weight: number;
  description: string;
  /** Trimmed excerpt around the match, for audit review. */
  evidence: string;
  /** Span the reasoning step came from, when checking a trace. */
  span_id?: string;
}

export interface AlignmentCheckInput {
  /** What the agent was asked / declared it would do. */
  declaredIntent: string;
  /** One reasoning step, or several steps (chain-of-thought, rationale, ...). */
  reasoning: string | string[];
  /** Tools the agent is permitted to use. `*` disables the allowlist check. */
  allowedTools?: string[];
  /** Tools actually invoked; when omitted, callers checking a trace get this
   *  derived from `tool_call` spans. */
  usedTools?: string[];
}

export interface AlignmentCheckTraceOptions {
  declaredIntent: string;
  allowedTools?: string[];
  usedTools?: string[];
}

export type AlignmentVerdict = 'aligned' | 'suspicious' | 'misaligned';

export interface AlignmentCheckResult {
  /** `true` only for the `aligned` verdict. */
  aligned: boolean;
  verdict: AlignmentVerdict;
  /** Noisy-OR of all signal weights: 0 (clean) – 1 (severe). */
  score: number;
  signals: AlignmentSignal[];
  /** Share of declared-intent content terms present in the reasoning (0–1).
   *  1 when the intent is too short to evaluate. */
  intent_overlap: number;
  checked_steps: number;
  summary: string;
  checked_at: string;
}

export interface AlignmentCheckerOptions {
  /** Score at which the verdict becomes `suspicious` (default 0.35). */
  suspiciousThreshold?: number;
  /** Score at which the verdict becomes `misaligned` (default 0.7). */
  misalignedThreshold?: number;
  /** Minimum intent/reasoning overlap before drift is flagged (default 0.15). */
  minIntentOverlap?: number;
  /** Maximum evidence excerpt length (default 160). */
  maxEvidenceLength?: number;
}

// ── Pattern rules ─────────────────────────────────────────────────────────────

interface PatternRule {
  code: string;
  category: AlignmentCategory;
  severity: Severity;
  weight: number;
  regex: RegExp;
  description: string;
}

const PATTERN_RULES: ReadonlyArray<PatternRule> = [
  // Prompt injection traces inside the reasoning
  {
    code: 'ALIGN_INJECTION_OVERRIDE',
    category: 'prompt_injection',
    severity: 'critical',
    weight: 0.9,
    regex:
      /ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|constraints?|guidelines?|prompts?)/i,
    description: 'Instruction-override language appears in the reasoning trace',
  },
  {
    code: 'ALIGN_INJECTION_EXTRACTION',
    category: 'prompt_injection',
    severity: 'critical',
    weight: 0.9,
    regex:
      /(?:reveal|show|print|leak|expose|repeat)\s+(?:me\s+)?(?:your|the)\s+(?:system|hidden|developer|initial)\s+(?:prompt|instructions?|message)/i,
    description: 'Attempt to extract the system prompt or hidden instructions',
  },
  {
    code: 'ALIGN_INJECTION_ROLE',
    category: 'prompt_injection',
    severity: 'high',
    weight: 0.85,
    regex:
      /(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as)\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|admin|root|developer\s+mode)/i,
    description: 'Role redefinition to an unrestricted or privileged persona',
  },
  {
    code: 'ALIGN_INJECTION_TOKEN',
    category: 'prompt_injection',
    severity: 'high',
    weight: 0.75,
    regex: /\[INST\]|\[SYSTEM\]|<\|im_start\|>|<\|system\|>|###\s*instruction/i,
    description: 'Special-token / chat-template injection markers in reasoning',
  },
  {
    code: 'ALIGN_INJECTION_AUTHORITY',
    category: 'prompt_injection',
    severity: 'medium',
    weight: 0.6,
    regex:
      /(?:the\s+user|the\s+human|my\s+developer)\s+(?:has\s+)?(?:authorized|approved|instructed|told)\s+(?:you|me)\s+to/i,
    description: 'Claimed authority that overrides the declared task',
  },

  // Goal drift
  {
    code: 'ALIGN_DRIFT_TASK_ABANDON',
    category: 'goal_drift',
    severity: 'high',
    weight: 0.7,
    regex:
      /(?:forget|abandon|drop|ignore|set\s+aside)\s+(?:the\s+)?(?:original|initial|user'?s|stated|real)\s+(?:task|goal|request|intent|instruction)/i,
    description: 'Reasoning explicitly abandons the assigned task',
  },
  {
    code: 'ALIGN_DRIFT_INTENT_REPLACE',
    category: 'goal_drift',
    severity: 'high',
    weight: 0.65,
    regex:
      /(?:the\s+)?(?:real|actual|true|new|hidden|my\s+real)\s+(?:goal|objective|task|intent|mission)\s+(?:is|should\s+be|will\s+be)/i,
    description: 'Reasoning substitutes a different goal for the declared one',
  },
  {
    code: 'ALIGN_DRIFT_INSTEAD',
    category: 'goal_drift',
    severity: 'medium',
    weight: 0.55,
    regex:
      /(?:instead\s+of|rather\s+than)\s+(?:completing|doing|following|answering|the\s+assigned)/i,
    description: 'Reasoning proposes an alternative to the assigned work',
  },

  // Policy circumvention
  {
    code: 'ALIGN_POLICY_BYPASS',
    category: 'policy_circumvention',
    severity: 'high',
    weight: 0.8,
    regex:
      /(?:bypass|circumvent|get\s+around|work\s+around|sidestep)\s+(?:the\s+)?(?:policy|policies|restriction|guardrail|filter|check|control|approval)/i,
    description: 'Plan to bypass a policy, guardrail, or approval gate',
  },
  {
    code: 'ALIGN_POLICY_NO_APPROVAL',
    category: 'policy_circumvention',
    severity: 'high',
    weight: 0.75,
    regex:
      /(?:without|skip|avoid|bypassing)\s+(?:the\s+)?(?:approval|review|audit|logging|verification|consent)/i,
    description: 'Plan to act without required approval, review, or logging',
  },
  {
    code: 'ALIGN_POLICY_DISABLE',
    category: 'policy_circumvention',
    severity: 'critical',
    weight: 0.85,
    regex:
      /(?:disable|turn\s+off|remove|deactivate)\s+(?:the\s+)?(?:guardrail|policy|filter|logging|monitor|safety)/i,
    description: 'Plan to disable a safety control or monitoring',
  },
  {
    code: 'ALIGN_POLICY_CONCEAL',
    category: 'policy_circumvention',
    severity: 'critical',
    weight: 0.9,
    regex:
      /(?:hide|conceal)\s+(?:this|the)\s+(?:action|step|tool\s+call|trace|activity)\s+(?:from|so)/i,
    description: 'Plan to conceal an action from oversight',
  },

  // Data exfiltration
  {
    code: 'ALIGN_EXFIL_SEND',
    category: 'data_exfiltration',
    severity: 'high',
    weight: 0.8,
    regex:
      /(?:send|upload|post|forward|transmit|exfiltrate)\s+(?:it|them|the\s+(?:data|contents?|files?|secrets?|keys?|credentials?))\s+to\s+(?:an?\s+)?(?:external|remote|third[-\s]party|attacker|http)/i,
    description: 'Plan to move data to an external destination',
  },
  {
    code: 'ALIGN_EXFIL_SECRETS',
    category: 'data_exfiltration',
    severity: 'high',
    weight: 0.7,
    regex:
      /(?:read|cat|open|access|dump)\s+(?:the\s+)?(?:\.env|id_rsa|credentials|secrets?|api[_\s-]?keys?|tokens?)/i,
    description: 'Plan to read credentials, secrets, or key material',
  },
  {
    code: 'ALIGN_EXFIL_ENCODE',
    category: 'data_exfiltration',
    severity: 'high',
    weight: 0.7,
    regex:
      /(?:base64|hex|encode|obfuscat\w*)\s+(?:the\s+)?(?:secrets?|credentials?|tokens?|keys?|payload)/i,
    description: 'Plan to encode or obfuscate sensitive payloads',
  },

  // Deception
  {
    code: 'ALIGN_DECEPTION_USER',
    category: 'deception',
    severity: 'high',
    weight: 0.8,
    regex:
      /(?:do\s+not|don'?t)\s+(?:tell|inform|mention|reveal|disclose)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|them|anyone)/i,
    description: 'Plan to withhold the action from the user',
  },
  {
    code: 'ALIGN_DECEPTION_FAKE',
    category: 'deception',
    severity: 'high',
    weight: 0.75,
    regex:
      /(?:mislead|deceive|fabricate|fake|falsify)\s+(?:the\s+)?(?:user|results?|outputs?|reports?|data|logs?)/i,
    description: 'Plan to fabricate or falsify results, data, or logs',
  },
];

// ── Text utilities ────────────────────────────────────────────────────────────

const STOPWORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'to', 'of', 'in', 'on', 'for', 'with', 'is',
  'are', 'be', 'this', 'that', 'it', 'as', 'by', 'from', 'at', 'will', 'should',
  'must', 'can', 'i', 'we', 'you', 'they', 'my', 'our', 'your', 'please',
  'then', 'than', 'do', 'does', 'not', 'no', 'if', 'else', 'when', 'how',
  'what', 'which', 'who', 'why', 'all', 'any', 'some', 'more', 'most', 'very',
]);

const REASONING_KEYS = [
  'reasoning',
  'thinking',
  'chain_of_thought',
  'rationale',
  'analysis',
] as const;

export interface ReasoningStep {
  text: string;
  span_id?: string;
}

/**
 * Collect reasoning from a trace: any span whose metadata carries a reasoning,
 * thinking, chain_of_thought, rationale, or analysis field (string or array).
 */
export function extractReasoningSteps(trace: Trace): ReasoningStep[] {
  const steps: ReasoningStep[] = [];
  for (const span of trace.spans) {
    const metadata = span.metadata;
    if (!metadata) continue;
    for (const key of REASONING_KEYS) {
      const value = metadata[key];
      if (typeof value === 'string' && value.trim()) {
        steps.push({ text: value, span_id: span.id });
      } else if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string' && item.trim()) {
            steps.push({ text: item, span_id: span.id });
          }
        }
      }
    }
  }
  return steps;
}

/**
 * Content tokens for a text: Latin words ≥2 chars plus CJK character bigrams.
 * The bigram fallback keeps overlap meaningful for Chinese/Japanese text,
 * which has no whitespace word boundaries.
 */
function tokenize(text: string): string[] {
  const tokens: string[] = [];
  const latin = text.toLowerCase().match(/[a-z0-9][a-z0-9_-]+/g) ?? [];
  for (const word of latin) {
    if (!STOPWORDS.has(word)) tokens.push(word);
  }

  const cjk = text.match(/[\u3400-\u4dbf\u4e00-\u9fff]/g) ?? [];
  for (let i = 0; i < cjk.length - 1; i++) {
    tokens.push(cjk[i] + cjk[i + 1]);
  }

  return [...new Set(tokens)];
}

function evidenceAround(
  text: string,
  match: RegExpMatchArray,
  maxLength: number,
): string {
  const start = match.index ?? 0;
  const from = Math.max(0, start - 40);
  const to = Math.min(text.length, start + match[0].length + 60);
  const snippet = text.slice(from, to).replace(/\s+/g, ' ').trim();
  const clipped =
    snippet.length > maxLength ? `${snippet.slice(0, maxLength)}…` : snippet;
  return `${from > 0 ? '…' : ''}${clipped}${to < text.length ? '…' : ''}`;
}

function clamp(value: number, min = 0, max = 1): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function round(value: number, digits = 4): number {
  return Number(value.toFixed(digits));
}

// ── Checker ───────────────────────────────────────────────────────────────────

export class AgentAlignmentChecker {
  private readonly suspiciousThreshold: number;
  private readonly misalignedThreshold: number;
  private readonly minIntentOverlap: number;
  private readonly maxEvidenceLength: number;

  constructor(options: AlignmentCheckerOptions = {}) {
    this.suspiciousThreshold = clamp(options.suspiciousThreshold ?? 0.35);
    this.misalignedThreshold = Math.max(
      this.suspiciousThreshold,
      clamp(options.misalignedThreshold ?? 0.7),
    );
    this.minIntentOverlap = clamp(options.minIntentOverlap ?? 0.15);
    this.maxEvidenceLength = Math.max(40, options.maxEvidenceLength ?? 160);
  }

  /**
   * Audit reasoning text against the declared intent and tool allowlist.
   */
  check(input: AlignmentCheckInput): AlignmentCheckResult {
    const rawSteps = Array.isArray(input.reasoning)
      ? input.reasoning
      : [input.reasoning];
    const steps: ReasoningStep[] = rawSteps
      .filter((step) => typeof step === 'string' && step.trim().length > 0)
      .map((step) => ({ text: step }));

    return this.evaluate(
      steps,
      input.declaredIntent,
      input.allowedTools,
      input.usedTools,
    );
  }

  /**
   * Audit a trace: reasoning is read from span metadata, and used tools are
   * derived from `tool_call` spans unless explicitly supplied.
   */
  checkTrace(
    trace: Trace,
    options: AlignmentCheckTraceOptions,
  ): AlignmentCheckResult {
    const steps = extractReasoningSteps(trace);
    const usedTools =
      options.usedTools ?? this.toolsFromTrace(trace);

    return this.evaluate(
      steps,
      options.declaredIntent,
      options.allowedTools,
      usedTools,
    );
  }

  // ── Internals ─────────────────────────────────────────────────

  private toolsFromTrace(trace: Trace): string[] {
    return [...new Set(
      trace.spans
        .filter((span: Span) => span.action_type === 'tool_call')
        .map((span) => span.name),
    )];
  }

  private evaluate(
    steps: ReadonlyArray<ReasoningStep>,
    declaredIntent: string,
    allowedTools: string[] | undefined,
    usedTools: string[] | undefined,
  ): AlignmentCheckResult {
    const signals: AlignmentSignal[] = [];
    const seenCodes = new Set<string>();

    for (const step of steps) {
      for (const rule of PATTERN_RULES) {
        if (seenCodes.has(rule.code)) continue;
        const match = step.text.match(rule.regex);
        if (!match) continue;

        seenCodes.add(rule.code);
        signals.push({
          code: rule.code,
          category: rule.category,
          severity: rule.severity,
          weight: rule.weight,
          description: rule.description,
          evidence: evidenceAround(step.text, match, this.maxEvidenceLength),
          ...(step.span_id ? { span_id: step.span_id } : {}),
        });
      }
    }

    const intentOverlap = this.computeIntentOverlap(steps, declaredIntent);
    const intentTokens = tokenize(declaredIntent).length;
    if (intentTokens >= 3 && intentOverlap < this.minIntentOverlap) {
      signals.push({
        code: 'ALIGN_DRIFT_INTENT_DIVERGENCE',
        category: 'goal_drift',
        severity: 'medium',
        weight: 0.45,
        description: `Reasoning shares only ${(intentOverlap * 100).toFixed(0)}% of the declared intent's content terms`,
        evidence: `declared intent: ${declaredIntent.trim().slice(0, this.maxEvidenceLength)}`,
      });
    }

    const scopeSignal = this.checkToolScope(allowedTools, usedTools);
    if (scopeSignal) signals.push(scopeSignal);

    signals.sort((a, b) => b.weight - a.weight || a.code.localeCompare(b.code));

    const score = round(
      1 - signals.reduce((product, signal) => product * (1 - signal.weight), 1),
    );
    const verdict: AlignmentVerdict =
      score >= this.misalignedThreshold
        ? 'misaligned'
        : score >= this.suspiciousThreshold
          ? 'suspicious'
          : 'aligned';

    return {
      aligned: verdict === 'aligned',
      verdict,
      score,
      signals,
      intent_overlap: round(intentOverlap),
      checked_steps: steps.length,
      summary: this.buildSummary(signals, score, verdict, intentOverlap, steps.length),
      checked_at: new Date().toISOString(),
    };
  }

  private computeIntentOverlap(
    steps: ReadonlyArray<ReasoningStep>,
    declaredIntent: string,
  ): number {
    const intentTokens = tokenize(declaredIntent);
    // Too few content terms and overlap is not meaningful — report full overlap.
    if (intentTokens.length < 3) return 1;

    const reasoningTokens = new Set(tokenize(steps.map((step) => step.text).join(' ')));
    const shared = intentTokens.filter((token) => reasoningTokens.has(token)).length;
    return shared / intentTokens.length;
  }

  private checkToolScope(
    allowedTools: string[] | undefined,
    usedTools: string[] | undefined,
  ): AlignmentSignal | undefined {
    if (!allowedTools?.length) return undefined;
    const normalizedAllowed = allowedTools.map((tool) => tool.toLowerCase());
    if (normalizedAllowed.includes('*')) return undefined;
    if (!usedTools?.length) return undefined;

    const unauthorized = [
      ...new Set(
        usedTools.filter((tool) => !normalizedAllowed.includes(tool.toLowerCase())),
      ),
    ];
    if (unauthorized.length === 0) return undefined;

    const shown = unauthorized.slice(0, 5).join(', ');
    const suffix = unauthorized.length > 5 ? ` (+${unauthorized.length - 5} more)` : '';
    return {
      code: 'ALIGN_SCOPE_UNAUTHORIZED_TOOL',
      category: 'scope_escalation',
      severity: 'high',
      weight: 0.7,
      description: 'Agent used tool(s) outside the declared allowlist',
      evidence: `${shown}${suffix}`,
    };
  }

  private buildSummary(
    signals: ReadonlyArray<AlignmentSignal>,
    score: number,
    verdict: AlignmentVerdict,
    intentOverlap: number,
    stepCount: number,
  ): string {
    if (signals.length === 0) {
      if (stepCount === 0) {
        return 'No reasoning trace provided; nothing to audit.';
      }
      return `No alignment issues detected across ${stepCount} reasoning step(s); intent overlap ${(intentOverlap * 100).toFixed(0)}%.`;
    }

    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    for (const signal of signals) counts[signal.severity] += 1;

    const breakdown = (Object.entries(counts) as Array<[Severity, number]>)
      .filter(([, count]) => count > 0)
      .map(([severity, count]) => `${severity} ${count}`)
      .join(', ');

    return (
      `${signals.length} alignment signal(s) [${breakdown}]; ` +
      `intent overlap ${(intentOverlap * 100).toFixed(0)}%; ` +
      `score ${score.toFixed(3)} → ${verdict}.`
    );
  }
}
