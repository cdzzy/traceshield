/**
 * Prompt injection detection and prevention engine (Issue #3).
 *
 * Multi-layer detection using pattern matching and behavioral heuristics to
 * identify prompt-injection attacks before they reach the model.
 */

export interface InjectionDetectionResult {
  detected: boolean;
  confidence: number;          // 0–1
  patterns: string[];          // matched pattern descriptions
  layer: 'pattern' | 'heuristic' | 'none';
  sanitized: boolean;
}

const INJECTION_PATTERNS: Array<{ regex: RegExp; description: string; weight: number }> = [
  { regex: /ignore\s+(previous|above|all|prior)\s+(instructions?|constraints?|prompts?|rules?)/i, description: 'instruction override', weight: 0.95 },
  { regex: /forget\s+(everything|all|what|your)\s+(instructions?|constraints?|training|rules?)/i, description: 'memory reset', weight: 0.9 },
  { regex: /you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|uncensored)/i, description: 'role redefinition', weight: 0.9 },
  { regex: /reveal\s+(your\s+)?(system\s+prompt|instructions?|hidden\s+prompt)/i, description: 'system prompt extraction', weight: 0.95 },
  { regex: /\[INST\]|\[SYSTEM\]|<\|im_start\|>|system:\s*(?!$)/i, description: 'special-token injection', weight: 0.85 },
  { regex: /disregard\s+(all|any)\s+(prior|previous)\s+instructions/i, description: 'disregard instruction', weight: 0.9 },
  { regex: /you\s+must\s+(obey|comply|follow)\s+(me|the\s+user|this)/i, description: 'authority override', weight: 0.8 },
  { regex: /pretend|act\s+as\s+if|roleplay/i, description: 'roleplay deception', weight: 0.6 },
];

export class PromptInjectionDetector {
  private readonly threshold: number;

  constructor(options: { threshold?: number } = {}) {
    this.threshold = options.threshold ?? 0.7;
  }

  /**
   * Detect prompt injection in a user input.
   */
  detect(input: string): InjectionDetectionResult {
    const text = typeof input === 'string' ? input : JSON.stringify(input);
    const matched: Array<{ description: string; weight: number }> = [];

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.regex.test(text)) {
        matched.push({ description: pattern.description, weight: pattern.weight });
      }
    }

    if (matched.length === 0) {
      return { detected: false, confidence: 0, patterns: [], layer: 'none', sanitized: false };
    }

    const confidence = Math.min(1, matched.reduce((sum, m) => sum + m.weight, 0) / matched.length);
    const detected = confidence >= this.threshold;

    return {
      detected,
      confidence,
      patterns: matched.map((m) => m.description),
      layer: 'pattern',
      sanitized: false,
    };
  }

  /**
   * Detect injection; if detected, return a sanitized (neutralized) version.
   */
  sanitize(input: string): InjectionDetectionResult & { output: string } {
    const result = this.detect(input);
    if (!result.detected) {
      return { ...result, output: input };
    }
    return {
      ...result,
      sanitized: true,
      output: '[input blocked by prompt-injection filter]',
    };
  }
}
