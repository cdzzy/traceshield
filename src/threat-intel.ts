/**
 * Real-time threat intelligence feed integration (Issue #7).
 *
 * Integrates with threat intelligence providers (MISP, OpenCTI, or custom
 * HTTP feeds) to dynamically update security policies with new indicators of
 * compromise (IOCs) and blocked patterns.
 */

export interface ThreatIndicator {
  id: string;
  type: 'prompt-injection' | 'tool-misuse' | 'data-exfiltration' | 'mcp-threat' | 'ip' | 'hash';
  value: string;
  source: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface ThreatProvider {
  name: string;
  fetchIndicators(): Promise<ThreatIndicator[]>;
}

export interface ThreatIntelConfig {
  providers: ThreatProvider[];
  autoUpdatePolicies?: boolean;
}

export class ThreatIntelFeed {
  private readonly providers: ThreatProvider[];
  private readonly autoUpdatePolicies: boolean;
  private indicators: ThreatIndicator[] = [];
  private readonly blockedPatterns: Set<string> = new Set();

  constructor(config: ThreatIntelConfig) {
    this.providers = config.providers;
    this.autoUpdatePolicies = config.autoUpdatePolicies ?? true;
  }

  /**
   * Refresh indicators from all providers and update blocked patterns.
   */
  async refresh(): Promise<ThreatIndicator[]> {
    const fetched: ThreatIndicator[] = [];
    for (const provider of this.providers) {
      try {
        const indicators = await provider.fetchIndicators();
        fetched.push(...indicators);
      } catch {
        // Best-effort: ignore a failing provider, keep going.
      }
    }

    this.indicators = fetched;
    if (this.autoUpdatePolicies) {
      this.updateBlockedPatterns();
    }
    return fetched;
  }

  /**
   * Check whether an input matches a known threat indicator.
   */
  matches(input: string): ThreatIndicator | null {
    const lower = input.toLowerCase();
    for (const indicator of this.indicators) {
      if (indicator.type === 'prompt-injection' || indicator.type === 'tool-misuse') {
        if (lower.includes(indicator.value.toLowerCase())) {
          return indicator;
        }
      }
    }
    return null;
  }

  getIndicators(): ThreatIndicator[] {
    return [...this.indicators];
  }

  getBlockedPatterns(): string[] {
    return [...this.blockedPatterns];
  }

  /**
   * Threat level derived from the highest-severity active indicator.
   */
  getThreatLevel(): 'green' | 'yellow' | 'red' {
    if (this.indicators.some((i) => i.severity === 'critical')) return 'red';
    if (this.indicators.some((i) => i.severity === 'high')) return 'yellow';
    return 'green';
  }

  private updateBlockedPatterns(): void {
    for (const indicator of this.indicators) {
      if (indicator.type === 'prompt-injection' || indicator.type === 'tool-misuse' || indicator.type === 'mcp-threat') {
        this.blockedPatterns.add(indicator.value);
      }
    }
  }
}
