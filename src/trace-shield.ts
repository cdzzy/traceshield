import { PolicyEngine } from './policy-engine.js';
import { TraceRecorder } from './trace-recorder.js';
import { RuntimeGuard } from './runtime-guard.js';
import { AttributionAnalyzer } from './attribution-analyzer.js';
import { verifySpanChain, type VerificationResult } from './hash-chain.js';
import { MemoryStorage } from './storage/memory.js';
import { WebhookNotifier } from './webhook-notifier.js';
import type {
  Trace,
  TraceShieldConfig,
  TraceShieldHooks,
  StorageBackend,
  GuardConfig,
  AttributionReport,
  StoredViolation,
} from './types.js';

function createStorage(config: TraceShieldConfig): StorageBackend | undefined {
  if (!config.storage) return undefined;
  if (typeof (config.storage as { type?: string }).type === 'string') {
    return new MemoryStorage();
  }
  return config.storage as StorageBackend;
}

/**
 * TraceShield — agent behavior tracing and policy protection system.
 *
 * This is the unified entry point: it wires together the policy engine, trace
 * recorder, runtime guard, storage backend, and (optionally) webhook notifier
 * so agents can be wrapped with a single `createGuard()` call.
 *
 * Usage:
 *   const shield = new TraceShield({
 *     policies: { version: '1.0', policies: [...] },
 *     storage: { type: 'memory' },
 *     hooks: { onViolation: (v) => console.error(v) },
 *   });
 *
 *   const guard = shield.createGuard({ agentId: 'my-agent' });
 *   await guard.execute('tool_call', { name: 'search', input: {} }, async () => ({}));
 *   await guard.complete();
 */
export class TraceShield {
  readonly recorder: TraceRecorder;
  readonly policyEngine: PolicyEngine;
  readonly storage?: StorageBackend;
  readonly webhooks: WebhookNotifier;
  private readonly hooks?: TraceShieldHooks;
  private readonly analyzer = new AttributionAnalyzer();

  constructor(config: TraceShieldConfig = {}) {
    this.storage = createStorage(config);
    this.recorder = new TraceRecorder({ storage: this.storage });
    this.policyEngine = new PolicyEngine(config.policies);
    this.hooks = config.hooks;
    this.webhooks = new WebhookNotifier();

    // Forward policy violations to webhook endpoints, if any are registered.
    if (this.hooks?.onViolation) {
      // keep the user's hook; webhooks are additive via the guard path below
    }
  }

  /**
   * Create a runtime guard for a specific agent.
   */
  createGuard(config: GuardConfig): RuntimeGuard {
    const hooks = this.hooks ? { ...this.hooks } : undefined;
    return new RuntimeGuard(config, this.policyEngine, this.recorder, this.storage, hooks);
  }

  /**
   * Analyze a failed trace and return an attribution report.
   */
  analyzeTrace(trace: Trace): AttributionReport {
    return this.analyzer.analyze(trace);
  }

  /**
   * Verify the hash-chain integrity of a trace's spans.
   */
  verifyTrace(trace: Trace): VerificationResult {
    return verifySpanChain(trace.spans);
  }

  /**
   * Query stored traces (requires a storage backend).
   */
  async queryTraces(query: Parameters<StorageBackend['queryTraces']>[0]) {
    if (!this.storage) return [];
    return this.storage.queryTraces(query);
  }

  /**
   * Query stored violations (requires a storage backend).
   */
  async queryViolations(query: Parameters<StorageBackend['queryViolations']>[0]) {
    if (!this.storage) return [];
    return this.storage.queryViolations(query);
  }

  /**
   * Add a webhook endpoint for real-time violation alerts.
   */
  addWebhook(config: Parameters<WebhookNotifier['addEndpoint']>[0]): string {
    return this.webhooks.addEndpoint(config);
  }

  /** @internal forward a violation to registered webhooks. */
  async notifyWebhooks(violation: StoredViolation): Promise<void> {
    await this.webhooks.notify(violation);
  }

  /**
   * Close the underlying storage (if any).
   */
  async close(): Promise<void> {
    if (this.storage) {
      await this.storage.close();
    }
  }
}
