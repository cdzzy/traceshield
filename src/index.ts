import { PolicyEngine } from './policy-engine.js';
import { TraceRecorder } from './trace-recorder.js';
import { AttributionAnalyzer } from './attribution-analyzer.js';
import { RuntimeGuard } from './runtime-guard.js';
import { MemoryStorage } from './storage/memory.js';
import { verifySpanChain } from './hash-chain.js';
import type {
  TraceShieldConfig,
  StorageBackend,
  GuardConfig,
  Trace,
  TraceQuery,
  ViolationQuery,
  StoredViolation,
  AttributionReport,
  PolicySet,
} from './types.js';

export class TraceShield {
  private policyEngine: PolicyEngine;
  private recorder: TraceRecorder;
  private analyzer: AttributionAnalyzer;
  private storage: StorageBackend;
  private config: TraceShieldConfig;
  private initialized = false;

  constructor(config: TraceShieldConfig = {}) {
    this.config = config;

    // Initialize policy engine
    if (typeof config.policies === 'string') {
      this.policyEngine = PolicyEngine.fromFile(config.policies);
    } else if (config.policies) {
      this.policyEngine = new PolicyEngine(config.policies);
    } else {
      this.policyEngine = new PolicyEngine();
    }

    // Initialize storage
    this.storage = this.createStorage(config);

    // Initialize recorder with storage
    this.recorder = new TraceRecorder({
      storage: this.storage,
      hashAlgorithm: config.hashAlgorithm,
    });

    // Initialize analyzer
    this.analyzer = new AttributionAnalyzer();
  }

  /**
   * Initialize the storage backend. Must be called before using
   * storage-dependent features (queryTraces, queryViolations, etc).
   * Guards and traces work without initialization (data kept in memory).
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;
    await this.storage.initialize();
    this.initialized = true;
  }

  async close(): Promise<void> {
    await this.storage.close();
    this.initialized = false;
  }

  // ---- Guard Factory ----

  /**
   * Create a RuntimeGuard for an agent. Each guard manages a single trace
   * (one execution session). Create a new guard for each agent task.
   */
  createGuard(config: GuardConfig): RuntimeGuard {
    return new RuntimeGuard(
      config,
      this.policyEngine,
      this.recorder,
      this.storage,
      this.config.hooks,
    );
  }

  // ---- Policy Management ----

  getPolicyEngine(): PolicyEngine {
    return this.policyEngine;
  }

  loadPolicies(policies: PolicySet): void {
    this.policyEngine.loadPolicySet(policies);
  }

  // ---- Trace Queries ----

  async queryTraces(query: TraceQuery): Promise<Trace[]> {
    return this.storage.queryTraces(query);
  }

  async getTrace(traceId: string): Promise<Trace | null> {
    return this.recorder.loadTrace(traceId);
  }

  /**
   * Verify the integrity of a trace's hash chain.
   * Returns verification result with any detected tampering.
   */
  verifyTrace(trace: Trace) {
    return verifySpanChain(trace.spans, this.config.hashAlgorithm);
  }

  // ---- Violation Queries ----

  async queryViolations(query: ViolationQuery): Promise<StoredViolation[]> {
    return this.storage.queryViolations(query);
  }

  // ---- Attribution Analysis ----

  /**
   * Analyze a failed trace and generate an attribution report.
   */
  async analyze(traceId: string): Promise<AttributionReport> {
    const trace = await this.recorder.loadTrace(traceId);
    if (!trace) throw new Error(`Trace ${traceId} not found`);

    const report = this.analyzer.analyze(trace);

    await this.storage.saveReport(report);
    return report;
  }

  analyzeTrace(trace: Trace): AttributionReport {
    return this.analyzer.analyze(trace);
  }

  async getReports(traceId: string): Promise<AttributionReport[]> {
    return this.storage.getReportsByTrace(traceId);
  }

  // ---- Utility ----

  getRecorder(): TraceRecorder {
    return this.recorder;
  }

  getStorage(): StorageBackend {
    return this.storage;
  }

  private createStorage(config: TraceShieldConfig): StorageBackend {
    const storageConfig = config.storage ?? { type: 'memory' as const };

    switch (storageConfig.type) {
      case 'memory':
        return new MemoryStorage();
      case 'sqlite': {
        // Lazy import to avoid requiring better-sqlite3 when not used
        const { SqliteStorage } = require('./storage/sqlite.js') as typeof import('./storage/sqlite.js');
        return new SqliteStorage(storageConfig.path);
      }
      case 'postgresql': {
        const { PostgresStorage } = require('./storage/postgresql.js') as typeof import('./storage/postgresql.js');
        return new PostgresStorage(storageConfig.connectionString);
      }
      case 'custom':
        return storageConfig.backend;
      default:
        return new MemoryStorage();
    }
  }
}

// ---- Re-exports ----

export { PolicyEngine, PolicyViolationError } from './policy-engine.js';
export { TraceRecorder } from './trace-recorder.js';
export { AttributionAnalyzer } from './attribution-analyzer.js';
export { RuntimeGuard } from './runtime-guard.js';
export { MemoryStorage } from './storage/memory.js';
export { verifySpanChain, computeSpanHash, computeTraceIntegrityHash } from './hash-chain.js';
export type { VerificationResult, ChainError } from './hash-chain.js';

// Re-export all types
export type {
  ActionType,
  PolicySet,
  Policy,
  PolicyRule,
  PolicyEffect,
  RuleCondition,
  PatternMatch,
  NumericConstraint,
  PolicyEvaluation,
  EvalContext,
  PolicyDecision,
  Trace,
  TraceStatus,
  Span,
  SpanStatus,
  SpanError,
  FailureType,
  Severity,
  AttributionReport,
  RootCause,
  CausalLink,
  TimelineEvent,
  TraceQuery,
  ViolationQuery,
  StoredViolation,
  StorageBackend,
  TraceShieldConfig,
  StorageConfig,
  TraceShieldHooks,
  GuardConfig,
  ActionInput,
} from './types.js';
