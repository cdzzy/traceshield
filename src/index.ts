// TraceShield - Agent Behavior Tracing & Protection System

export { TraceShield } from './trace-shield.js';
export { TraceRecorder } from './trace-recorder.js';
export { PolicyEngine, PolicyViolationError } from './policy-engine.js';
export { RuntimeGuard } from './runtime-guard.js';
export { AttributionAnalyzer } from './attribution-analyzer.js';
export { verifySpanChain, computeTraceIntegrityHash, computeSpanHash } from './hash-chain.js';
export type { VerificationResult } from './hash-chain.js';
export { MemoryStorage } from './storage/memory.js';
export { WebhookNotifier } from './webhook-notifier.js';
export type {
  WebhookEndpoint,
  WebhookPayload,
  WebhookEventType,
  WebhookType,
} from './webhook-notifier.js';
export { AuditDashboard, createDashboard } from './dashboard.js';
export type {
  DashboardConfig,
  DashboardStats,
} from './dashboard.js';
export {
  generateSOC2Report,
  generateGDPRReport,
  formatReportAsMarkdown,
} from './compliance-reports.js';
export type {
  ComplianceReport,
  ComplianceSummary,
  ViolationSummary,
  AgentSummary,
} from './compliance-reports.js';

// MCP security listener / proxy (Issue #4)
export { MCPEventListener, MCPToolWrapper, WELL_KNOWN_MCP_TOOLS, getDefaultMCPPolicies } from './mcp-listener.js';
export type { MCPEvent, MCPEventType, MCPPolicyRule, MCPActionResult } from './mcp-listener.js';

// Prompt injection detection (Issue #3)
export { PromptInjectionDetector } from './injection-detector.js';
export type { InjectionDetectionResult } from './injection-detector.js';

// Behavior baseline learning (Issue #5)
export { BehaviorBaseline } from './behavior-baseline.js';
export type { BehaviorAnomaly } from './behavior-baseline.js';

// Red team toolkit (Issue #6)
export { RedTeam, RED_TEAM_SCENARIOS } from './red-team.js';
export type { AttackScenario, AttackAttempt, RedTeamReport } from './red-team.js';

// Threat intelligence integration (Issue #7)
export { ThreatIntelFeed } from './threat-intel.js';
export type { ThreatProvider, ThreatIndicator, ThreatIntelConfig } from './threat-intel.js';

// Compliance export (Issue #2)
export { TraceShieldExporter } from './compliance-exporter.js';
export type { ExportOptions, ExportVerification } from './compliance-exporter.js';

// Zero-knowledge compliance proofs (Issue #8)
export { ZKComplianceProver } from './zk-compliance.js';
export type { ZKComplianceProof, ZKVerification } from './zk-compliance.js';

// Multi-agent attribution graph visualization
export { buildAttributionGraph, renderMermaid, renderDot } from './attribution-graph.js';
export type { AttributionGraph, GraphNode, GraphEdge, GraphNodeKind } from './attribution-graph.js';

export * from './types.js';
