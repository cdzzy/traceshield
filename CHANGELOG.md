# Changelog

All notable changes to TraceShield are documented in this file.

## [0.2.0] - 2026-08-15

### Added

- **Real-time violation webhooks** (`#1`): `WebhookNotifier` (generic + Slack endpoints) wired into the `TraceShield` facade.
- **Tamper-evident audit export** (`#2`): `TraceShieldExporter` exporting JSON / JSON-LD / CEF with integrity verification.
- **Prompt injection detection** (`#3`): `PromptInjectionDetector` with pattern-based multi-layer detection and sanitization.
- **MCP security listener** (`#4`): `MCPEventListener` / `MCPToolWrapper` with rate limiting, policy checks, and well-known MCP tool risk classification.
- **Behavior baseline learning** (`#5`): `BehaviorBaseline` detecting novel tool usage after a learning period.
- **Red team toolkit** (`#6`): `RedTeam` with pre-built prompt-injection / tool-misuse scenarios and reports.
- **Threat intelligence feed** (`#7`): `ThreatIntelFeed` with pluggable providers (MISP/OpenCTI/custom), IOC matching, and policy updates.
- **ZK compliance proofs** (`#8`): `ZKComplianceProver` using a SHA-256 commitment scheme for privacy-preserving compliance verification.

### Changed

- Completed the architecture refactor: unified `types.ts`, new `TraceShield` facade (`src/trace-shield.ts`) exposing `createGuard` / `analyzeTrace` / `verifyTrace`, and reconciled `policy-engine`, `runtime-guard`, `trace-recorder`, `webhook-notifier`, `compliance-reports`, `dashboard`, and `mcp-listener` onto the new Span/Trace model.
- Fixed ESM `require` usage in `policy-engine`; added ESLint (flat config) so the CI lint job passes.

## [0.1.0]

- Initial release (hash chain, policy engine, runtime guard, attribution analyzer, storage adapters).
