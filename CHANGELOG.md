# Changelog

All notable changes to TraceShield are documented in this file.

## [0.6.1] - 2026-09-25

### Changed

- `yaml` bumped to 2.9.x — 2.8.2 carried a Stack Overflow advisory (GHSA-48c2-rrv3-qjmp) triggered by deeply nested YAML; the CLI scanner and policy loader now run on a patched parser.
- Dev toolchain: vitest 3.2.7, tsx 4.23.15 (previous pin pulled a vulnerable esbuild, GHSA-g7r4-m6w7-qqqr), and `@vitest/coverage-v8` added so the CI coverage artifact reflects real numbers.
- Remaining `npm audit` findings are dev-only (vitest mock helper, moderate) with no non-breaking fix — vitest 5 would drop Node 18/20 support in CI — so they are accepted and documented here.

### Fixed

- Removed unused `StoredViolation` / `Policy` type imports flagged by ESLint.

## [0.6.0] - 2026-09-20

### Added

- **MCP configuration scanner** (`src/mcp-scanner.ts`): audit MCP server configs for supply-chain and instruction-injection risk with rules MCP000–MCP007 — invalid config, overridden instructions, hidden Unicode, permissive permissions, shell execution, secrets + network in one server, wildcard mounts, root-directory mounts. The filesystem is injected, so scanning is fully testable.
- **CLI**: `traceshield scan [--json]` walks a path tree and exits non-zero on high/critical findings — drop it into CI as a gate.
- **OWASP mapping** (`docs/owasp-asi-mapping.md`): capability × ASI01–ASI10 matrix documenting which TraceShield feature covers which agentic-security risk.
- **Release automation** (`.github/workflows/release.yml`): npm publish with provenance on `v*` tags, refused when the tag doesn't match `package.json` version.

## [0.5.0] - 2026-09-04

### Added

- **Policy-as-code + GitOps**: `validatePolicySet` is a CI gate that flags duplicate rule ids, unknown actions/effects, unconditional rules, and deny rules without messages; `diffPolicySets` + `renderDiffMarkdown` render rule-level diffs (added/removed/changed) for PR review.

## [0.4.0] - 2026-08-27

### Added

- **Multi-agent attribution graph visualization**: `buildAttributionGraph` aggregates traces into an agent→action→policy graph; `renderMermaid` / `renderDot` render it for dashboards and audit reports, with counts on repeated edges and sanitized labels.

## [0.3.0] - 2026-08-19

### Added

- **`traceshield` CLI for audit investigation**: `status`, `traces`, `violations`, and `verify` commands load a JSON audit export and let you inspect traces/violations and check hash-chain integrity. Errors are typed (`CliError`); the bin entry lives in `cli-main.ts`.

### Changed

- `TraceShieldExporter` gains a lossless `full` export format that includes complete spans and policy evaluations (the `json` format remains a summary).

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
