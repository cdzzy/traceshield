# traceshield × OWASP Agentic AI Top 10 (ASI01–ASI10)

This document maps the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/) —
risk IDs **ASI01–ASI10:2026**, published Dec 9 2025 by the OWASP GenAI Security Project's
Agentic Security Initiative — onto traceshield's current capabilities and roadmap.

Status legend for the matrix:

- ✅ **shipped** — capability exists in the current release (module referenced)
- 🟡 **partial** — capability covers a common subset of the risk
- 📋 **planned** — on the roadmap, not yet implemented

## Coverage matrix

| Risk | Description | Detection | Blocking | Audit | Planning |
|------|-------------|-----------|----------|-------|----------|
| ASI01 | Agent Goal Hijack | ✅ `injection-detector.ts` — pattern + heuristic layers on every input | ✅ `runtime-guard.ts` — inject before execution, `block` on detection | ✅ `trace-recorder.ts` — input, spans, and policy outcomes hash-chained | 📋 Provenance tags separating trusted system/goal content from untrusted tool output |
| ASI02 | Tool Misuse & Exploitation | ✅ `policy-engine.ts` — match rules on action type, resource, tags | ✅ `runtime-guard.ts` + YAML `on_violation: block` / `throttle` / rate limits | ✅ `trace-recorder.ts` — per-span `policy_evaluations` with rule IDs | 📋 Schema-level argument validation against per-tool allowlists |
| ASI03 | Agent Identity & Privilege Abuse | ✅ `attribution-analyzer.ts` / `attribution-graph.ts` — who/what triggered each action | ✅ Policy rules with `require: { approval: true }` human gates | ✅ Full attribution chain per trace (`causalChain`, user, session) | 📋 Per-agent short-lived task-scoped credentials |
| ASI04 | Agentic Supply Chain Compromise | ✅ `traceshield scan` CLI — poisoned tool descriptions, hidden Unicode, dangerous permission combos in MCP configs | ✅ `policy-gitops.ts` — `validatePolicySet` CI gate for policy changes | ✅ Config scan reports are JSON-exportable for review trails | 📋 Hash-pinning and provenance verification for MCP servers and skills before load |
| ASI05 | Unexpected Code Execution (RCE) | ✅ Policy match on `action: 'command-exec'` style rules; `scan` flags shell-wrapper MCP servers | ✅ `runtime-guard.ts` intercepts before execution; allowlist/deny rules | ✅ Every executed action recorded with status and hash | 📋 Sandbox execution profiles (non-root, no-network) as first-class policy targets |
| ASI06 | Memory & Context Poisoning | ✅ `injection-detector.ts` can be applied to content before it is written to memory | 🟡 Block at write time requires wiring the detector into the memory adapter | ✅ Writes are traced and attributable | 📋 Trust-tagged memory entries; low-trust sources rejected from durable memory |
| ASI07 | Insecure Inter-Agent Communication | ✅ `compliance-exporter.ts` — integrity verification detects tampering | ✅ Hash-chain breaks are surfaced by `traceshield verify` | ✅ SHA-256 hash chain over all spans (`hash-chain.ts`) | 📋 Signed agent-to-agent messages with replay protection |
| ASI08 | Cascading Agent Failures | ✅ `behavior-baseline.ts` — per-agent anomaly detection on drift | ✅ `throttle` effects and per-minute/per-agent rate-limit rules | ✅ `attribution-graph.ts` renders the causal chain of any failure | 📋 Circuit breakers to contain blast radius across agent networks |
| ASI09 | Human-Agent Trust Exploitation | ✅ `red-team.ts` — adversarial scenarios including manipulation attempts | ✅ `require: { approval: true }` forces independent human confirmation | ✅ Approval decisions recorded as policy evaluations | 📋 Risk cues and provenance surfaced in approval workflows |
| ASI10 | Rogue Agents | ✅ `behavior-baseline.ts` — baseline deviation per agent; `red-team.ts` collusion scenarios | ✅ Policy `block` + webhook kill notifications (`webhook-notifier.ts`) | ✅ Complete per-agent action history with tamper evidence | 📋 Continuous baseline monitoring with auto-quarantine playbooks |

## How the capabilities map to modules

### Detection

- **`src/injection-detector.ts`** — multi-layer prompt-injection detection
  (instruction override, role redefinition, system-prompt extraction, special-token
  injection) applied to inputs and reusable for memory writes (ASI01, ASI06, ASI09).
- **`src/policy-engine.ts`** — declarative rules (YAML or code) that match actions on
  type, resource, tags, and metadata (ASI02, ASI03, ASI05).
- **`src/behavior-baseline.ts`** — learns per-agent behavior and flags anomalies
  (ASI08, ASI10).
- **`src/mcp-scanner.ts`** — `traceshield scan` inspects MCP client configuration files
  (Claude Desktop `claude_desktop_config.json`, project `.mcp.json`, `.cursor/mcp.json`,
  `.vscode/mcp.json`) for:
  - instruction-override phrases in tool descriptions (ASI01, ASI04),
  - hidden Unicode characters (zero-width, bidi controls) used to smuggle instructions
    past visual review (ASI01, ASI04),
  - dangerous permission combos: permissive execution flags, shell wrappers with
    secrets in the environment, wildcard tool allowlists, root filesystem mounts
    (ASI02, ASI03, ASI05).

### Blocking

- **`src/runtime-guard.ts`** — synchronous interception of actions before execution;
  policy outcomes (`allow`, `deny`, `flag`, `throttle`) are enforced at the call site
  (ASI01, ASI02, ASI05, ASI09, ASI10).
- **`src/policy-gitops.ts`** — `validatePolicySet` as a CI gate and `diffPolicySets`
  for PR review, so policy itself cannot be weakened silently (ASI04).

### Audit

- **`src/trace-recorder.ts` + `src/hash-chain.ts`** — every action recorded as a span,
  chained by SHA-256 hashes; tampering is detectable via `traceshield verify`
  (ASI07, and the audit column of every other row).
- **`src/attribution-analyzer.ts` / `src/attribution-graph.ts`** — root-cause traces
  and multi-agent causal graphs (ASI03, ASI08).
- **`src/compliance-exporter.ts` / `src/compliance-reports.ts` / `src/zk-compliance.ts`** —
  evidence packs (JSON-LD/CEF, SOC2/GDPR templates, privacy-preserving proofs) for
  regulators and incident review.

## Planning backlog

Consolidated, unimplemented mitigations referenced in the matrix:

1. **Provenance-tagged context** — mark trusted system/goal content vs untrusted tool
   output end-to-end (ASI01, ASI06).
2. **Tool argument schema validation** — validate tool name + arguments against
   per-tool allowlists before execution (ASI02, ASI05).
3. **Per-agent task-scoped credentials** — short-lived tokens bound to verified agent
   identity with continuous re-authorization (ASI03).
4. **MCP/skill provenance pinning** — verify immutable hashes and upstream trust
   before loading runtime components (ASI04).
5. **Sandbox execution profiles** — first-class non-root/no-network sandbox targets in
   policy (ASI05).
6. **Trust-tagged durable memory** — reject low-trust sources from long-term memory
   writes (ASI06).
7. **Signed inter-agent messaging** — mutual auth, message signing, replay protection
   (ASI07).
8. **Circuit breakers** — cross-agent containment once anomalies cascade (ASI08).
9. **Approval risk cues** — surface provenance and risk indicators inside human
   approval flows (ASI09).
10. **Auto-quarantine playbooks** — kill switch + credential revocation when baseline
    deviation crosses critical thresholds (ASI10).

## References

- OWASP GenAI Security Project — *Top 10 for Agentic Applications (2026)*, ASI01–ASI10
  <https://genai.owasp.org/>
- OWASP Agentic AI Initiative — *Agentic AI: Threats and Mitigations v1.0* (T1–T15 taxonomy)
- traceshield CLI: `traceshield scan [--json] [paths...]` — exit code `1` when any
  high/critical finding is present.
