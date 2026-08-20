/**
 * traceshield CLI — audit investigation from the command line.
 *
 * Loads recorded audit data from a JSON export (see `TraceShieldExporter`) or
 * an in-memory session, then lets you inspect traces and violations and verify
 * hash-chain integrity.
 *
 * Commands:
 *   traceshield status <export.json>
 *   traceshield traces <export.json> [--agent A] [--status S] [--limit N]
 *   traceshield violations <export.json> [--agent A] [--limit N]
 *   traceshield verify <export.json>
 *
 * The export file is the JSON produced by `TraceShieldExporter` (a bundle with
 * a `traces` array). If omitted or "-", an empty in-memory store is used.
 */

import * as fs from 'node:fs';
import { MemoryStorage } from './storage/memory.js';
import type { Trace, StoredViolation } from './types.js';

export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: number = 1,
  ) {
    super(message);
    this.name = 'CliError';
  }
}

interface CliArgs {
  command: string;
  exportPath: string;
  agent?: string;
  status?: string;
  limit: number;
}

function parseArgs(argv: string[]): CliArgs {
  const args = argv.slice(2);
  const out: CliArgs = {
    command: args[0] ?? 'help',
    exportPath: '-',
    limit: 20,
  };

  const rest: string[] = [];
  for (let i = 1; i < args.length; i++) {
    const a = args[i]!;
    switch (a) {
      case '--agent': case '-a': out.agent = args[++i]; break;
      case '--status': case '-s': out.status = args[++i]; break;
      case '--limit': case '-l': out.limit = Number(args[++i] ?? 20) || 20; break;
      default:
        if (a.startsWith('-')) throw new CliError(`unknown option: ${a}`);
        rest.push(a);
    }
  }

  if (rest.length > 0) out.exportPath = rest[0]!;
  return out;
}

function fail(message: string): never {
  throw new CliError(message);
}

/** Load a JSON audit export into an in-memory store. */
async function loadStore(exportPath: string): Promise<MemoryStorage> {
  const store = new MemoryStorage();
  await store.initialize();

  if (exportPath === '-' || exportPath === '') return store;
  if (!fs.existsSync(exportPath)) fail(`export file not found: ${exportPath}`);

  let raw: string;
  try {
    raw = fs.readFileSync(exportPath, 'utf-8');
  } catch (err) {
    fail(`failed to read ${exportPath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    fail(`invalid JSON in ${exportPath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  const bundle = data as { traces?: Trace[] };
  if (!Array.isArray(bundle.traces)) {
    fail(`export ${exportPath} has no "traces" array (use TraceShieldExporter format)`);
  }

  for (const trace of bundle.traces) {
    if (!trace || typeof trace !== 'object' || !('id' in trace)) continue;
    await store.saveTrace(trace as Trace);
    for (const span of (trace as Trace).spans ?? []) {
      await store.saveSpan(span);
    }
  }
  return store;
}

function truncate(s: string, n: number): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > n ? one.slice(0, n - 1) + '…' : one;
}

// ── Commands ─────────────────────────────────────────────────────────────

async function cmdStatus(args: CliArgs): Promise<number> {
  const store = await loadStore(args.exportPath);
  const traces = await store.queryTraces({});
  const violations = await store.queryViolations({});

  const byStatus: Record<string, number> = {};
  for (const t of traces) byStatus[t.status] = (byStatus[t.status] ?? 0) + 1;

  process.stdout.write(`Audit status\n\n`);
  process.stdout.write(`  traces:    ${traces.length}\n`);
  process.stdout.write(`  violations:${violations.length}\n`);
  if (traces.length > 0) {
    process.stdout.write(`\n  traces by status:\n`);
    for (const [status, count] of Object.entries(byStatus)) {
      process.stdout.write(`    ${(status + ':').padEnd(12)} ${String(count).padStart(4)}\n`);
    }
  }
  return 0;
}

async function cmdTraces(args: CliArgs): Promise<number> {
  const store = await loadStore(args.exportPath);
  const traces = await store.queryTraces({
    agent_id: args.agent,
    status: args.status as Trace['status'],
    limit: args.limit,
  });

  if (traces.length === 0) {
    process.stdout.write('No traces found.\n');
    return 0;
  }

  process.stdout.write(`${traces.length} trace(s)\n\n`);
  for (const t of traces) {
    const id = t.id.slice(0, 8);
    process.stdout.write(
      `  ${id}  ${String(t.status).padEnd(10)} ${String(t.agent_id).padEnd(14)} spans=${t.spans.length} ${truncate(t.started_at, 19)}\n`,
    );
  }
  return 0;
}

async function cmdViolations(args: CliArgs): Promise<number> {
  const store = await loadStore(args.exportPath);
  const traces = await store.queryTraces({ agent_id: args.agent, limit: 10000 });

  // Violations are embedded in spans' policy_evaluations, not stored separately
  const violations: Array<{ rule_id: string; effect: string; policy_name: string; agent_id: string }> = [];
  for (const trace of traces) {
    if (args.agent && trace.agent_id !== args.agent) continue;
    for (const span of trace.spans) {
      for (const eval_ of span.policy_evaluations) {
        if (eval_.result === 'allow') continue;
        violations.push({
          rule_id: eval_.rule_id,
          effect: eval_.result,
          policy_name: eval_.policy_name,
          agent_id: trace.agent_id,
        });
      }
    }
  }

  if (violations.length === 0) {
    process.stdout.write('No violations found.\n');
    return 0;
  }

  process.stdout.write(`${violations.length} violation(s)\n\n`);
  for (const v of violations) {
    process.stdout.write(
      `  ${v.rule_id.padEnd(24)} ${String(v.effect).padEnd(6)} ${v.policy_name} (${v.agent_id})\n`,
    );
  }
  return 0;
}

async function cmdVerify(args: CliArgs): Promise<number> {
  if (args.exportPath === '-' || args.exportPath === '') {
    fail('verify requires an export file path');
  }
  const store = await loadStore(args.exportPath);
  const traces = await store.queryTraces({});
  if (traces.length === 0) {
    process.stdout.write('No traces to verify.\n');
    return 0;
  }

  const { TraceShieldExporter } = await import('./compliance-exporter.js');
  const exporter = new TraceShieldExporter(traces);
  const result = exporter.verify();

  process.stdout.write(`Integrity verification\n\n`);
  process.stdout.write(`  span count:  ${result.spanCount}\n`);
  process.stdout.write(`  integrity:   ${result.integrityValid ? 'VALID ✓' : 'TAMPERED ✗'}\n`);
  for (const error of result.errors) {
    process.stdout.write(`  error: ${error}\n`);
  }
  return 0;
}

function cmdHelp(): number {
  process.stdout.write(`traceshield — audit investigation

Usage:
  traceshield status     <export.json>
  traceshield traces     <export.json> [--agent A] [--status S] [--limit N]
  traceshield violations <export.json> [--agent A] [--limit N]
  traceshield verify     <export.json>

The export file is JSON from TraceShieldExporter (a bundle with a "traces"
array). Use "-" or omit it to inspect an empty in-memory store.
`);
  return 0;
}

export async function main(argv: string[] = process.argv): Promise<number> {
  const args = parseArgs(argv);
  switch (args.command) {
    case 'status': return cmdStatus(args);
    case 'traces': return cmdTraces(args);
    case 'violations': return cmdViolations(args);
    case 'verify': return cmdVerify(args);
    case 'help': case '--help': case '-h': return cmdHelp();
    default:
      throw new CliError(`unknown command: ${args.command} (see 'traceshield help')`);
  }
}
