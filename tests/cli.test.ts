/**
 * Tests for the traceshield CLI (v0.3.0).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { main, CliError } from '../src/cli.js';
import { MemoryStorage } from '../src/storage/memory.js';
import { computeSpanHash } from '../src/hash-chain.js';
import type { Trace, Span } from '../src/types.js';

function makeSpan(overrides: Partial<Span> = {}): Span {
  return {
    id: 's1',
    trace_id: 't1',
    sequence: 0,
    action_type: 'tool_call',
    name: 'search',
    input: {},
    started_at: new Date().toISOString(),
    status: 'completed',
    policy_evaluations: [],
    hash: 'abc',
    previous_hash: '000',
    ...overrides,
  };
}

function capture(fn: () => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  const chunks: string[] = [];
  const errChunks: string[] = [];
  const origWrite = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);

  (process.stdout as unknown as { write: unknown }).write = (chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
    return true;
  };
  (process.stderr as unknown as { write: unknown }).write = (chunk: string | Uint8Array) => {
    errChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
    return true;
  };

  function restore(): void {
    (process.stdout as unknown as { write: unknown }).write = origWrite;
    (process.stderr as unknown as { write: unknown }).write = origErr;
  }

  return fn().then(
    code => { restore(); return { code, out: chunks.join(''), err: errChunks.join('') }; },
    err => {
      restore();
      if (err instanceof CliError) {
        errChunks.unshift(`traceshield: ${err.message}\n`);
        return { code: err.exitCode, out: chunks.join(''), err: errChunks.join('') };
      }
      throw err;
    },
  );
}

describe('traceshield CLI', () => {
  let dir: string;
  let exportPath: string;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'traceshield-cli-'));
    exportPath = path.join(dir, 'audit.json');

    const store = new MemoryStorage();
    await store.initialize();

    const goodSpan = makeSpan();
    goodSpan.hash = computeSpanHash(goodSpan);
    const goodTrace: Trace = {
      id: 't1', agent_id: 'agent-1', started_at: new Date().toISOString(),
      status: 'completed', spans: [goodSpan], integrity_hash: 'x',
    };
    await store.saveTrace(goodTrace);
    await store.saveSpan(goodSpan);

    const badSpan = makeSpan({
      id: 's2', trace_id: 't2', sequence: 0, name: 'export',
      status: 'failed',
      policy_evaluations: [{
        policy_name: 'no-export', rule_id: 'r1', effect: 'deny', result: 'deny',
        message: 'blocked', evaluated_at: new Date().toISOString(),
      }],
    });
    badSpan.hash = computeSpanHash(badSpan);
    const badTrace: Trace = {
      id: 't2', agent_id: 'agent-1', started_at: new Date().toISOString(),
      status: 'failed', spans: [badSpan], integrity_hash: 'y',
    };
    await store.saveTrace(badTrace);
    await store.saveSpan(badSpan);

    const { TraceShieldExporter } = await import('../src/compliance-exporter.js');
    const exporter = new TraceShieldExporter([goodTrace, badTrace]);
    fs.writeFileSync(exportPath, exporter.export({ format: 'full' }));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('status reports traces and violations', async () => {
    const { code, out } = await capture(() => main(['node', 'traceshield', 'status', exportPath]));
    expect(code).toBe(0);
    expect(out).toContain('traces:');
    expect(out).toContain('violations:');
  });

  it('traces lists entries', async () => {
    const { code, out } = await capture(() => main(['node', 'traceshield', 'traces', exportPath]));
    expect(code).toBe(0);
    expect(out).toContain('trace(s)');
    expect(out).toContain('agent-1');
  });

  it('traces filters by status', async () => {
    const { out } = await capture(() => main(['node', 'traceshield', 'traces', exportPath, '--status', 'failed']));
    expect(out).toContain('failed');
    expect(out).not.toContain('completed');
  });

  it('violations lists entries', async () => {
    const { code, out } = await capture(() => main(['node', 'traceshield', 'violations', exportPath]));
    expect(code).toBe(0);
    expect(out).toContain('no-export');
    expect(out).toContain('r1');
  });

  it('verify validates a clean export', async () => {
    const { code, out } = await capture(() => main(['node', 'traceshield', 'verify', exportPath]));
    expect(code).toBe(0);
    expect(out).toContain('VALID');
  });

  it('verify detects tampering', async () => {
    const tampered = path.join(dir, 'tampered.json');
    const data = JSON.parse(fs.readFileSync(exportPath, 'utf-8'));
    data.traces[0].spans[0].input = { hacked: true };
    fs.writeFileSync(tampered, JSON.stringify(data));
    const { code, out } = await capture(() => main(['node', 'traceshield', 'verify', tampered]));
    expect(code).toBe(0);
    expect(out).toContain('TAMPERED');
  });

  it('help exits cleanly', async () => {
    const { code, out } = await capture(() => main(['node', 'traceshield', 'help']));
    expect(code).toBe(0);
    expect(out).toContain('Usage:');
  });

  it('missing export file fails', async () => {
    const { code, err } = await capture(() => main(['node', 'traceshield', 'status', 'nope.json']));
    expect(code).toBe(1);
    expect(err).toContain('not found');
  });
});
