import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { Server } from 'node:http';
import { AuditDashboard, createDashboard } from '../src/dashboard.js';
import { TraceRecorder } from '../src/trace-recorder.js';

describe('AuditDashboard', () => {
  let recorder: TraceRecorder;
  let dashboard: AuditDashboard;

  beforeEach(() => {
    recorder = new TraceRecorder();
  });

  afterEach(async () => {
    await dashboard?.stop();
  });

  /** Read the ephemeral port the dashboard bound to (config.port = 0). */
  function boundPort(dash: AuditDashboard): number {
    const server = (dash as unknown as { server?: Server }).server;
    if (!server) throw new Error('dashboard server not started');
    const addr = server.address();
    if (addr && typeof addr === 'object') return addr.port;
    throw new Error('unable to resolve bound port');
  }

  it('serves the dashboard HTML at / and /dashboard', async () => {
    dashboard = await createDashboard(recorder, { port: 0 });
    const port = boundPort(dashboard);

    for (const path of ['/', '/dashboard']) {
      const res = await fetch(`http://127.0.0.1:${port}${path}`);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/html');
      expect(await res.text()).toContain('TraceShield Audit Dashboard');
    }
  });

  it('exposes live stats that reflect recorded traces', async () => {
    dashboard = await createDashboard(recorder, { port: 0 });
    const port = boundPort(dashboard);

    const trace = await recorder.startTrace('agent-a');
    recorder.startSpan(trace.id, 'tool_call', 'read_file', { path: '/tmp/a.txt' });
    dashboard.recordTrace(trace);

    const res = await fetch(`http://127.0.0.1:${port}/api/stats`);
    expect(res.status).toBe(200);
    const stats = (await res.json()) as { totalTraces: number; agents: { active: number } };
    expect(stats.totalTraces).toBe(1);
    expect(stats.agents.active).toBe(1);
  });

  it('returns recent traces from /api/traces', async () => {
    dashboard = await createDashboard(recorder, { port: 0 });
    const port = boundPort(dashboard);

    const trace = await recorder.startTrace('agent-b');
    recorder.startSpan(trace.id, 'tool_call', 'list_dir', { path: '/tmp' });
    dashboard.recordTrace(trace);

    const res = await fetch(`http://127.0.0.1:${port}/api/traces?limit=5`);
    expect(res.status).toBe(200);
    const traces = (await res.json()) as Array<{ agent_id: string }>;
    expect(traces).toHaveLength(1);
    expect(traces[0].agent_id).toBe('agent-b');
  });

  it('returns 404 for unknown routes', async () => {
    dashboard = await createDashboard(recorder, { port: 0 });
    const port = boundPort(dashboard);

    const res = await fetch(`http://127.0.0.1:${port}/api/nope`);
    expect(res.status).toBe(404);
  });

  it('stop() closes the HTTP server', async () => {
    dashboard = await createDashboard(recorder, { port: 0 });
    const port = boundPort(dashboard);

    await dashboard.stop();
    await expect(fetch(`http://127.0.0.1:${port}/api/stats`)).rejects.toThrow();
  });
});
