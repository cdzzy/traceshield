/**
 * TraceShield Real-Time Audit Dashboard
 * 
 * Provides a web-based dashboard for monitoring agent traces,
 * policy violations, and audit logs in real-time.
 * 
 * Reference: Inspired by agentconfig's monitoring dashboard and
 * modern observability platforms.
 * 
 * Usage:
 *   const dashboard = new AuditDashboard(recorder, { port: 8080 });
 *   await dashboard.start();
 *   // Dashboard available at http://localhost:8080
 */

import { TraceRecorder } from './trace-recorder.js';
import { PolicyEngine } from './policy-engine.js';
import type { Trace, PolicyViolation, AuditStats } from './types.js';

export interface DashboardConfig {
  port?: number;
  host?: string;
  refreshInterval?: number;
  maxTraces?: number;
  enableWebSocket?: boolean;
}

export interface DashboardStats {
  totalTraces: number;
  violations: {
    total: number;
    blocked: number;
    flagged: number;
    byRule: Record<string, number>;
  };
  agents: {
    total: number;
    active: number;
    topAgents: Array<{ agentId: string; traceCount: number }>;
  };
  actions: {
    byType: Record<string, number>;
    recent: Trace[];
  };
  timeline: Array<{
    timestamp: number;
    traceCount: number;
    violationCount: number;
  }>;
}

/**
 * Simple HTTP server for the audit dashboard
 */
export class AuditDashboard {
  private recorder: TraceRecorder;
  private policyEngine?: PolicyEngine;
  private config: Required<DashboardConfig>;
  private server?: any;
  private stats: DashboardStats;
  private updateInterval?: NodeJS.Timeout;

  constructor(
    recorder: TraceRecorder,
    config: DashboardConfig = {},
    policyEngine?: PolicyEngine
  ) {
    this.recorder = recorder;
    this.policyEngine = policyEngine;
    this.config = {
      port: config.port || 8080,
      host: config.host || '0.0.0.0',
      refreshInterval: config.refreshInterval || 5000,
      maxTraces: config.maxTraces || 1000,
      enableWebSocket: config.enableWebSocket ?? false,
    };

    this.stats = this.initializeStats();
  }

  private initializeStats(): DashboardStats {
    return {
      totalTraces: 0,
      violations: {
        total: 0,
        blocked: 0,
        flagged: 0,
        byRule: {},
      },
      agents: {
        total: 0,
        active: 0,
        topAgents: [],
      },
      actions: {
        byType: {},
        recent: [],
      },
      timeline: [],
    };
  }

  /**
   * Start the dashboard server
   */
  async start(): Promise<void> {
    // Dynamic import to avoid Node.js-specific code in browser bundles
    const http = await import('http');
    const url = await import('url');

    this.server = http.createServer((req: any, res: any) => {
      this.handleRequest(req, res);
    });

    return new Promise((resolve, reject) => {
      this.server!.listen(this.config.port, this.config.host, () => {
        console.log(`🔍 TraceShield Dashboard running at http://${this.config.host}:${this.config.port}`);
        this.startStatsUpdate();
        resolve();
      });

      this.server!.on('error', reject);
    });
  }

  /**
   * Stop the dashboard server
   */
  async stop(): Promise<void> {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
    }

    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => {
          console.log('Dashboard server stopped');
          resolve();
        });
      });
    }
  }

  /**
   * Handle HTTP requests
   */
  private handleRequest(req: any, res: any): void {
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    // Route handling
    if (pathname === '/' || pathname === '/dashboard') {
      this.serveDashboard(res);
    } else if (pathname === '/api/stats') {
      this.serveStats(res);
    } else if (pathname === '/api/traces') {
      this.serveTraces(res, parsedUrl.searchParams);
    } else if (pathname === '/api/violations') {
      this.serveViolations(res);
    } else if (pathname === '/api/agents') {
      this.serveAgents(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    }
  }

  /**
   * Serve the main dashboard HTML
   */
  private serveDashboard(res: any): void {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraceShield Audit Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid #334155;
        }
        .header h1 {
            font-size: 1.5rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .header .shield { color: #10b981; }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: #1e293b;
            border-radius: 0.5rem;
            padding: 1.5rem;
            border: 1px solid #334155;
        }
        .stat-card h3 {
            font-size: 0.875rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: #f8fafc;
        }
        .stat-value.success { color: #10b981; }
        .stat-value.warning { color: #f59e0b; }
        .stat-value.error { color: #ef4444; }
        .section {
            background: #1e293b;
            border-radius: 0.5rem;
            padding: 1.5rem;
            border: 1px solid #334155;
            margin-bottom: 1.5rem;
        }
        .section h2 {
            font-size: 1.125rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            text-align: left;
            padding: 0.75rem;
            border-bottom: 1px solid #334155;
        }
        th {
            color: #94a3b8;
            font-weight: 500;
            font-size: 0.875rem;
        }
        tr:hover { background: #334155; }
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .badge-success { background: #064e3b; color: #10b981; }
        .badge-warning { background: #78350f; color: #f59e0b; }
        .badge-error { background: #7f1d1d; color: #ef4444; }
        .timestamp { color: #64748b; font-size: 0.875rem; }
        .refresh-indicator {
            position: fixed;
            top: 1rem;
            right: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            color: #64748b;
        }
        .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #10b981;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1><span class="shield">🛡️</span> TraceShield Audit Dashboard</h1>
    </div>
    
    <div class="refresh-indicator">
        <span class="dot"></span>
        <span>Live</span>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Traces</h3>
                <div class="stat-value" id="total-traces">-</div>
            </div>
            <div class="stat-card">
                <h3>Active Agents</h3>
                <div class="stat-value success" id="active-agents">-</div>
            </div>
            <div class="stat-card">
                <h3>Violations</h3>
                <div class="stat-value warning" id="total-violations">-</div>
            </div>
            <div class="stat-card">
                <h3>Blocked Actions</h3>
                <div class="stat-value error" id="blocked-actions">-</div>
            </div>
        </div>

        <div class="section">
            <h2>🚨 Recent Violations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Agent</th>
                        <th>Action</th>
                        <th>Rule</th>
                        <th>Outcome</th>
                    </tr>
                </thead>
                <tbody id="violations-table">
                    <tr><td colspan="5">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>📊 Recent Traces</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Agent</th>
                        <th>Action</th>
                        <th>Resource</th>
                        <th>Policy</th>
                    </tr>
                </thead>
                <tbody id="traces-table">
                    <tr><td colspan="5">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>🤖 Top Agents</h2>
            <table>
                <thead>
                    <tr>
                        <th>Agent ID</th>
                        <th>Trace Count</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="agents-table">
                    <tr><td colspan="3">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                document.getElementById('total-traces').textContent = data.totalTraces.toLocaleString();
                document.getElementById('active-agents').textContent = data.agents.active;
                document.getElementById('total-violations').textContent = data.violations.total;
                document.getElementById('blocked-actions').textContent = data.violations.blocked;
            } catch (e) {
                console.error('Failed to fetch stats:', e);
            }
        }

        async function fetchViolations() {
            try {
                const res = await fetch('/api/violations');
                const data = await res.json();
                const tbody = document.getElementById('violations-table');
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#64748b">No violations found</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.slice(0, 10).map(v => \`
                    <tr>
                        <td class="timestamp">\${new Date(v.timestamp).toLocaleTimeString()}</td>
                        <td>\${v.agentId}</td>
                        <td>\${v.action}</td>
                        <td>\${v.rule}</td>
                        <td><span class="badge badge-\${v.outcome === 'blocked' ? 'error' : 'warning'}">\${v.outcome}</span></td>
                    </tr>
                \`).join('');
            } catch (e) {
                console.error('Failed to fetch violations:', e);
            }
        }

        async function fetchTraces() {
            try {
                const res = await fetch('/api/traces?limit=10');
                const data = await res.json();
                const tbody = document.getElementById('traces-table');
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#64748b">No traces found</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.map(t => \`
                    <tr>
                        <td class="timestamp">\${new Date(t.timestamp).toLocaleTimeString()}</td>
                        <td>\${t.agentId}</td>
                        <td>\${t.action}</td>
                        <td>\${t.resource || '-'}</td>
                        <td><span class="badge badge-\${t.policyOutcome === 'allowed' ? 'success' : t.policyOutcome === 'blocked' ? 'error' : 'warning'}">\${t.policyOutcome}</span></td>
                    </tr>
                \`).join('');
            } catch (e) {
                console.error('Failed to fetch traces:', e);
            }
        }

        async function fetchAgents() {
            try {
                const res = await fetch('/api/agents');
                const data = await res.json();
                const tbody = document.getElementById('agents-table');
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#64748b">No agents found</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.map(a => \`
                    <tr>
                        <td>\${a.agentId}</td>
                        <td>\${a.traceCount}</td>
                        <td><span class="badge badge-success">Active</span></td>
                    </tr>
                \`).join('');
            } catch (e) {
                console.error('Failed to fetch agents:', e);
            }
        }

        function updateAll() {
            fetchStats();
            fetchViolations();
            fetchTraces();
            fetchAgents();
        }

        // Initial load
        updateAll();
        
        // Refresh every 5 seconds
        setInterval(updateAll, 5000);
    </script>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  }

  /**
   * Serve stats API
   */
  private serveStats(res: any): void {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(this.stats));
  }

  /**
   * Serve traces API
   */
  private serveTraces(res: any, params: URLSearchParams): void {
    const limit = parseInt(params.get('limit') || '100', 10);
    
    // Get recent traces from storage (simplified)
    const traces = this.stats.actions.recent.slice(0, limit);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(traces));
  }

  /**
   * Serve violations API
   */
  private serveViolations(res: any): void {
    // This would query the policy engine for violations
    const violations: any[] = [];
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(violations));
  }

  /**
   * Serve agents API
   */
  private serveAgents(res: any): void {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(this.stats.agents.topAgents));
  }

  /**
   * Start periodic stats updates
   */
  private startStatsUpdate(): void {
    this.updateInterval = setInterval(() => {
      this.updateStats();
    }, this.config.refreshInterval);
  }

  /**
   * Update dashboard statistics
   */
  private updateStats(): void {
    // In a real implementation, this would query the storage backend
    // For now, we maintain simplified stats
    
    // Update timeline
    const now = Date.now();
    this.stats.timeline.push({
      timestamp: now,
      traceCount: this.stats.totalTraces,
      violationCount: this.stats.violations.total,
    });

    // Keep only last 100 timeline points
    if (this.stats.timeline.length > 100) {
      this.stats.timeline = this.stats.timeline.slice(-100);
    }
  }

  /**
   * Record a new trace (called by TraceRecorder)
   */
  recordTrace(trace: Trace): void {
    this.stats.totalTraces++;
    
    // Update action counts
    this.stats.actions.byType[trace.action] = 
      (this.stats.actions.byType[trace.action] || 0) + 1;
    
    // Add to recent traces
    this.stats.actions.recent.unshift(trace);
    if (this.stats.actions.recent.length > this.config.maxTraces) {
      this.stats.actions.recent.pop();
    }

    // Update agent stats
    const agentIndex = this.stats.agents.topAgents.findIndex(
      a => a.agentId === trace.agentId
    );
    if (agentIndex >= 0) {
      this.stats.agents.topAgents[agentIndex].traceCount++;
    } else {
      this.stats.agents.topAgents.push({
        agentId: trace.agentId,
        traceCount: 1,
      });
    }

    // Sort by trace count
    this.stats.agents.topAgents.sort((a, b) => b.traceCount - a.traceCount);
    this.stats.agents.total = this.stats.agents.topAgents.length;
    this.stats.agents.active = this.stats.agents.topAgents.filter(
      a => a.traceCount > 0
    ).length;
  }

  /**
   * Record a policy violation
   */
  recordViolation(violation: PolicyViolation): void {
    this.stats.violations.total++;
    
    if (violation.outcome === 'blocked') {
      this.stats.violations.blocked++;
    } else if (violation.outcome === 'flagged') {
      this.stats.violations.flagged++;
    }

    // Update by-rule counts
    const ruleName = violation.rule || 'unknown';
    this.stats.violations.byRule[ruleName] = 
      (this.stats.violations.byRule[ruleName] || 0) + 1;
  }
}

/**
 * Create and start a dashboard
 */
export async function createDashboard(
  recorder: TraceRecorder,
  config?: DashboardConfig,
  policyEngine?: PolicyEngine
): Promise<AuditDashboard> {
  const dashboard = new AuditDashboard(recorder, config, policyEngine);
  await dashboard.start();
  return dashboard;
}
