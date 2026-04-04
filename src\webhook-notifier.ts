/**
 * Violation Webhook Notifier — send real-time alerts when policy violations occur.
 *
 * When an agent triggers a policy violation (blocked, flagged, or throttled),
 * this notifier sends a structured webhook payload to one or more external endpoints.
 *
 * Supported destinations:
 * - Generic HTTP POST webhook (Slack-compatible, PagerDuty, custom endpoints)
 * - Slack incoming webhook (formatted Slack message block)
 *
 * Usage:
 *   import { WebhookNotifier } from 'traceshield';
 *
 *   const notifier = new WebhookNotifier();
 *
 *   // Add webhook endpoints
 *   notifier.addEndpoint({
 *     url: 'https://hooks.slack.com/services/xxx',
 *     type: 'slack',
 *     events: ['blocked', 'flagged'],
 *   });
 *
 *   notifier.addEndpoint({
 *     url: 'https://your-endpoint.com/audit',
 *     type: 'generic',
 *     events: ['blocked'],
 *     headers: { 'Authorization': 'Bearer your-token' },
 *   });
 *
 *   // Hook into the runtime guard
 *   guard.on('violation', (violation) => notifier.notify(violation));
 */

import type { StoredViolation } from './types.js';

export type WebhookEventType = 'blocked' | 'flagged' | 'throttled' | 'allowed';
export type WebhookType = 'generic' | 'slack';

export interface WebhookEndpoint {
  /** Unique identifier for this endpoint */
  id: string;
  /** Destination URL */
  url: string;
  /** Type of webhook payload */
  type: WebhookType;
  /** Which violation events to send (default: all) */
  events?: WebhookEventType[];
  /** Custom HTTP headers (for auth tokens, etc.) */
  headers?: Record<string, string>;
  /** Retry count on failure (default: 3) */
  retries?: number;
  /** Timeout in ms (default: 5000) */
  timeout?: number;
  /** Whether this endpoint is enabled */
  enabled?: boolean;
}

export interface WebhookPayload {
  /** TraceShield event type */
  event: WebhookEventType;
  /** When the event occurred */
  timestamp: string;
  /** Violation details (null for allowed events) */
  violation: StoredViolation | null;
  /** Summary for quick scanning */
  summary: {
    outcome: WebhookEventType;
    agentId: string;
    actionType: string;
    policyName: string | null;
    message: string;
  };
}

export class WebhookNotifier {
  private endpoints: Map<string, WebhookEndpoint> = new Map();
  private idCounter = 0;

  /**
   * Add a webhook endpoint to notify on policy violations.
   *
   * @param config - Webhook configuration
   * @returns The endpoint ID (for removal later)
   */
  addEndpoint(config: Omit<WebhookEndpoint, 'id'>): string {
    const id = config.id ?? `webhook-${++this.idCounter}`;
    this.endpoints.set(id, {
      ...config,
      id,
      events: config.events ?? ['blocked', 'flagged', 'throttled'],
      retries: config.retries ?? 3,
      timeout: config.timeout ?? 5000,
      enabled: config.enabled ?? true,
    });
    return id;
  }

  /**
   * Remove a webhook endpoint by ID.
   */
  removeEndpoint(id: string): boolean {
    return this.endpoints.delete(id);
  }

  /**
   * List all registered webhook endpoints.
   */
  listEndpoints(): WebhookEndpoint[] {
    return Array.from(this.endpoints.values());
  }

  /**
   * Enable or disable an endpoint.
   */
  setEnabled(id: string, enabled: boolean): boolean {
    const endpoint = this.endpoints.get(id);
    if (!endpoint) return false;
    endpoint.enabled = enabled;
    return true;
  }

  /**
   * Send notification to all matching endpoints.
   *
   * Failures are logged but do not throw — webhook delivery is best-effort.
   */
  async notify(violation: StoredViolation): Promise<void> {
    const event: WebhookEventType = violation.outcome as WebhookEventType;
    const payload = this._buildPayload(violation);

    const matching = Array.from(this.endpoints.values()).filter(
      (ep) => ep.enabled && (ep.events ?? []).includes(event),
    );

    await Promise.allSettled(
      matching.map((ep) => this._send(ep, payload)),
    );
  }

  /**
   * Build the webhook payload from a violation.
   */
  private _buildPayload(violation: StoredViolation): WebhookPayload {
    return {
      event: violation.outcome as WebhookEventType,
      timestamp: new Date().toISOString(),
      violation,
      summary: {
        outcome: violation.outcome,
        agentId: violation.agentId,
        actionType: violation.actionType,
        policyName: violation.policyName ?? null,
        message: violation.message ?? `Policy ${violation.policyName ?? 'unknown'} violation`,
      },
    };
  }

  /**
   * Send a single webhook with retry logic.
   */
  private async _send(endpoint: WebhookEndpoint, payload: WebhookPayload): Promise<void> {
    const body = endpoint.type === 'slack'
      ? this._slackPayload(payload)
      : JSON.stringify(payload);

    for (let attempt = 0; attempt <= (endpoint.retries ?? 3); attempt++) {
      try {
        await this._httpPost(endpoint, body);
        return;
      } catch (err) {
        if (attempt === endpoint.retries!) {
          console.error(
            `[WebhookNotifier] Failed to deliver to ${endpoint.url} after ${attempt + 1} attempts:`,
            err,
          );
        } else {
          // Exponential backoff
          await new Promise((r) => setTimeout(r, 2 ** attempt * 100));
        }
      }
    }
  }

  private async _httpPost(endpoint: WebhookEndpoint, body: string): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), endpoint.timeout ?? 5000);

    try {
      const response = await fetch(endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': endpoint.type === 'slack' ? 'application/json' : 'application/json',
          ...endpoint.headers,
        },
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Build a Slack-compatible message block payload.
   */
  private _slackPayload(payload: WebhookPayload): string {
    const { summary, violation } = payload;
    const emoji = summary.outcome === 'blocked' ? '🚫' : summary.outcome === 'flagged' ? '⚠️' : '⏱️';
    const color = summary.outcome === 'blocked' ? '#dc3545' : summary.outcome === 'flagged' ? '#ffc107' : '#17a2b8';

    const fields = [
      { type: 'mrkdwn', text: `*Agent*\n${summary.agentId}` },
      { type: 'mrkdwn', text: `*Action*\n\`${summary.actionType}\`` },
    ];

    if (summary.policyName) {
      fields.push({ type: 'mrkdwn', text: `*Policy*\n${summary.policyName}` });
    }

    return JSON.stringify({
      attachments: [
        {
          color,
          blocks: [
            {
              type: 'header',
              text: { type: 'plain_text', text: `${emoji} TraceShield Violation: ${summary.outcome.toUpperCase()}` },
            },
            {
              type: 'section',
              fields,
            },
            {
              type: 'section',
              text: { type: 'mrkdwn', text: `*Message*\n${summary.message}` },
            },
            {
              type: 'context',
              elements: [
                { type: 'mrkdwn', text: `Time: ${new Date(payload.timestamp).toLocaleString()}` },
                { type: 'mrkdwn', text: `Trace ID: \`${violation?.traceId ?? 'N/A'}\`` },
              ],
            },
          ],
        },
      ],
    });
  }
}
