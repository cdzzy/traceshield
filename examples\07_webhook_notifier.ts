/**
 * Webhook Notifier Example — send real-time violation alerts to external systems.
 *
 * When a policy violation occurs, TraceShield can notify external systems via webhooks.
 * Supported: Slack, PagerDuty, custom HTTP endpoints.
 *
 * Reference: See src/webhook-notifier.ts for full API.
 */

import { WebhookNotifier } from '../src/webhook-notifier';
import type { StoredViolation } from '../src/types';

// Mock violation for demonstration
const mockViolation: StoredViolation = {
  traceId: 'tr-abc123',
  agentId: 'data-processor',
  actionType: 'data-read',
  outcome: 'blocked',
  policyName: 'pii-access-control',
  message: 'PII data access requires human approval',
  timestamp: new Date().toISOString(),
  agentVersion: '1.0.0',
  sessionId: 'sess-001',
  userId: 'u-456',
  metadata: {},
  spans: [],
  prevHash: 'xyz789',
  hash: 'abc123',
};


function example_generic_webhook() {
  const notifier = new WebhookNotifier();

  // Add a generic HTTP endpoint
  notifier.addEndpoint({
    id: 'audit-service',
    url: 'https://your-audit-service.com/webhook/traceshield',
    type: 'generic',
    events: ['blocked', 'flagged'],
    headers: {
      'Authorization': 'Bearer your-api-token',
      'X-Source': 'traceshield',
    },
    retries: 3,
    timeout: 5000,
  });

  console.log('Generic webhook registered:', notifier.listEndpoints());
}


async function example_slack_webhook() {
  const notifier = new WebhookNotifier();

  // Add a Slack incoming webhook
  notifier.addEndpoint({
    id: 'slack-alerts',
    url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
    type: 'slack',
    events: ['blocked'],  // Only notify for blocked actions
  });

  // Simulate notifying on a violation
  await notifier.notify(mockViolation);
  console.log('Slack notification sent!');
}


async function example_multi_endpoint() {
  const notifier = new WebhookNotifier();

  // Slack for quick alerts
  notifier.addEndpoint({
    id: 'slack',
    url: 'https://hooks.slack.com/services/xxx/yyy/zzz',
    type: 'slack',
    events: ['blocked'],
  });

  // PagerDuty for critical violations
  notifier.addEndpoint({
    id: 'pagerduty',
    url: 'https://events.pagerduty.com/v2/enqueue',
    type: 'generic',
    events: ['blocked'],
    headers: { 'Content-Type': 'application/json' },
  });

  // Audit log endpoint for all events
  notifier.addEndpoint({
    id: 'audit-log',
    url: 'https://audit.internal.com/traceshield',
    type: 'generic',
    events: ['blocked', 'flagged', 'throttled', 'allowed'],
  });

  console.log('Endpoints:', notifier.listEndpoints().map(e => e.id));

  // Simulate violation
  await notifier.notify(mockViolation);
  console.log('All notifications sent!');
}


if (require.main === module) {
  console.log('=== Webhook Notifier Examples ===\n');

  example_generic_webhook();
  console.log();

  example_slack_webhook().catch(console.error);
}
