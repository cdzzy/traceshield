/**
 * TraceShield - Basic Usage Example
 *
 * Demonstrates:
 * 1. Creating a TraceShield instance with inline policies
 * 2. Using the RuntimeGuard to wrap agent actions
 * 3. Policy enforcement (deny + warn)
 * 4. Trace recording and integrity verification
 * 5. Failure attribution analysis
 */

import {
  TraceShield,
  PolicyViolationError,
  type PolicySet,
} from '../src/index.js';

// ============================================================
// Step 1: Define policies as structured data
// ============================================================

const policies: PolicySet = {
  version: '1.0',
  policies: [
    {
      name: 'tool-restrictions',
      description: 'Restrict dangerous tool calls',
      rules: [
        {
          id: 'block-delete',
          action: 'tool_call',
          condition: {
            tool_name: { pattern: '^delete_' },
          },
          effect: 'deny',
          message: 'Delete operations are not allowed',
        },
        {
          id: 'warn-external-calls',
          action: 'tool_call',
          condition: {
            tool_name: { pattern: '^(http_|fetch_|curl_)' },
          },
          effect: 'warn',
          message: 'External HTTP calls should be reviewed',
        },
      ],
    },
    {
      name: 'output-safety',
      description: 'Check agent outputs for safety',
      rules: [
        {
          id: 'no-pii-in-output',
          action: '*',
          condition: {
            output_contains: ['SSN', 'social security number'],
          },
          effect: 'deny',
          message: 'Output must not contain PII',
        },
      ],
    },
  ],
};

// ============================================================
// Step 2: Create TraceShield instance
// ============================================================

const shield = new TraceShield({
  policies,
  storage: { type: 'memory' },
});

// ============================================================
// Step 3: Simulate an agent workflow
// ============================================================

async function runAgent() {
  const guard = shield.createGuard({
    agentId: 'demo-agent',
    sessionId: 'session-001',
    metadata: { user: 'demo-user' },
  });

  console.log('--- TraceShield Basic Usage Example ---\n');

  // Successful tool call
  try {
    const result = await guard.execute(
      'tool_call',
      { name: 'search_docs', input: { query: 'quarterly revenue' } },
      async (input) => {
        // Simulate tool execution
        return { results: ['Q1: $10M', 'Q2: $12M'] };
      },
    );
    console.log('[OK] search_docs:', result);
  } catch (err) {
    console.error('[FAIL] search_docs:', err);
  }

  // Successful LLM call
  try {
    const result = await guard.execute(
      'llm_call',
      {
        name: 'gpt-4',
        input: { messages: [{ role: 'user', content: 'Summarize revenue' }] },
        metadata: { model: 'gpt-4' },
      },
      async () => {
        return { content: 'Revenue grew 20% from Q1 to Q2.' };
      },
    );
    console.log('[OK] llm_call:', result);
  } catch (err) {
    console.error('[FAIL] llm_call:', err);
  }

  // Policy violation: blocked tool call
  try {
    await guard.execute(
      'tool_call',
      { name: 'delete_user', input: { userId: '123' } },
      async () => {
        return { deleted: true };
      },
    );
    console.log('[OK] delete_user: should not reach here');
  } catch (err) {
    if (err instanceof PolicyViolationError) {
      console.log('[BLOCKED] delete_user:', err.message);
      console.log('  Policy:', err.evaluation.policy_name);
      console.log('  Rule:', err.evaluation.rule_id);
    } else {
      console.error('[FAIL] delete_user:', err);
    }
  }

  // Warning: external call (allowed but flagged)
  try {
    const result = await guard.execute(
      'tool_call',
      { name: 'http_get', input: { url: 'https://api.example.com/data' } },
      async () => {
        return { status: 200, data: 'ok' };
      },
    );
    console.log('[WARN] http_get:', result, '(flagged for review)');
  } catch (err) {
    console.error('[FAIL] http_get:', err);
  }

  // Tool error: simulate a tool that throws
  try {
    await guard.execute(
      'tool_call',
      { name: 'unstable_api', input: {} },
      async () => {
        throw new Error('Connection timeout');
      },
    );
  } catch {
    console.log('[ERROR] unstable_api: caught expected error');
  }

  // Complete the trace
  const trace = await guard.complete('failed');

  console.log('\n--- Trace Summary ---');
  console.log('Trace ID:', trace?.id);
  console.log('Status:', trace?.status);
  console.log('Spans:', trace?.spans.length);

  if (trace) {
    // Verify trace integrity
    const verification = shield.verifyTrace(trace);
    console.log('\n--- Integrity Verification ---');
    console.log('Valid:', verification.valid);
    console.log('Span count:', verification.span_count);
    if (verification.errors.length > 0) {
      console.log('Errors:', verification.errors);
    }

    // Analyze failure
    console.log('\n--- Attribution Analysis ---');
    const report = shield.analyzeTrace(trace);
    console.log('Severity:', report.severity);
    console.log('Summary:', report.summary);
    console.log('\nRoot Causes:');
    for (const cause of report.root_causes) {
      console.log(`  [${cause.type}] (confidence: ${(cause.confidence * 100).toFixed(0)}%)`);
      console.log(`    ${cause.description}`);
    }
    console.log('\nRecommendations:');
    for (const rec of report.recommendations) {
      console.log(`  - ${rec}`);
    }
    console.log('\nTimeline:');
    for (const event of report.timeline) {
      console.log(`  ${event.timestamp} [${event.event_type}] ${event.description}`);
    }
  }
}

runAgent().catch(console.error);

