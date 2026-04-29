/**
 * Example: MCP Event Listener for traceshield.
 * 
 * This example demonstrates how to use the MCP Event Listener
 * to automatically trace and enforce policies on MCP tool calls.
 * 
 * Inspired by Skill_Seekers MCP server patterns (26 tools, 12 platforms).
 * 
 * Usage:
 *   npx ts-node examples/06_mcp_listener.ts
 */

import {
  MCPEventListener,
  MCPEvent,
  MCPToolWrapper,
  WELL_KNOWN_MCP_TOOLS,
  getDefaultMCPPolicies,
} from '../src/mcp-listener';
import { PolicyEngine } from '../src/policy-engine';

// Mock tool implementations
const mockTools = {
  web_search: async ({ query }: { query: string }) => {
    return { results: [`Result 1 for "${query}"`, `Result 2 for "${query}"`] };
  },

  file_read: async ({ path }: { path: string }) => {
    return { content: `Content of ${path}`, size: 1024 };
  },

  file_write: async ({ path, content }: { path: string; content: string }) => {
    return { success: true, path, bytesWritten: content.length };
  },

  send_email: async ({ to, subject }: { to: string; subject: string }) => {
    return { success: true, messageId: `msg-${Date.now()}` };
  },

  run_command: async ({ command }: { command: string }) => {
    return { output: `Executed: ${command}`, exitCode: 0 };
  },
};

async function exampleBasicListener() {
  console.log('='.repeat(60));
  console.log('Example: Basic MCP Event Listener');
  console.log('='.repeat(60));

  // Create listener
  const listener = new MCPEventListener({
    enableAutoTracing: true,
    enableRateLimiting: true,
    maxEventsPerMinute: 100,
  });

  console.log('\n1. Created MCP Event Listener');
  console.log('   Auto-tracing: enabled');
  console.log('   Rate-limiting: enabled');

  return listener;
}

async function exampleToolInterception(listener: MCPEventListener) {
  console.log('\n' + '='.repeat(60));
  console.log('Example: Tool Call Interception');
  console.log('='.repeat(60));

  // Intercept a tool call
  console.log('\n1. Intercepting web_search call:');
  const result1 = await listener.intercept('web_search', { query: 'AI news' }, {
    agentId: 'agent-001',
    sessionId: 'session-123',
  });
  console.log('   Allowed:', result1.allowed);
  console.log('   Action:', result1.action);

  // Record the result
  if (result1.allowed) {
    const toolResult = await mockTools.web_search({ query: 'AI news' });
    listener.recordResult(`mcp-${Date.now() - 100}`, toolResult, 150);
    console.log('   Tool result recorded');
  }

  // Try to intercept a blocked tool
  console.log('\n2. Intercepting blocked tool (run_command):');
  const result2 = await listener.intercept('run_command', { command: 'rm -rf /' }, {
    agentId: 'agent-001',
  });
  console.log('   Allowed:', result2.allowed);
  console.log('   Action:', result2.action);

  return listener;
}

async function exampleEventQuery(listener: MCPEventListener) {
  console.log('\n' + '='.repeat(60));
  console.log('Example: Querying Events');
  console.log('='.repeat(60));

  // Get all events
  const allEvents = listener.getEvents();
  console.log('\n1. All events:', allEvents.length);

  // Get events by agent
  const agentEvents = listener.getEvents({
    agentIds: ['agent-001'],
  });
  console.log('   Events for agent-001:', agentEvents.length);

  // Get events by tool
  const toolEvents = listener.getEvents({
    toolNames: ['web_search'],
  });
  console.log('   Events for web_search:', toolEvents.length);
}

async function exampleStatistics(listener: MCPEventListener) {
  console.log('\n' + '='.repeat(60));
  console.log('Example: Event Statistics');
  console.log('='.repeat(60));

  const stats = listener.getStats();

  console.log('\n1. Overview:');
  console.log('   Total events:', stats.totalEvents);
  console.log('   Error rate:', (stats.errorRate * 100).toFixed(1) + '%');
  console.log('   Avg duration:', stats.avgDuration.toFixed(0) + 'ms');

  console.log('\n2. By tool:');
  for (const [tool, count] of Object.entries(stats.byTool)) {
    console.log(`   ${tool}: ${count}`);
  }

  console.log('\n3. By agent:');
  for (const [agent, count] of Object.entries(stats.byAgent)) {
    console.log(`   ${agent}: ${count}`);
  }
}

async function exampleToolWrapper() {
  console.log('\n' + '='.repeat(60));
  console.log('Example: MCP Tool Wrapper');
  console.log('='.repeat(60));

  // Create listener
  const listener = new MCPEventListener();

  // Create tool wrapper
  const wrapper = new MCPToolWrapper({
    listener,
    toolImplementations: mockTools,
  });

  // Set agent context
  wrapper.setContext({
    agentId: 'agent-002',
    sessionId: 'session-456',
  });

  console.log('\n1. Registered tools:', wrapper.getAvailableTools());

  // Call a tool
  console.log('\n2. Calling web_search through wrapper:');
  try {
    const result = await wrapper.callTool('web_search', { query: 'TypeScript' });
    console.log('   Result:', result);
  } catch (error) {
    console.log('   Error:', (error as Error).message);
  }

  // Call a blocked tool
  console.log('\n3. Calling blocked tool (run_command):');
  try {
    await wrapper.callTool('run_command', { command: 'dangerous command' });
  } catch (error) {
    console.log('   Blocked as expected:', (error as Error).message);
  }
}

async function exampleWellKnownTools() {
  console.log('\n' + '='.repeat(60));
  console.log('Example: Well-Known MCP Tool Patterns');
  console.log('='.repeat(60));

  console.log('\n1. Tool Categories and Risk Levels:');
  for (const [tool, info] of Object.entries(WELL_KNOWN_MCP_TOOLS)) {
    const approval = info.requiresApproval ? '🔒' : '🔓';
    const riskEmoji = info.risk === 'critical' ? '🔴' : info.risk === 'high' ? '🟠' : '🟡';
    console.log(`   ${approval} ${tool}: ${riskEmoji} ${info.risk} (approval: ${info.requiresApproval})`);
  }
}

async function exampleDefaultPolicies() {
  console.log('\n' + '='.repeat(60));
  console.log('Example: Default MCP Policies');
  console.log('='.repeat(60));

  const policies = getDefaultMCPPolicies();

  console.log('\n1. Default Policy Rules:');
  policies.forEach((rule, i) => {
    console.log(`   ${i + 1}. ${rule.name}`);
    console.log(`      Tool pattern: ${rule.toolPattern}`);
    console.log(`      Action: ${rule.action}`);
    console.log(`      Requires approval: ${rule.requireApproval}`);
    if (rule.rateLimit) {
      console.log(`      Rate limit: ${rule.rateLimit.perMinute} per minute`);
    }
  });

  // Apply policies to a policy engine
  console.log('\n2. Applying policies to PolicyEngine:');
  const engine = new PolicyEngine();

  for (const policy of policies) {
    engine.addRule({
      name: policy.name,
      match: (action) => {
        if (typeof policy.toolPattern === 'string') {
          return action.resource === policy.toolPattern;
        }
        if (policy.toolPattern instanceof RegExp) {
          return policy.toolPattern.test(action.resource);
        }
        return false;
      },
      check: async () => policy.action === 'block' ? 'block' : 'allow',
      onViolation: policy.action as 'block' | 'warn',
      message: `Policy: ${policy.name}`,
    });
  }

  console.log('   Added', policies.length, 'rules to PolicyEngine');
}

async function exampleProductionUse() {
  console.log('\n' + '='.repeat(60));
  console.log('Example: Production MCP Tracing Setup');
  console.log('='.repeat(60));

  console.log(`
Production Setup Guide:
----------------------

1. Integrate with MCP Server:

   import { MCPServer } from '@modelcontextprotocol/sdk';
   import { MCPEventListener } from 'traceshield';

   const listener = new MCPEventListener({
     recorder: traceRecorder,
     policyEngine: policyEngine,
   });

   const server = new MCPServer({
     name: 'traced-mcp-server',
     tools: yourTools,
   });

   server.on('toolCall', async (tool, args, ctx) => {
     const { allowed } = await listener.intercept(tool.name, args, ctx);
     if (!allowed) throw new Error('Tool call blocked');
     return await tool.handler(args);
   });

2. Set up Policy Rules:

   const rules = [
     ...getDefaultMCPPolicies(),
     {
       name: 'customer-data-protection',
       toolPattern: /^query_(customer|user|account)/,
       action: 'block',
       requireApproval: true,
       argumentPatterns: {
         includeSSN: /true/i,
       },
     },
   ];

3. Configure Rate Limits:

   const listener = new MCPEventListener({
     enableRateLimiting: true,
     maxEventsPerMinute: 1000,
   });

4. Enable Audit Logging:

   listener.on('tool_call', (event) => {
     auditLogger.log({
       type: 'mcp_tool_call',
       agentId: event.agentId,
       tool: event.toolName,
       timestamp: event.timestamp,
     });
   });
`);
}

async function main() {
  console.log('\n🚀 MCP Event Listener Examples\n');

  try {
    const listener = await exampleBasicListener();
    await exampleToolInterception(listener);
    await exampleEventQuery(listener);
    await exampleStatistics(listener);
    await exampleToolWrapper();
    await exampleWellKnownTools();
    await exampleDefaultPolicies();
    await exampleProductionUse();

    console.log('\n' + '='.repeat(60));
    console.log('✅ All MCP Event Listener examples completed!');
    console.log('='.repeat(60));
  } catch (error) {
    console.error('Error:', error);
  }
}

main();

