/**
 * MCP Event Listener - Automatic tracing for MCP tool calls.
 * 
 * This module provides automatic tracing and policy enforcement
 * for MCP (Model Context Protocol) tool invocations.
 * 
 * Inspired by Skill_Seekers MCP server patterns (26 tools, 12 platforms).
 * 
 * Usage:
 *   import { MCPEventListener } from './mcp-listener';
 *   
 *   const listener = new MCPEventListener({
 *     recorder: myRecorder,
 *     policyEngine: myPolicy,
 *   });
 *   
 *   // Intercept MCP tool calls
 *   const result = await listener.intercept('web_search', { query: 'AI' }, {
 *     agentId: 'my-agent',
 *     sessionId: 'session-123',
 *   });
 */

import { TraceRecorder } from './trace-recorder.js';
import { PolicyEngine } from './policy-engine.js';
import type { AgentId, EvalContext } from './types.js';

// ---- MCP Event Types ----

export interface MCPEvent {
  id: string;
  type: MCPEventType;
  toolName: string;
  arguments: Record<string, unknown>;
  agentId: AgentId;
  sessionId?: string;
  userId?: string;
  timestamp: number;
  result?: unknown;
  error?: Error;
  duration?: number;
  metadata?: Record<string, unknown>;
}

export type MCPEventType =
  | 'tool_call'
  | 'tool_result'
  | 'tool_error'
  | 'resource_access'
  | 'resource_update'
  | 'prompt_rendered';

export interface MCPEventFilter {
  toolNames?: string[];
  agentIds?: AgentId[];
  eventTypes?: MCPEventType[];
  fromTimestamp?: number;
  toTimestamp?: number;
}

// ---- Policy Rules for MCP ----

export interface MCPPolicyConfig {
  rules: MCPPolicyRule[];
  defaultAction: 'allow' | 'block' | 'warn';
}

export interface MCPPolicyRule {
  name: string;
  toolPattern?: string | RegExp;
  argumentPatterns?: Record<string, string | RegExp>;
  action?: 'block' | 'warn' | 'allow' | 'throttle' | 'require_approval';
  rateLimit?: {
    perMinute?: number;
    perHour?: number;
    perAgent?: boolean;
  };
  requireApproval?: boolean;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

export type MCPActionResult = 'allow' | 'block' | 'warn' | 'throttle' | 'require_approval';

// ---- MCP Event Listener ----

export interface MCPListenerConfig {
  recorder?: TraceRecorder;
  policyEngine?: PolicyEngine;
  enableAutoTracing?: boolean;
  enableRateLimiting?: boolean;
  maxEventsPerMinute?: number;
}

export class MCPEventListener {
  private recorder?: TraceRecorder;
  private policyEngine?: PolicyEngine;
  private eventHistory: MCPEvent[] = [];
  private config: Required<MCPListenerConfig>;
  private rateLimitCounts: Map<string, { count: number; resetAt: number }> = new Map();

  constructor(config: MCPListenerConfig = {}) {
    this.config = {
      recorder: config.recorder!,
      policyEngine: config.policyEngine!,
      enableAutoTracing: config.enableAutoTracing ?? true,
      enableRateLimiting: config.enableRateLimiting ?? true,
      maxEventsPerMinute: config.maxEventsPerMinute ?? 1000,
    };
  }

  /**
   * Intercept and trace an MCP tool call.
   */
  async intercept(
    toolName: string,
    arguments_: Record<string, unknown>,
    context: {
      agentId: AgentId;
      sessionId?: string;
      userId?: string;
      metadata?: Record<string, unknown>;
    }
  ): Promise<{ result: unknown; allowed: boolean; action: MCPActionResult }> {
    const startTime = Date.now();

    // Create event
    const event: MCPEvent = {
      id: `mcp-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      type: 'tool_call',
      toolName,
      arguments: arguments_,
      agentId: context.agentId,
      sessionId: context.sessionId,
      userId: context.userId,
      timestamp: startTime,
      metadata: context.metadata,
    };

    // Check rate limit
    if (this.config.enableRateLimiting) {
      const rateCheck = this.checkRateLimit(event);
      if (rateCheck.limited) {
        event.type = 'tool_error';
        event.error = new Error(`Rate limit exceeded: ${rateCheck.message}`);
        event.duration = Date.now() - startTime;
        this.recordEvent(event);

        return {
          result: null,
          allowed: false,
          action: 'throttle',
        };
      }
    }

    // Check policy
    const policyDecision = this.checkPolicy(event);

    // Record the call event
    this.recordEvent(event);

    // Handle based on policy action
    if (policyDecision.action === 'block') {
      const blockedEvent = { ...event, type: 'tool_error' as const };
      blockedEvent.error = new Error(`Blocked by policy: ${policyDecision.reason ?? 'policy rule'}`);
      blockedEvent.duration = Date.now() - startTime;
      this.recordEvent(blockedEvent);

      return {
        result: null,
        allowed: false,
        action: 'block',
      };
    }

    if (policyDecision.action === 'require_approval') {
      return {
        result: null,
        allowed: false,
        action: 'require_approval',
      };
    }

    // Tool call is allowed
    return {
      result: undefined, // Actual result would come from the tool
      allowed: true,
      action: policyDecision.action === 'warn' ? 'warn' : 'allow',
    };
  }

  /**
   * Record the result of a tool call.
   */
  recordResult(
    eventId: string,
    result: unknown,
    duration?: number
  ): void {
    const event = this.eventHistory.find((e) => e.id === eventId);
    if (!event) return;

    event.type = 'tool_result';
    event.result = result;
    event.duration = duration ?? (Date.now() - event.timestamp);
    this.recordEvent(event);
  }

  /**
   * Record an error from a tool call.
   */
  recordError(
    eventId: string,
    error: Error,
    duration?: number
  ): void {
    const event = this.eventHistory.find((e) => e.id === eventId);
    if (!event) return;

    event.type = 'tool_error';
    event.error = error;
    event.duration = duration ?? (Date.now() - event.timestamp);
    this.recordEvent(event);
  }

  /**
   * Get events matching a filter.
   */
  getEvents(filter?: MCPEventFilter): MCPEvent[] {
    let events = this.eventHistory;

    if (!filter) return events;

    if (filter.toolNames) {
      events = events.filter((e) => filter.toolNames!.includes(e.toolName));
    }

    if (filter.agentIds) {
      events = events.filter((e) => filter.agentIds!.includes(e.agentId));
    }

    if (filter.eventTypes) {
      events = events.filter((e) => filter.eventTypes!.includes(e.type));
    }

    if (filter.fromTimestamp) {
      events = events.filter((e) => e.timestamp >= filter.fromTimestamp!);
    }

    if (filter.toTimestamp) {
      events = events.filter((e) => e.timestamp <= filter.toTimestamp!);
    }

    return events;
  }

  /**
   * Get statistics about MCP events.
   */
  getStats(): {
    totalEvents: number;
    byTool: Record<string, number>;
    byAgent: Record<string, number>;
    byType: Record<string, number>;
    errorRate: number;
    avgDuration: number;
  } {
    const byTool: Record<string, number> = {};
    const byAgent: Record<string, number> = {};
    const byType: Record<string, number> = {};
    let totalDuration = 0;
    let errorCount = 0;

    for (const event of this.eventHistory) {
      byTool[event.toolName] = (byTool[event.toolName] || 0) + 1;
      byAgent[event.agentId] = (byAgent[event.agentId] || 0) + 1;
      byType[event.type] = (byType[event.type] || 0) + 1;

      if (event.duration) totalDuration += event.duration;
      if (event.type === 'tool_error') errorCount++;
    }

    return {
      totalEvents: this.eventHistory.length,
      byTool,
      byAgent,
      byType,
      errorRate: this.eventHistory.length > 0
        ? errorCount / this.eventHistory.length
        : 0,
      avgDuration: this.eventHistory.length > 0
        ? totalDuration / this.eventHistory.length
        : 0,
    };
  }

  private recordEvent(event: MCPEvent): void {
    // Add to history
    this.eventHistory.push(event);

    // Trim history if too large
    if (this.eventHistory.length > 10000) {
      this.eventHistory = this.eventHistory.slice(-5000);
    }
  }

  private checkPolicy(event: MCPEvent): { action: MCPActionResult; reason?: string } {
    // Default: allow
    if (!this.config.policyEngine) {
      return { action: 'allow' };
    }

    const context: EvalContext = {
      action_type: 'tool_call',
      action_name: event.toolName,
      input: event.arguments,
      metadata: {
        agentId: event.agentId,
        arguments: event.arguments,
        sessionId: event.sessionId,
      },
      trace_id: event.id,
      span_count: this.eventHistory.length,
      elapsed_ms: event.duration ?? 0,
    };

    const decision = this.config.policyEngine.evaluatePre(context);

    if (!decision.allowed) {
      return {
        action: 'block',
        reason: decision.blocked_by?.message ?? decision.blocked_by?.rule_id,
      };
    }

    const hasWarn = decision.evaluations.some((e) => e.result === 'warn');
    return { action: hasWarn ? 'warn' : 'allow' };
  }

  private checkRateLimit(event: MCPEvent): { limited: boolean; message?: string } {
    const now = Date.now();
    const minuteKey = `minute:${event.agentId}:${event.toolName}`;

    // Check per-minute limit
    let minuteCount = this.rateLimitCounts.get(minuteKey);
    if (!minuteCount || now > minuteCount.resetAt) {
      minuteCount = { count: 0, resetAt: now + 60000 };
      this.rateLimitCounts.set(minuteKey, minuteCount);
    }

    if (minuteCount.count >= this.config.maxEventsPerMinute) {
      return {
        limited: true,
        message: `Per-minute rate limit exceeded for ${event.toolName}`,
      };
    }

    minuteCount.count++;

    return { limited: false };
  }

  /**
   * Clear event history.
   */
  clearHistory(): void {
    this.eventHistory = [];
  }
}

// ---- MCP Tool Wrapper ----

export interface MCPToolWrapperConfig {
  listener: MCPEventListener;
  toolImplementations: Record<string, (args: Record<string, unknown>) => Promise<unknown>>;
}

/**
 * Wrap MCP tools with automatic tracing and policy enforcement.
 */
export class MCPToolWrapper {
  private listener: MCPEventListener;
  private tools: Map<string, (args: Record<string, unknown>) => Promise<unknown>>;
  private agentContext: { agentId: AgentId; sessionId?: string; userId?: string };

  constructor(config: MCPToolWrapperConfig) {
    this.listener = config.listener;
    this.tools = new Map(Object.entries(config.toolImplementations));
    this.agentContext = { agentId: 'system' };
  }

  setContext(context: { agentId: AgentId; sessionId?: string; userId?: string }): void {
    this.agentContext = context;
  }

  registerTool(name: string, implementation: (args: Record<string, unknown>) => Promise<unknown>): void {
    this.tools.set(name, implementation);
  }

  async callTool(toolName: string, arguments_: Record<string, unknown>): Promise<unknown> {
    const tool = this.tools.get(toolName);
    if (!tool) {
      throw new Error(`Tool '${toolName}' not found`);
    }

    // Intercept with listener
    const { allowed, action } = await this.listener.intercept(
      toolName,
      arguments_,
      this.agentContext
    );

    if (!allowed) {
      throw new Error(`Tool call blocked: ${action}`);
    }

    // Execute the tool
    const startTime = Date.now();
    try {
      const toolResult = await tool(arguments_);
      this.listener.recordResult(
        `mcp-${startTime}`,
        toolResult,
        Date.now() - startTime
      );
      return toolResult;
    } catch (error) {
      this.listener.recordError(
        `mcp-${startTime}`,
        error as Error,
        Date.now() - startTime
      );
      throw error;
    }
  }

  getAvailableTools(): string[] {
    return Array.from(this.tools.keys());
  }
}

// ---- Well-known MCP Tool Patterns ----

export const WELL_KNOWN_MCP_TOOLS = {
  // Web & Search
  web_search: { category: 'web', risk: 'low', requiresApproval: false },
  get_page: { category: 'web', risk: 'low', requiresApproval: false },
  browse_url: { category: 'web', risk: 'medium', requiresApproval: false },

  // File System
  file_read: { category: 'filesystem', risk: 'medium', requiresApproval: false },
  file_write: { category: 'filesystem', risk: 'high', requiresApproval: true },
  file_delete: { category: 'filesystem', risk: 'critical', requiresApproval: true },

  // Code Execution
  run_python: { category: 'execution', risk: 'high', requiresApproval: true },
  run_bash: { category: 'execution', risk: 'critical', requiresApproval: true },
  execute_code: { category: 'execution', risk: 'critical', requiresApproval: true },

  // API & Network
  http_request: { category: 'network', risk: 'high', requiresApproval: true },
  send_email: { category: 'network', risk: 'high', requiresApproval: true },
  api_call: { category: 'network', risk: 'medium', requiresApproval: false },

  // Data & Database
  query_database: { category: 'data', risk: 'high', requiresApproval: true },
  write_database: { category: 'data', risk: 'critical', requiresApproval: true },
  export_data: { category: 'data', risk: 'medium', requiresApproval: true },

  // System
  run_command: { category: 'system', risk: 'critical', requiresApproval: true },
  manage_process: { category: 'system', risk: 'critical', requiresApproval: true },
};

/**
 * Get default policy rules for MCP tools.
 */
export function getDefaultMCPPolicies(): MCPPolicyRule[] {
  const rules: MCPPolicyRule[] = [];

  // High-risk tool restrictions
  rules.push({
    name: 'block-destructive-tools',
    toolPattern: /^(file_delete|run_command|manage_process)$/,
    action: 'block',
    requireApproval: true,
    logLevel: 'error',
  });

  // Network tool rate limits
  rules.push({
    name: 'rate-limit-network-calls',
    toolPattern: /^(http_request|api_call|send_email)$/,
    action: 'warn',
    rateLimit: { perMinute: 30, perAgent: true },
    logLevel: 'warn',
  });

  // Execution tool restrictions
  rules.push({
    name: 'execution-tools-require-approval',
    toolPattern: /^(run_python|run_bash|execute_code)$/,
    action: 'warn',
    requireApproval: true,
    logLevel: 'info',
  });

  return rules;
}

