import type { TraceShield } from '../index.js';
import type { ActionType } from '../types.js';

/**
 * Generic adapter that wraps any function-based agent workflow.
 * Provides a simple way to add TraceShield to custom agents without
 * requiring a specific framework.
 *
 * Usage:
 *   const adapter = new GenericAdapter(shield, { agentId: 'my-agent' });
 *   const result = await adapter.toolCall('search', { query: 'foo' }, mySearchFn);
 *   const response = await adapter.llmCall('gpt-4', prompt, myLLMFn);
 *   await adapter.complete();
 */
export class GenericAdapter {
  private guard;

  constructor(
    shield: TraceShield,
    config: { agentId: string; sessionId?: string; metadata?: Record<string, unknown> },
  ) {
    this.guard = shield.createGuard(config);
  }

  async toolCall<T>(
    toolName: string,
    input: unknown,
    handler: (input: unknown) => T | Promise<T>,
    metadata?: Record<string, unknown>,
  ): Promise<T> {
    return this.guard.execute('tool_call', { name: toolName, input, metadata }, handler);
  }

  async llmCall<T>(
    modelName: string,
    input: unknown,
    handler: (input: unknown) => T | Promise<T>,
    metadata?: Record<string, unknown>,
  ): Promise<T> {
    return this.guard.execute(
      'llm_call',
      { name: modelName, input, metadata: { ...metadata, model: modelName } },
      handler,
    );
  }

  async decision<T>(
    decisionName: string,
    input: unknown,
    handler: (input: unknown) => T | Promise<T>,
    metadata?: Record<string, unknown>,
  ): Promise<T> {
    return this.guard.execute('decision', { name: decisionName, input, metadata }, handler);
  }

  async action<T>(
    actionType: ActionType,
    name: string,
    input: unknown,
    handler: (input: unknown) => T | Promise<T>,
    metadata?: Record<string, unknown>,
  ): Promise<T> {
    return this.guard.execute(actionType, { name, input, metadata }, handler);
  }

  async complete(status: 'completed' | 'failed' | 'aborted' = 'completed') {
    return this.guard.complete(status);
  }

  getTraceId(): string | null {
    return this.guard.getTraceId();
  }
}

