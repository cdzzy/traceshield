import type { TraceShield } from '../index.js';

/**
 * LangChain adapter.
 * Provides callback-based integration with LangChain's callback system.
 *
 * Usage:
 *   import { TraceShield } from 'traceshield';
 *   import { createLangChainCallbacks } from 'traceshield/adapters/langchain';
 *
 *   const shield = new TraceShield({ policies: './policies.yaml' });
 *   const callbacks = createLangChainCallbacks(shield, { agentId: 'my-agent' });
 *
 *   const chain = new LLMChain({ llm, prompt, callbacks: [callbacks] });
 */

interface LangChainCallbackHandler {
  handleLLMStart?(llm: { name: string }, prompts: string[]): Promise<void>;
  handleLLMEnd?(output: { generations: unknown[] }): Promise<void>;
  handleLLMError?(error: Error): Promise<void>;
  handleToolStart?(tool: { name: string }, input: string): Promise<void>;
  handleToolEnd?(output: string): Promise<void>;
  handleToolError?(error: Error): Promise<void>;
  handleChainStart?(chain: { name: string }, inputs: Record<string, unknown>): Promise<void>;
  handleChainEnd?(outputs: Record<string, unknown>): Promise<void>;
  handleChainError?(error: Error): Promise<void>;
}

export function createLangChainCallbacks(
  shield: TraceShield,
  config: { agentId: string; sessionId?: string },
): LangChainCallbackHandler {
  const guard = shield.createGuard(config);

  return {
    async handleLLMStart(llm, prompts) {
      try {
        await guard.execute(
          'llm_call',
          {
            name: llm.name ?? 'langchain:llm',
            input: { prompts },
            metadata: { provider: 'langchain' },
          },
          async () => ({ _pending: true }),
        );
      } catch {
        // Policy errors are logged in the trace
      }
    },

    async handleLLMEnd(_output) {
      // LLM completed — recorded via the trace system
    },

    async handleLLMError(_error) {
      // Recorded via the trace system
    },

    async handleToolStart(tool, input) {
      try {
        await guard.execute(
          'tool_call',
          {
            name: tool.name ?? 'langchain:tool',
            input: { raw_input: input },
            metadata: { provider: 'langchain' },
          },
          async () => ({ _pending: true }),
        );
      } catch {
        // Policy errors are logged
      }
    },

    async handleToolEnd(_output) {
      // Recorded via the trace system
    },

    async handleToolError(_error) {
      // Recorded via the trace system
    },

    async handleChainStart(chain, inputs) {
      try {
        await guard.execute(
          'decision',
          {
            name: chain.name ?? 'langchain:chain',
            input: inputs,
            metadata: { provider: 'langchain' },
          },
          async () => ({ _pending: true }),
        );
      } catch {
        // Policy errors are logged
      }
    },

    async handleChainEnd(_outputs) {
      await guard.complete('completed');
    },

    async handleChainError(_error) {
      await guard.complete('failed');
    },
  };
}
