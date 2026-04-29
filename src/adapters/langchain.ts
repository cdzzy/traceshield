import type { TraceShield } from '../index.js';
import type { RuntimeGuard } from '../runtime-guard.js';

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
  let currentSpanId: string | null = null;
  let currentStartTime: number | null = null;

  return {
    async handleLLMStart(llm, prompts) {
      const traceId = guard.getTraceId();
      if (!traceId) {
        // Guard will auto-create trace on first execute call
        // We do a pre-flight trace start by executing a lightweight span
      }
      currentStartTime = Date.now();

      // We use execute in a "record only" way by immediately resolving
      // The actual LLM call is handled by LangChain
      try {
        await guard.execute(
          'llm_call',
          {
            name: llm.name ?? 'langchain:llm',
            input: { prompts },
            metadata: { provider: 'langchain' },
          },
          async () => {
            // Just record — LangChain handles actual execution
            return { _pending: true };
          },
        );
      } catch {
        // Swallow policy errors — they'll be logged in the trace
      }
    },

    async handleLLMEnd(output) {
      // LLM completed — output is recorded via the trace system
      currentStartTime = null;
    },

    async handleLLMError(error) {
      currentStartTime = null;
    },

    async handleToolStart(tool, input) {
      currentStartTime = Date.now();
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
      currentStartTime = null;
    },

    async handleToolError(_error) {
      currentStartTime = null;
    },

    async handleChainStart(chain, inputs) {
      currentStartTime = Date.now();
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

