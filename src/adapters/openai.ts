import type { TraceShield } from '../index.js';
import type { RuntimeGuard } from '../runtime-guard.js';

interface OpenAIClient {
  chat: {
    completions: {
      create(params: Record<string, unknown>): Promise<unknown>;
    };
  };
}

interface OpenAICompletionParams {
  model?: string;
  messages?: unknown[];
  tools?: unknown[];
  [key: string]: unknown;
}

/**
 * OpenAI SDK adapter.
 * Wraps an OpenAI client instance so all chat.completions.create calls
 * are automatically traced and policy-checked.
 *
 * Usage:
 *   import OpenAI from 'openai';
 *   import { TraceShield } from 'traceshield';
 *   import { wrapOpenAI } from 'traceshield/adapters/openai';
 *
 *   const shield = new TraceShield({ policies: './policies.yaml' });
 *   const client = wrapOpenAI(new OpenAI(), shield, { agentId: 'my-agent' });
 *   const response = await client.chat.completions.create({ model: 'gpt-4', messages: [...] });
 */
export function wrapOpenAI(
  client: OpenAIClient,
  shield: TraceShield,
  config: { agentId: string; sessionId?: string },
): OpenAIClient {
  const guard = shield.createGuard(config);

  const originalCreate = client.chat.completions.create.bind(client.chat.completions);

  client.chat.completions.create = async (params: OpenAICompletionParams) => {
    const model = (params.model as string) ?? 'unknown';

    return guard.execute(
      'llm_call',
      {
        name: `openai:${model}`,
        input: {
          model,
          messages: params.messages,
          tools: params.tools,
        },
        metadata: {
          model,
          provider: 'openai',
          ...params,
        },
      },
      async () => {
        return originalCreate(params);
      },
    );
  };

  return client;
}

/**
 * Creates a standalone guard for manual OpenAI call wrapping.
 */
export function createOpenAIGuard(
  shield: TraceShield,
  config: { agentId: string; sessionId?: string },
): {
  guard: RuntimeGuard;
  wrapCall: <T>(model: string, messages: unknown[], fn: () => Promise<T>) => Promise<T>;
  complete: () => Promise<unknown>;
} {
  const guard = shield.createGuard(config);

  return {
    guard,
    wrapCall: async <T>(model: string, messages: unknown[], fn: () => Promise<T>) => {
      return guard.execute(
        'llm_call',
        {
          name: `openai:${model}`,
          input: { model, messages },
          metadata: { model, provider: 'openai' },
        },
        fn,
      );
    },
    complete: () => guard.complete(),
  };
}

