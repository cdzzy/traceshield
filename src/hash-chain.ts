import { createHash } from 'node:crypto';
import type { Span } from './types.js';

const DEFAULT_ALGORITHM = 'sha256';

export function computeSpanHash(span: Omit<Span, 'hash'>, algorithm = DEFAULT_ALGORITHM): string {
  const payload = JSON.stringify({
    id: span.id,
    trace_id: span.trace_id,
    parent_span_id: span.parent_span_id,
    sequence: span.sequence,
    action_type: span.action_type,
    name: span.name,
    input: span.input,
    output: span.output,
    started_at: span.started_at,
    ended_at: span.ended_at,
    status: span.status,
    policy_evaluations: span.policy_evaluations,
    error: span.error,
    previous_hash: span.previous_hash,
  });

  return createHash(algorithm).update(payload).digest('hex');
}

export function computeChainHash(
  currentSpanHash: string,
  previousHash: string,
  algorithm = DEFAULT_ALGORITHM,
): string {
  return createHash(algorithm)
    .update(previousHash + currentSpanHash)
    .digest('hex');
}

export function computeTraceIntegrityHash(
  spans: Span[],
  algorithm = DEFAULT_ALGORITHM,
): string {
  const sorted = [...spans].sort((a, b) => a.sequence - b.sequence);
  const payload = sorted.map((s) => s.hash).join(':');
  return createHash(algorithm).update(payload).digest('hex');
}

export function verifySpanChain(spans: Span[], algorithm = DEFAULT_ALGORITHM): VerificationResult {
  const sorted = [...spans].sort((a, b) => a.sequence - b.sequence);
  const errors: ChainError[] = [];

  for (let i = 0; i < sorted.length; i++) {
    const span = sorted[i];

    // Verify individual span hash
    const expectedHash = computeSpanHash(span, algorithm);
    if (span.hash !== expectedHash) {
      errors.push({
        span_id: span.id,
        sequence: span.sequence,
        type: 'hash_mismatch',
        message: `Span hash mismatch: expected ${expectedHash}, got ${span.hash}`,
      });
    }

    // Verify chain linkage (skip first span)
    if (i > 0) {
      const prevSpan = sorted[i - 1];
      if (span.previous_hash !== prevSpan.hash) {
        errors.push({
          span_id: span.id,
          sequence: span.sequence,
          type: 'chain_break',
          message: `Chain break at sequence ${span.sequence}: previous_hash doesn't match span ${prevSpan.id}`,
        });
      }
    }
  }

  return {
    valid: errors.length === 0,
    span_count: sorted.length,
    errors,
  };
}

export interface VerificationResult {
  valid: boolean;
  span_count: number;
  errors: ChainError[];
}

export interface ChainError {
  span_id: string;
  sequence: number;
  type: 'hash_mismatch' | 'chain_break';
  message: string;
}
