import { randomUUID } from 'node:crypto';
import type {
  Trace,
  Span,
  AttributionReport,
  RootCause,
  CausalLink,
  TimelineEvent,
  FailureType,
  Severity,
} from './types.js';

export class AttributionAnalyzer {
  /**
   * Analyze a failed trace and produce an attribution report identifying
   * root causes, causal chains, and recommendations.
   */
  analyze(trace: Trace): AttributionReport {
    if (trace.status !== 'failed' && trace.status !== 'aborted') {
      throw new Error(`Trace ${trace.id} is not failed/aborted (status: ${trace.status})`);
    }

    const sortedSpans = [...trace.spans].sort((a, b) => a.sequence - b.sequence);
    const failedSpans = sortedSpans.filter((s) => s.status === 'failed');
    const failureSpan = failedSpans[failedSpans.length - 1] ?? sortedSpans[sortedSpans.length - 1];

    const rootCauses = this.identifyRootCauses(sortedSpans, failedSpans);
    const causalChain = this.buildCausalChain(sortedSpans, failedSpans);
    const timeline = this.buildTimeline(sortedSpans);
    const severity = this.assessSeverity(rootCauses, failedSpans, sortedSpans);
    const recommendations = this.generateRecommendations(rootCauses, sortedSpans);

    const summary = this.buildSummary(rootCauses, failedSpans, trace);

    return {
      id: randomUUID(),
      trace_id: trace.id,
      failure_span_id: failureSpan?.id ?? '',
      root_causes: rootCauses,
      causal_chain: causalChain,
      timeline,
      summary,
      severity,
      recommendations,
      generated_at: new Date().toISOString(),
    };
  }

  private identifyRootCauses(allSpans: Span[], failedSpans: Span[]): RootCause[] {
    const causes: RootCause[] = [];

    for (const span of failedSpans) {
      // Check for policy violations
      const violations = span.policy_evaluations.filter((e) => e.result === 'deny');
      if (violations.length > 0) {
        causes.push({
          type: 'policy_violation',
          span_id: span.id,
          description: `Policy violation in "${span.name}": ${violations.map((v) => v.message).join('; ')}`,
          confidence: 0.95,
          evidence: violations.map((v) => `[${v.policy_name}/${v.rule_id}] ${v.message ?? ''}`),
        });
        continue;
      }

      // Check for tool errors
      if (span.error && span.action_type === 'tool_call') {
        causes.push({
          type: 'tool_error',
          span_id: span.id,
          description: `Tool "${span.name}" failed: ${span.error.message}`,
          confidence: 0.9,
          evidence: [
            `Error type: ${span.error.type}`,
            `Message: ${span.error.message}`,
            ...(span.error.stack ? [`Stack: ${span.error.stack.split('\n')[0]}`] : []),
          ],
        });
        continue;
      }

      // Check for model errors
      if (span.error && span.action_type === 'llm_call') {
        causes.push({
          type: 'model_error',
          span_id: span.id,
          description: `LLM call "${span.name}" failed: ${span.error.message}`,
          confidence: 0.85,
          evidence: [
            `Error type: ${span.error.type}`,
            `Message: ${span.error.message}`,
          ],
        });
        continue;
      }

      // Check for timeout
      if (span.duration_ms !== undefined && span.duration_ms > 30000) {
        causes.push({
          type: 'timeout',
          span_id: span.id,
          description: `Action "${span.name}" took ${span.duration_ms}ms (possible timeout)`,
          confidence: 0.7,
          evidence: [`Duration: ${span.duration_ms}ms`],
        });
        continue;
      }

      // Unknown failure
      causes.push({
        type: 'unknown',
        span_id: span.id,
        description: `Action "${span.name}" failed without clear error information`,
        confidence: 0.3,
        evidence: span.error ? [`Error: ${span.error.message}`] : ['No error details available'],
      });
    }

    // Detect cascading failures
    if (failedSpans.length > 1) {
      const firstFailure = failedSpans[0];
      const subsequentFailures = failedSpans.slice(1);
      const existingIds = new Set(causes.map((c) => c.span_id));

      for (const span of subsequentFailures) {
        // If this span depends on a failed span (via parent), it's cascading
        if (span.parent_span_id && failedSpans.some((f) => f.id === span.parent_span_id)) {
          if (!existingIds.has(span.id)) continue;
          // Upgrade existing cause to cascading
          const existing = causes.find((c) => c.span_id === span.id);
          if (existing && existing.type !== 'policy_violation') {
            existing.type = 'cascading_failure';
            existing.description = `Cascading failure from "${firstFailure.name}": ${existing.description}`;
            existing.confidence = Math.min(existing.confidence, 0.8);
          }
        }
      }
    }

    // Sort by confidence descending
    causes.sort((a, b) => b.confidence - a.confidence);
    return causes;
  }

  private buildCausalChain(allSpans: Span[], failedSpans: Span[]): CausalLink[] {
    const links: CausalLink[] = [];
    const failedIds = new Set(failedSpans.map((s) => s.id));

    for (const span of failedSpans) {
      // Direct parent dependency
      if (span.parent_span_id) {
        const parent = allSpans.find((s) => s.id === span.parent_span_id);
        if (parent) {
          links.push({
            from_span_id: span.id,
            to_span_id: parent.id,
            relationship: failedIds.has(parent.id) ? 'caused_by' : 'dependent_on',
            description: `"${span.name}" ${failedIds.has(parent.id) ? 'caused by failure of' : 'depends on'} "${parent.name}"`,
          });
        }
      }

      // Sequential dependency: if previous span failed, this one might be affected
      const prevSpan = allSpans.find((s) => s.sequence === span.sequence - 1);
      if (prevSpan && failedIds.has(prevSpan.id) && prevSpan.id !== span.parent_span_id) {
        links.push({
          from_span_id: span.id,
          to_span_id: prevSpan.id,
          relationship: 'triggered',
          description: `"${span.name}" triggered after failure of "${prevSpan.name}"`,
        });
      }
    }

    return links;
  }

  private buildTimeline(spans: Span[]): TimelineEvent[] {
    const events: TimelineEvent[] = [];

    for (const span of spans) {
      events.push({
        timestamp: span.started_at,
        span_id: span.id,
        event_type: 'action_start',
        description: `[${span.action_type}] "${span.name}" started`,
      });

      for (const eval_ of span.policy_evaluations) {
        events.push({
          timestamp: eval_.evaluated_at,
          span_id: span.id,
          event_type: eval_.result === 'deny' ? 'violation' : 'policy_check',
          description: `Policy "${eval_.policy_name}" (${eval_.rule_id}): ${eval_.result}${eval_.message ? ' - ' + eval_.message : ''}`,
        });
      }

      if (span.error) {
        events.push({
          timestamp: span.ended_at ?? span.started_at,
          span_id: span.id,
          event_type: 'error',
          description: `[${span.error.type}] ${span.error.message}`,
        });
      }

      if (span.ended_at) {
        events.push({
          timestamp: span.ended_at,
          span_id: span.id,
          event_type: 'action_end',
          description: `[${span.action_type}] "${span.name}" ${span.status} (${span.duration_ms ?? '?'}ms)`,
        });
      }
    }

    events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    return events;
  }

  private assessSeverity(rootCauses: RootCause[], failedSpans: Span[], allSpans: Span[]): Severity {
    // Policy violations are always high/critical
    const hasViolation = rootCauses.some((c) => c.type === 'policy_violation');
    if (hasViolation) return 'critical';

    // Cascading failures are high
    const hasCascading = rootCauses.some((c) => c.type === 'cascading_failure');
    if (hasCascading) return 'high';

    // Multiple failures suggest systemic issue
    const failureRatio = failedSpans.length / Math.max(allSpans.length, 1);
    if (failureRatio > 0.5) return 'high';
    if (failureRatio > 0.2) return 'medium';

    return 'low';
  }

  private generateRecommendations(rootCauses: RootCause[], allSpans: Span[]): string[] {
    const recommendations: string[] = [];

    for (const cause of rootCauses) {
      switch (cause.type) {
        case 'policy_violation':
          recommendations.push(
            `Review policy constraints: ${cause.description}. Consider if the policy is too restrictive or if the agent behavior needs correction.`,
          );
          break;
        case 'tool_error':
          recommendations.push(
            `Add error handling/retry for tool failures: ${cause.description}. Consider adding fallback tools or graceful degradation.`,
          );
          break;
        case 'model_error':
          recommendations.push(
            `Investigate LLM failure: ${cause.description}. Check model availability, token limits, and input formatting.`,
          );
          break;
        case 'timeout':
          recommendations.push(
            `Optimize slow operation: ${cause.description}. Consider adding timeouts, caching, or breaking into smaller steps.`,
          );
          break;
        case 'cascading_failure':
          recommendations.push(
            `Add circuit breaker for cascading failures: ${cause.description}. Implement early termination when upstream dependencies fail.`,
          );
          break;
        case 'data_quality':
          recommendations.push(
            `Add input validation: ${cause.description}. Validate data quality before passing to downstream actions.`,
          );
          break;
        default:
          recommendations.push(
            `Investigate unknown failure: ${cause.description}. Add more detailed error reporting for this action type.`,
          );
      }
    }

    // General recommendations
    const warningSpans = allSpans.filter(
      (s) => s.policy_evaluations.some((e) => e.result === 'warn'),
    );
    if (warningSpans.length > 0) {
      recommendations.push(
        `${warningSpans.length} action(s) triggered policy warnings. Review these patterns to prevent future violations.`,
      );
    }

    return recommendations;
  }

  private buildSummary(rootCauses: RootCause[], failedSpans: Span[], trace: Trace): string {
    const totalSpans = trace.spans.length;
    const failCount = failedSpans.length;
    const primaryCause = rootCauses[0];

    let summary = `Trace "${trace.id}" failed with ${failCount}/${totalSpans} action(s) failing.`;

    if (primaryCause) {
      summary += ` Primary root cause: ${primaryCause.type} (confidence: ${(primaryCause.confidence * 100).toFixed(0)}%) — ${primaryCause.description}`;
    }

    return summary;
  }
}
