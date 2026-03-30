// TraceShield - Agent Behavior Tracing & Protection System

export { TraceShield } from './tracer.js';
export { TraceRecorder } from './trace-recorder.js';
export { PolicyEngine } from './policy-engine.js';
export { RuntimeGuard } from './runtime-guard.js';
export { AuditDashboard, createDashboard } from './dashboard.js';
export type {
  DashboardConfig,
  DashboardStats,
} from './dashboard.js';
export * from './types.js';
