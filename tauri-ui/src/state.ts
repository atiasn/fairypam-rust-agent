import type { AgentStatus, CommandError, ReleaseResult } from './api';

export type AgentStateEvent =
  | { kind: 'status'; status: AgentStatus }
  | { kind: 'offline'; error: CommandError }
  | { kind: 'emergency'; release: ReleaseResult }
  | { kind: 'stop_requested' };

export type AuthorityOverride =
  | { kind: 'offline'; error: CommandError }
  | { kind: 'emergency'; release: ReleaseResult }
  | null;

export function reduceAuthority(
  current: AuthorityOverride,
  event: AgentStateEvent,
): AuthorityOverride {
  if (event.kind === 'emergency') return event;
  if (event.kind === 'offline') return current?.kind === 'emergency' ? current : event;
  if (event.kind === 'status' && current?.kind === 'offline') return null;
  return current;
}

export interface EffectiveAgentState {
  online: boolean;
  emergency: boolean;
  status: AgentStatus | null;
  error: CommandError | null;
}

export function effectiveAgentState(
  queryStatus: AgentStatus | undefined,
  override: AuthorityOverride,
): EffectiveAgentState {
  if (override?.kind === 'emergency') {
    return { online: false, emergency: true, status: queryStatus ?? null, error: null };
  }
  if (override?.kind === 'offline') {
    return { online: false, emergency: false, status: queryStatus ?? null, error: override.error };
  }
  return {
    online: queryStatus?.lifecycle === 'connected',
    emergency: false,
    status: queryStatus ?? null,
    error: null,
  };
}
