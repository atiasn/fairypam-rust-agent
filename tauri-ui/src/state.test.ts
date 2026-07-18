import { describe, expect, it } from 'vitest';

import { effectiveAgentState, reduceAuthority } from './state';

const online = {
  lifecycle: 'connected' as const,
  activeProfileId: 'genshin',
  targetLocked: true,
  captureActive: true,
};

describe('authoritative state overrides', () => {
  it('offline event wins over stale online query data', () => {
    const override = reduceAuthority(null, {
      kind: 'offline',
      error: { code: 'agent_unavailable', message: 'offline', retryable: true },
    });
    expect(effectiveAgentState(online, override)).toMatchObject({ online: false, emergency: false });
  });

  it('emergency remains latched when a later status event is online', () => {
    const emergency = reduceAuthority(null, {
      kind: 'emergency',
      release: { holds: 2, state: 'released' },
    });
    const afterStatus = reduceAuthority(emergency, { kind: 'status', status: online });
    expect(effectiveAgentState(online, afterStatus)).toMatchObject({ online: false, emergency: true });
  });
});
