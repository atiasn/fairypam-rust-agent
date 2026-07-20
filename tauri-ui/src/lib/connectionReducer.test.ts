import { describe, expect, it } from 'vitest';

import { canMutate, connectionReducer, initialConnectionState } from './connectionReducer';

describe('connectionReducer', () => {
  it('lets a transport failure override a stale successful query', () => {
    const online = connectionReducer(initialConnectionState, { type: 'QuerySucceeded' });
    const offline = connectionReducer(online, {
      type: 'QueryFailed',
      code: 'local.transport.disconnected',
    });

    expect(offline).toEqual({ availability: 'offline', reasonCode: 'local.transport.disconnected' });
    expect(canMutate(offline)).toBe(false);
  });

  it('does not let a stale success clear emergency state', () => {
    const emergency = connectionReducer(initialConnectionState, {
      type: 'ExplicitEmergency',
      code: 'agent.guardian.emergency',
    });

    expect(connectionReducer(emergency, { type: 'QuerySucceeded' })).toEqual(emergency);
  });
});
