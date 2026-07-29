import { describe, expect, it } from 'vitest';

import { canMutate, connectionReducer, initialConnectionState } from './connectionReducer';

describe('connectionReducer', () => {
  it('lets any overview failure override a stale successful query', () => {
    const online = connectionReducer(initialConnectionState, { type: 'QuerySucceeded' });
    const offline = connectionReducer(online, {
      type: 'QueryFailed',
      code: 'task_command_not_allowed',
    });

    expect(offline).toEqual({ availability: 'offline', reasonCode: 'task_command_not_allowed' });
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
