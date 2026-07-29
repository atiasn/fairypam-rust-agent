export type Availability = 'online' | 'offline' | 'emergency' | 'unknown';

export type ConnectionState = {
  availability: Availability;
  reasonCode?: string;
};

export type ConnectionAction =
  | { type: 'QuerySucceeded' }
  | { type: 'QueryFailed'; code: string }
  | { type: 'ExplicitOffline'; code: string }
  | { type: 'ExplicitEmergency'; code: string }
  | { type: 'Reset' };

const offlineCode = (code: string) =>
  code === 'local.transport.timeout' ||
  code === 'local.transport.disconnected' ||
  code === 'local.transport.pipe_not_found';

export const initialConnectionState: ConnectionState = { availability: 'unknown' };

export function connectionReducer(
  state: ConnectionState,
  action: ConnectionAction,
): ConnectionState {
  if (action.type === 'ExplicitEmergency') {
    return { availability: 'emergency', reasonCode: action.code };
  }
  if (state.availability === 'emergency' && action.type !== 'Reset') return state;
  if (action.type === 'QuerySucceeded') return { availability: 'online' };
  if (action.type === 'QueryFailed' && offlineCode(action.code)) {
    return { availability: 'offline', reasonCode: action.code };
  }
  if (action.type === 'ExplicitOffline') return { availability: 'offline', reasonCode: action.code };
  if (action.type === 'Reset') return initialConnectionState;
  return state;
}

export const canMutate = (state: ConnectionState) => state.availability === 'online';
