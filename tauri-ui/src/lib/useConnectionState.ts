import { useEffect, useReducer } from 'react';

import { initialConnectionState, connectionReducer } from './connectionReducer';
import type { UiCommandError } from './contracts';

const errorCode = (error: unknown) => {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    return (error as UiCommandError).code;
  }
  return 'local.transport.disconnected';
};

export function useConnectionState(isSuccess: boolean, error: unknown) {
  const [connection, dispatch] = useReducer(connectionReducer, initialConnectionState);

  useEffect(() => {
    if (isSuccess) dispatch({ type: 'QuerySucceeded' });
  }, [isSuccess]);

  useEffect(() => {
    if (error) dispatch({ type: 'QueryFailed', code: errorCode(error) });
  }, [error]);

  return { connection, dispatch };
}
