import { useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';

import { agentApi } from './agentApi';
import { queryKeys } from './queryKeys';

const foregroundInterval = () => (document.visibilityState === 'visible' ? 5_000 : false);
const registrationObservationInterval = (query: { state: { data?: { registration_pending: boolean } } }) =>
  query.state.data?.registration_pending ? 1_000 : false;

export function useAgentQueries(enabled: boolean) {
  const queryClient = useQueryClient();

  useEffect(() => {
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void queryClient.invalidateQueries({ queryKey: ['agent-ui'] });
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, [queryClient]);

  const overview = useQuery({
    queryKey: queryKeys.overview,
    queryFn: agentApi.getOverview,
    enabled,
    refetchInterval: foregroundInterval,
    refetchIntervalInBackground: false,
  });
  const environment = useQuery({
    queryKey: queryKeys.environment,
    queryFn: agentApi.runEnvironmentCheck,
    enabled: enabled && overview.isSuccess,
    retry: false,
    refetchInterval: registrationObservationInterval,
    refetchIntervalInBackground: false,
  });

  return { overview, environment };
}
