import { useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';

import { agentApi } from './agentApi';
import { queryKeys } from './queryKeys';

const foregroundInterval = () => (document.visibilityState === 'visible' ? 5_000 : false);

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

  return {
    overview: useQuery({
      queryKey: queryKeys.overview,
      queryFn: agentApi.getOverview,
      enabled,
      refetchInterval: foregroundInterval,
      refetchIntervalInBackground: false,
    }),
    environment: useQuery({
      queryKey: queryKeys.environment,
      queryFn: agentApi.runEnvironmentCheck,
      enabled,
      retry: false,
    }),
  };
}
