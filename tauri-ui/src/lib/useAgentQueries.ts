import { useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';

import { agentApi } from './agentApi';
import { queryKeys } from './queryKeys';

const foregroundInterval = () => (document.visibilityState === 'visible' ? 5_000 : false);

export function useAgentQueries(profileId?: string) {
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
      refetchInterval: foregroundInterval,
      refetchIntervalInBackground: false,
    }),
    doctor: useQuery({
      queryKey: queryKeys.doctor,
      queryFn: agentApi.getDoctor,
      refetchInterval: foregroundInterval,
      refetchIntervalInBackground: false,
    }),
    profiles: useQuery({
      queryKey: queryKeys.profiles,
      queryFn: agentApi.listProfiles,
      refetchInterval: foregroundInterval,
      refetchIntervalInBackground: false,
    }),
    targets: useQuery({
      queryKey: queryKeys.targets(profileId ?? ''),
      queryFn: () => agentApi.listTargets(profileId ?? ''),
      enabled: Boolean(profileId),
      refetchInterval: foregroundInterval,
      refetchIntervalInBackground: false,
    }),
  };
}
