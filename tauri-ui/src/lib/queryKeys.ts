export const queryKeys = {
  overview: ['agent-ui', 'overview'] as const,
  doctor: ['agent-ui', 'doctor'] as const,
  profiles: ['agent-ui', 'profiles'] as const,
  targets: (profileId: string) => ['agent-ui', 'targets', profileId] as const,
  update: ['agent-ui', 'update'] as const,
  startup: ['agent-ui', 'startup'] as const,
  connection: ['agent-ui', 'connection'] as const,
  games: ['agent-ui', 'games'] as const,
  logTail: (level: 'error' | 'warn' | 'info') => ['agent-ui', 'log-tail', level] as const,
};
