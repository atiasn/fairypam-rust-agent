export const queryKeys = {
  startup: ['agent-ui', 'startup'] as const,
  overview: ['agent-ui', 'overview'] as const,
  connection: ['agent-ui', 'connection'] as const,
  games: ['agent-ui', 'games'] as const,
  logTail: (level: 'error' | 'warn' | 'info') => ['agent-ui', 'log-tail', level] as const,
};
