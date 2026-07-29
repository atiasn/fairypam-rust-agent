import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import { render } from '@testing-library/react';
import { expect, it, vi } from 'vitest';

vi.mock('./lib/agentApi', () => ({
  agentApi: {
    ensureLocalAgent: vi.fn().mockResolvedValue({ status: 'ready' }),
    onLocalAgentActivation: vi.fn().mockResolvedValue(() => {}),
    onEmbeddedRuntimeFailed: vi.fn().mockResolvedValue(() => {}),
    getOverview: vi.fn().mockResolvedValue({ status: { state: 'ConnectedIdle', capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'idle_no_holds' }, doctor: { profiles: [], runtime: 'dry_run' } }),
    getConnectionStatus: vi.fn().mockResolvedValue({ control: 'offline', frame: 'offline', capture_active: false }),
    runEnvironmentCheck: vi.fn().mockResolvedValue({ registration_ready: true, registration_pending: false, checks: [] }),
    getLogTail: vi.fn().mockResolvedValue({ entries: [] }),
    scanInstalledGames: vi.fn().mockResolvedValue({ games: [] }),
    launchGame: vi.fn(),
    closeGame: vi.fn(),
    capturePreview: vi.fn(),
    inputProbe: vi.fn(),
    registerHub: vi.fn().mockResolvedValue({ status: 'pending' }),
  },
}));

import App from './App';

it('has no structural axe violations in the main UI', async () => {
  const { container, findByRole } = render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <App />
    </QueryClientProvider>,
  );
  await findByRole('heading', { name: '后台服务已就绪' });
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  expect(result.violations).toEqual([]);
});
