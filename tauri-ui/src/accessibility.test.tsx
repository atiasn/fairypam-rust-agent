import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import { render } from '@testing-library/react';
import { expect, it, vi } from 'vitest';

vi.mock('./lib/agentApi', () => ({
  agentApi: {
    ensureLocalAgent: vi.fn().mockResolvedValue({ status: 'ready' }),
    getOverview: vi.fn().mockResolvedValue({ status: { state: 'ConnectedIdle', capture_active: false }, doctor: { profiles: [], runtime: 'dry_run' } }),
    getEnrollmentMode: vi.fn().mockResolvedValue({ status: 'standard' }),
    getConnectionStatus: vi.fn().mockResolvedValue({ hub_address: '', control: 'offline', frame: 'offline', capture_active: false, recovery_code: '' }),
    runEnvironmentCheck: vi.fn().mockResolvedValue({ checks: [] }),
    getLogTail: vi.fn().mockResolvedValue({ entries: [] }),
    scanInstalledGames: vi.fn().mockResolvedValue({ games: [] }),
    startEnrollment: vi.fn().mockResolvedValue({ status: 'elevation_requested' }),
    completeEnrollment: vi.fn().mockResolvedValue({ status: 'completed' }),
  },
}));

import App from './App';

it('has no structural axe violations in the main UI', async () => {
  const { container, findByRole } = render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <App />
    </QueryClientProvider>,
  );
  await findByRole('heading', { name: 'Agent 已运行' });
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  expect(result.violations).toEqual([]);
});
