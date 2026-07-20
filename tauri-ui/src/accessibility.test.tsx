import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import { render } from '@testing-library/react';
import { expect, it, vi } from 'vitest';

vi.mock('./lib/agentApi', () => ({
  agentApi: {
    getOverview: vi.fn().mockResolvedValue({ status: { state: 'ConnectedIdle', capture_active: false }, doctor: { profiles: [], runtime: 'dry_run' } }),
    getDoctor: vi.fn().mockResolvedValue({ profiles: [], runtime: 'dry_run' }),
    listProfiles: vi.fn().mockResolvedValue({ profiles: [] }),
    listTargets: vi.fn().mockResolvedValue({ candidates: [] }),
    lockTarget: vi.fn(), focusTarget: vi.fn(), stopCapture: vi.fn(), releaseAll: vi.fn(),
    getUpdateStatus: vi.fn().mockResolvedValue({ status: 'unsupported' }),
    getStartupStatus: vi.fn().mockResolvedValue({ status: 'unsupported' }),
    getConnectionStatus: vi.fn().mockResolvedValue({ hub_address: '', control: 'offline', frame: 'offline', capture_active: false, recovery_code: '' }),
    runEnvironmentCheck: vi.fn().mockResolvedValue({ checks: [] }),
    getLogTail: vi.fn().mockResolvedValue({ entries: [] }),
    scanInstalledGames: vi.fn().mockResolvedValue({ games: [] }),
    startEnrollment: vi.fn().mockResolvedValue({ status: 'elevation_requested' }),
    exportDiagnostics: vi.fn(), stopAgentAfterConfirmation: vi.fn(),
  },
}));

import App from './App';

it('has no structural axe violations in the main UI', async () => {
  const { container, findByRole } = render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <App />
    </QueryClientProvider>,
  );
  await findByRole('heading', { name: 'Agent 概览' });
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  expect(result.violations).toEqual([]);
});
