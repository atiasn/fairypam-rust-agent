import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

vi.mock('./lib/agentApi', () => ({
  agentApi: {
    getOverview: vi.fn().mockResolvedValue({ status: { state: 'ConnectedIdle', capture_active: false }, doctor: { profiles: ['signed-profile'], runtime: 'dry_run' } }),
    getDoctor: vi.fn().mockResolvedValue({ profiles: ['signed-profile'], runtime: 'dry_run' }),
    listProfiles: vi.fn().mockResolvedValue({ profiles: ['signed-profile'] }),
    listTargets: vi.fn().mockResolvedValue({ candidates: [] }),
    lockTarget: vi.fn(),
    focusTarget: vi.fn(),
    stopCapture: vi.fn(),
    releaseAll: vi.fn(),
    getUpdateStatus: vi.fn().mockResolvedValue({ status: 'unsupported' }),
    getStartupStatus: vi.fn().mockResolvedValue({ status: 'unsupported' }),
    exportDiagnostics: vi.fn(),
    stopAgentAfterConfirmation: vi.fn(),
  },
}));

import App from './App';

function renderApp() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <App />
    </QueryClientProvider>,
  );
}

describe('App', () => {
  it('renders a keyboard-accessible profile-to-target flow', async () => {
    const user = userEvent.setup();
    renderApp();

    expect(await screen.findByRole('heading', { name: 'Agent 概览' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Profile' }));
    expect(await screen.findByRole('button', { name: 'signed-profile' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'signed-profile' }));
    expect(await screen.findByRole('heading', { name: '目标窗口' })).toBeInTheDocument();
  });
});
