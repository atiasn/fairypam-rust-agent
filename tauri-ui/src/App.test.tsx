import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
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
    getConnectionStatus: vi.fn().mockResolvedValue({ hub_address: 'https://hub.test', control: 'connected', frame: 'connected', capture_active: false, recovery_code: '' }),
    runEnvironmentCheck: vi.fn().mockResolvedValue({ checks: [] }),
    getLogTail: vi.fn().mockResolvedValue({ entries: [] }),
    scanInstalledGames: vi.fn().mockResolvedValue({ games: [] }),
    startEnrollment: vi.fn().mockResolvedValue({ status: 'elevation_requested' }),
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

  it('shows non-sensitive Hub status and the discovery-only game list', async () => {
    const user = userEvent.setup();
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '连接' }));
    expect(await view.findByText('https://hub.test')).toBeInTheDocument();
    expect(view.getByRole('button', { name: '注册或重新注册' })).toBeInTheDocument();
    expect(view.getByText(/注册码、CA 和私钥不会出现在此界面/)).toBeInTheDocument();

    await user.click(view.getByRole('button', { name: '游戏' }));
    expect(await view.findByRole('heading', { name: '已发现的米哈游游戏' })).toBeInTheDocument();
    expect(view.getByText(/不接收或显示任意 EXE 路径/)).toBeInTheDocument();
  });
});
