import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

vi.mock('./lib/agentApi', () => ({
  agentApi: {
    ensureLocalAgent: vi.fn().mockResolvedValue({ status: 'ready' }),
    getOverview: vi.fn().mockResolvedValue({ status: { state: 'ConnectedIdle', capture_active: false }, doctor: { profiles: ['signed-profile'], runtime: 'dry_run' } }),
    getEnrollmentMode: vi.fn().mockResolvedValue({ status: 'standard' }),
    getConnectionStatus: vi.fn().mockResolvedValue({ hub_address: 'https://hub.test', control: 'connected', frame: 'connected', capture_active: false, recovery_code: '' }),
    runEnvironmentCheck: vi.fn().mockResolvedValue({ checks: [] }),
    getLogTail: vi.fn().mockResolvedValue({ entries: [] }),
    scanInstalledGames: vi.fn().mockResolvedValue({ games: [] }),
    startEnrollment: vi.fn().mockResolvedValue({ status: 'elevation_requested' }),
    completeEnrollment: vi.fn().mockResolvedValue({ status: 'completed' }),
  },
}));

import App from './App';
import { agentApi } from './lib/agentApi';

function renderApp() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <App />
    </QueryClientProvider>,
  );
}

describe('App', () => {
  it('keeps only the confirmed user navigation and wakes the Agent automatically', async () => {
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('heading', { name: 'Agent 已运行' })).toBeInTheDocument();
    expect(agentApi.ensureLocalAgent).toHaveBeenCalledOnce();
    for (const label of ['总览', '连接与注册', '环境检查', '日志', '游戏']) {
      expect(view.getByRole('button', { name: label })).toBeInTheDocument();
    }
    for (const removed of ['首次向导', 'Profile', '目标与预览', '输入安全', '更新', '自启动']) {
      expect(view.queryByRole('button', { name: removed })).not.toBeInTheDocument();
    }
  });

  it('shows non-sensitive Hub status and registration opens a protected window', async () => {
    const user = userEvent.setup();
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '连接与注册' }));
    expect(await view.findByText('https://hub.test')).toBeInTheDocument();
    await user.click(view.getByRole('button', { name: '注册或重新注册' }));
    expect(agentApi.startEnrollment).toHaveBeenCalledOnce();
    expect(view.getByText(/不会显示或写入命令行/)).toBeInTheDocument();
  });

  it('does not start the local Agent while the elevated registration window is loading', async () => {
    vi.mocked(agentApi.ensureLocalAgent).mockClear();
    vi.mocked(agentApi.getEnrollmentMode).mockResolvedValueOnce({ status: 'elevated' });
    renderApp();

    expect(await screen.findByRole('heading', { name: '连接 FairyPam Hub' })).toBeInTheDocument();
    expect(agentApi.ensureLocalAgent).not.toHaveBeenCalled();
  });

  it('does not invoke normal local-control commands from the elevated registration window', async () => {
    const initialCalls = vi.mocked(agentApi.ensureLocalAgent).mock.calls.length;
    vi.mocked(agentApi.getEnrollmentMode).mockResolvedValueOnce({ status: 'elevated' });
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('heading', { name: '连接 FairyPam Hub' })).toBeInTheDocument();
    expect(agentApi.ensureLocalAgent).toHaveBeenCalledTimes(initialCalls);
  });

  it('renders separate environment, log, and discovery-only game surfaces', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.runEnvironmentCheck).mockResolvedValueOnce({
      checks: [{ id: 'guardian', status: 'available', code: 'guardian.binary_available', recovery: '无需操作' }],
    });
    vi.mocked(agentApi.getLogTail).mockResolvedValueOnce({ entries: [{ level: 'warn', message: '[redacted agent log content]' }] });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValueOnce({
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: '5.8.0', installed: true, supported: false }],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '环境检查' }));
    await user.click(view.getByRole('button', { name: '检查本地环境' }));
    expect(await view.findByText(/guardian.binary_available/)).toBeInTheDocument();

    await user.click(view.getByRole('button', { name: '日志' }));
    expect(await view.findByText(/\[redacted agent log content\]/)).toBeInTheDocument();

    await user.click(view.getByRole('button', { name: '游戏' }));
    expect(await view.findByText('原神')).toBeInTheDocument();
    expect(view.queryByText(/C:\\Games|YuanShen\.exe/)).not.toBeInTheDocument();
  });
});
