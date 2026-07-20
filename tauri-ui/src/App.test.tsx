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
import { agentApi } from './lib/agentApi';

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

  it('renders each environment check, a redacted fixed log tail, and discovery metadata', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.runEnvironmentCheck).mockResolvedValueOnce({
      checks: [
        { id: 'binary_or_task', status: 'available', code: 'agent.binary_available', recovery: '修复 Agent 安装' },
        { id: 'agent', status: 'available', code: 'agent.running', recovery: '无需操作' },
        { id: 'guardian', status: 'available', code: 'guardian.binary_available', recovery: '修复 Guardian 安装' },
        { id: 'certificate', status: 'available', code: 'runtime.certificate_files_available', recovery: '重新注册' },
        { id: 'control', status: 'connected', code: 'runtime.connected', recovery: '检查 Hub' },
        { id: 'frame', status: 'connected', code: 'runtime.connected', recovery: '检查 Hub' },
        { id: 'profiles', status: 'unavailable', code: 'profile.unavailable', recovery: '安装签名 Profile' },
        { id: 'game_discovery', status: 'available', code: 'game.discovery_ready', recovery: '重新扫描' },
      ],
    });
    vi.mocked(agentApi.getLogTail).mockResolvedValueOnce({
      entries: [{ level: 'warn', message: '[redacted agent log content]' }],
    });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValueOnce({
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: '5.8.0', installed: true, supported: false }],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '诊断' }));
    await user.click(view.getByRole('button', { name: '检查本地环境' }));
    expect(await view.findByText(/二进制\/任务/)).toBeInTheDocument();
    expect(
      view.getAllByRole('listitem').find((item) =>
        item.textContent?.includes('Guardian') && item.textContent.includes('guardian.binary_available')),
    ).toBeDefined();
    expect(
      view.getAllByRole('listitem').some((item) => item.textContent?.includes('[redacted agent log content]')),
    ).toBe(true);
    expect(view.getByText(/不支持路径输入/)).toBeInTheDocument();

    await user.click(view.getByRole('button', { name: '游戏' }));
    expect(await view.findByText('原神')).toBeInTheDocument();
    expect(
      view.getAllByRole('listitem').find((item) => item.textContent?.includes('原神 5.8.0已安装：是；支持：否')),
    ).toBeDefined();
    expect(view.queryByText(/C:\\Games|YuanShen\.exe/)).not.toBeInTheDocument();
  });
});
