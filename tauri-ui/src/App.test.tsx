import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

vi.mock('./lib/agentApi', () => ({
  agentApi: {
    ensureLocalAgent: vi.fn().mockResolvedValue({ status: 'ready' }),
    getOverview: vi.fn().mockResolvedValue({ status: { state: 'ConnectedIdle', capture_active: false }, doctor: { profiles: ['signed-profile'], runtime: 'dry_run' } }),
    getConnectionStatus: vi.fn().mockResolvedValue({ hub_address: 'https://hub.test', control: 'connected', frame: 'connected', capture_active: false, recovery_code: '' }),
    runEnvironmentCheck: vi.fn().mockResolvedValue({ checks: [] }),
    getLogTail: vi.fn().mockResolvedValue({ entries: [] }),
    scanInstalledGames: vi.fn().mockResolvedValue({ games: [] }),
    registerHub: vi.fn().mockResolvedValue({ status: 'pending' }),
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

  it('keeps the Agent usable when the bounded Hub observation times out', async () => {
    vi.mocked(agentApi.ensureLocalAgent).mockResolvedValueOnce({ status: 'hub_wait_timeout' });
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByText('Agent 已就绪，Hub 正在重试连接')).toBeInTheDocument();
    expect(await view.findByText('已等待 Hub 连接 20 秒，Agent 会继续在后台重试。')).toBeInTheDocument();
    expect(view.queryByText('Agent 启动需要处理')).not.toBeInTheDocument();
  });

  it('shows non-sensitive Hub status and submits registration only through the local Gateway', async () => {
    const user = userEvent.setup();
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '连接与注册' }));
    expect(await view.findByText('https://hub.test')).toBeInTheDocument();
    await user.clear(view.getByLabelText('Hub HTTPS 地址'));
    await user.type(view.getByLabelText('Hub HTTPS 地址'), 'https://register.example');
    await user.type(view.getByLabelText('一次性注册码'), '0123456789abcdef');
    await user.click(view.getByRole('button', { name: '注册或重新注册' }));
    expect(agentApi.registerHub).toHaveBeenCalledWith('https://register.example', '0123456789abcdef');
    expect(await view.findByText('请在高权限 FairyPam Agent 确认注册；确认前不会使用注册码。若未在短时间内确认，本次注册会失效。')).toBeInTheDocument();
    expect(view.getByLabelText('一次性注册码')).toHaveValue('');
    expect(view.getByText(/注册码只经已验证的本地 Agent 通道提交/)).toBeInTheDocument();
    expect(view.queryByText(/UAC|注册窗口/)).not.toBeInTheDocument();
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
