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
  it('仅显示中文产品导航并自动准备后台服务', async () => {
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('heading', { name: '后台服务已就绪' })).toBeInTheDocument();
    expect(agentApi.ensureLocalAgent).toHaveBeenCalledOnce();
    for (const label of ['总览', '连接与注册', '环境检查', '日志', '游戏']) {
      expect(view.getByRole('button', { name: label })).toBeInTheDocument();
    }
    for (const removed of ['首次向导', 'Profile', '目标与预览', '输入安全', '更新', '自启动']) {
      expect(view.queryByRole('button', { name: removed })).not.toBeInTheDocument();
    }
  });

  it('连接等待超时时仍以中文说明服务会继续恢复', async () => {
    vi.mocked(agentApi.ensureLocalAgent).mockResolvedValueOnce({ status: 'hub_wait_timeout' });
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByText('服务已就绪，正在重试连接')).toBeInTheDocument();
    expect(await view.findByText('正在持续尝试连接，您仍可继续使用本地功能。')).toBeInTheDocument();
    expect(view.queryByText('服务启动需要处理')).not.toBeInTheDocument();
  });

  it('显示中文服务状态并只通过固定通道提交注册', async () => {
    const user = userEvent.setup();
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '连接与注册' }));
    expect(await view.findByText('https://hub.test')).toBeInTheDocument();
    await user.clear(view.getByLabelText('服务地址'));
    await user.type(view.getByLabelText('服务地址'), 'https://register.example');
    await user.type(view.getByLabelText('一次性注册码'), '0123456789abcdef');
    await user.click(view.getByRole('button', { name: '注册或重新注册' }));
    expect(agentApi.registerHub).toHaveBeenCalledWith('https://register.example', '0123456789abcdef');
    expect(await view.findByText('请在系统确认窗口中确认注册；确认前不会使用注册码。若未在短时间内确认，本次注册会失效。')).toBeInTheDocument();
    expect(view.getByLabelText('一次性注册码')).toHaveValue('');
    expect(view.getByText(/注册码只会通过受保护的通道提交/)).toBeInTheDocument();
    expect(view.queryByText(/UAC|注册窗口/)).not.toBeInTheDocument();
  });

  it('将环境检查映射为中文结果且不暴露机器代码', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.runEnvironmentCheck).mockResolvedValueOnce({
      checks: [{ id: 'guardian', status: 'available', code: 'guardian.binary_available', recovery: '无需操作' }],
    });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValueOnce({
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: '5.8.0', installed: true, supported: false }],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '环境检查' }));
    await user.click(view.getByRole('button', { name: '检查本地环境' }));
    expect(await view.findByRole('listitem')).toHaveTextContent('守护服务：正常；无需操作');
    expect(view.queryByText('guardian.binary_available')).not.toBeInTheDocument();

    await user.click(view.getByRole('button', { name: '游戏' }));
    expect(await view.findByText('原神')).toBeInTheDocument();
    expect(view.queryByText(/C:\\Games|YuanShen\.exe/)).not.toBeInTheDocument();
  });

  it('未知运行模式保持中性中文状态', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getOverview).mockResolvedValueOnce({
      status: { state: 'ConnectedIdle', capture_active: false },
      doctor: { profiles: ['signed-profile'], runtime: 'future_mode' },
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '环境检查' }));
    expect(await view.findByText('运行模式：正在确认')).toBeInTheDocument();
    expect(view.queryByText('future_mode')).not.toBeInTheDocument();
  });

  it('日志为空时显示清晰的中文空状态', async () => {
    const user = userEvent.setup();
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '日志' }));
    expect(await view.findByText('暂时没有可显示的运行记录。服务正常时，记录可能为空。')).toBeInTheDocument();
  });

  it('以中文安全摘要替代英文、协议和机器术语日志，同时保留中文脱敏记录', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getLogTail).mockResolvedValueOnce({
      entries: [
        { level: 'warn', message: '[redacted agent log content]' },
        { level: 'error', message: 'Agent connected to local control' },
        { level: 'error', message: 'local.protocol.nonce_replayed' },
        { level: 'info', message: '127.0.0.1:50051' },
        { level: 'info', message: '已脱敏的运行记录' },
      ],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '日志' }));
    const entries = await view.findAllByRole('listitem');
    expect(entries).toHaveLength(5);
    expect(entries[0]).toHaveTextContent('警告：该运行记录包含不适合展示的技术内容。');
    expect(entries[1]).toHaveTextContent('错误：该运行记录包含不适合展示的技术内容。');
    expect(entries[2]).toHaveTextContent('错误：该运行记录包含不适合展示的技术内容。');
    expect(entries[3]).toHaveTextContent('信息：该运行记录包含不适合展示的技术内容。');
    expect(entries[4]).toHaveTextContent('信息：已脱敏的运行记录');
    expect(entries[0]).not.toHaveTextContent('[redacted agent log content]');
    expect(entries[1]).not.toHaveTextContent('Agent connected to local control');
    expect(entries[2]).not.toHaveTextContent('local.protocol.nonce_replayed');
    expect(entries[3]).not.toHaveTextContent('127.0.0.1:50051');
  });
});
