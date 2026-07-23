import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./lib/agentApi', () => ({
  agentApi: {
    ensureLocalAgent: vi.fn().mockResolvedValue({ status: 'ready' }),
    getOverview: vi.fn().mockResolvedValue({ status: { state: 'ConnectedIdle', capture_active: false }, doctor: { profiles: ['signed-profile'], runtime: 'dry_run' } }),
    getConnectionStatus: vi.fn().mockResolvedValue({ control: 'connected', frame: 'connected', capture_active: false }),
    runEnvironmentCheck: vi.fn().mockResolvedValue({ registration_ready: true, registration_pending: false, checks: [] }),
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
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(agentApi.getLogTail).mockResolvedValue({ entries: [] });
  });

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

  it('启动后自动检查本机环境，并在未就绪时禁用注册', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.runEnvironmentCheck).mockResolvedValueOnce({
      registration_ready: false,
      registration_pending: false,
      checks: [{ id: 'guardian', status: 'unavailable', code: 'guardian.unavailable', recovery: '请处理' }],
    });
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('heading', { name: '后台服务已就绪' })).toBeInTheDocument();
    await waitFor(() => expect(agentApi.runEnvironmentCheck).toHaveBeenCalledOnce());
    await user.click(view.getByRole('button', { name: '连接与注册' }));

    expect(view.getByRole('button', { name: '注册或重新注册' })).toBeDisabled();
    expect(view.getByText('请先完成本机环境检查，再提交注册。')).toBeInTheDocument();
    fireEvent.submit(view.getByRole('button', { name: '注册或重新注册' }).closest('form')!);
    expect(agentApi.registerHub).not.toHaveBeenCalled();
  });

  it('环境检查刷新中或最新检查失败时保持注册禁用', async () => {
    const user = userEvent.setup();
    let rejectRefresh: (reason?: unknown) => void;
    vi.mocked(agentApi.runEnvironmentCheck)
      .mockResolvedValueOnce({ registration_ready: true, registration_pending: false, checks: [] })
      .mockImplementationOnce(() => new Promise((_resolve, reject) => {
        rejectRefresh = reject;
      }));
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '连接与注册' }));
    let register = view.getByRole('button', { name: '注册或重新注册' });
    await waitFor(() => expect(register).toBeEnabled());
    await user.click(view.getByRole('button', { name: '环境检查' }));
    await user.click(view.getByRole('button', { name: '检查本地环境' }));
    expect(await view.findByText('正在检查。')).toBeInTheDocument();

    await user.click(view.getByRole('button', { name: '连接与注册' }));
    register = view.getByRole('button', { name: '注册或重新注册' });
    expect(register).toBeDisabled();
    fireEvent.submit(register.closest('form')!);
    expect(agentApi.registerHub).not.toHaveBeenCalled();

    rejectRefresh!(new Error('环境检查失败'));
    expect(await view.findByText('本机环境暂时无法确认，请稍后重试。')).toBeInTheDocument();
    expect(register).toBeDisabled();
    fireEvent.submit(register.closest('form')!);
    expect(agentApi.registerHub).not.toHaveBeenCalled();
  });

  it('显示中文服务状态并直接提交注册，不回显提交内容', async () => {
    const user = userEvent.setup();
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '连接与注册' }));
    await user.clear(view.getByLabelText('服务地址'));
    await user.type(view.getByLabelText('服务地址'), 'https://register.example');
    await user.type(view.getByLabelText('一次性注册码'), '0123456789abcdef');
    vi.mocked(agentApi.runEnvironmentCheck)
      .mockResolvedValueOnce({ registration_ready: true, registration_pending: true, checks: [] })
      .mockResolvedValueOnce({ registration_ready: true, registration_pending: false, checks: [{ id: 'certificate', status: 'available', code: 'runtime.certificate_files_available', recovery: '无需操作' }] });
    await user.click(view.getByRole('button', { name: '注册或重新注册' }));
    expect(agentApi.registerHub).toHaveBeenCalledWith('https://register.example', '0123456789abcdef');
    expect(view.getByRole('button', { name: '注册或重新注册' })).toBeDisabled();
    expect(await view.findByText('正在完成注册，请稍候。')).toBeInTheDocument();
    expect(view.getByRole('button', { name: '注册或重新注册' })).toBeDisabled();
    expect(view.getByLabelText('服务地址')).toHaveValue('');
    expect(view.getByLabelText('一次性注册码')).toHaveValue('');
    expect(view.getByLabelText('服务地址')).toHaveAttribute('autocomplete', 'off');
    expect(view.getByLabelText('一次性注册码')).toHaveAttribute('autocomplete', 'off');
    expect(view.getByText(/注册码只会通过受保护的通道提交/)).toBeInTheDocument();
    expect(view.queryByText(/UAC|注册窗口|系统确认/)).not.toBeInTheDocument();

  });

  it('注册请求失败时清除注册码且不显示拒绝详情', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.registerHub).mockRejectedValueOnce(new Error('registration-code=not-for-display'));
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '连接与注册' }));
    await user.clear(view.getByLabelText('服务地址'));
    await user.type(view.getByLabelText('服务地址'), 'https://register.example');
    await user.type(view.getByLabelText('一次性注册码'), '0123456789abcdef');
    await user.click(view.getByRole('button', { name: '注册或重新注册' }));

    expect(await view.findByText('注册未完成。请获取新的注册码后重试。')).toBeInTheDocument();
    expect(view.getByLabelText('服务地址')).toHaveValue('');
    expect(view.getByLabelText('一次性注册码')).toHaveValue('');
    expect(view.queryByText('registration-code=not-for-display')).not.toBeInTheDocument();
  });

  it('将自动环境检查映射为中文结果且不暴露机器代码', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.runEnvironmentCheck).mockResolvedValueOnce({
      registration_ready: true,
      registration_pending: false,
      checks: [{ id: 'guardian', status: 'available', code: 'guardian.binary_available', recovery: '无需操作' }],
    });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValueOnce({
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: '5.8.0', installed: true, supported: false }],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '环境检查' }));
    expect(await view.findByRole('listitem')).toHaveTextContent('守护服务：正常');
    expect(view.queryByText('无需操作')).not.toBeInTheDocument();
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

  it('服务状态丢失时禁用注册并提供手动重试', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getOverview).mockRejectedValueOnce({
      code: 'local.transport.disconnected',
      message: '服务连接中断',
    });
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('heading', { name: '服务暂时无法使用' })).toBeInTheDocument();
    expect(view.getByRole('button', { name: '重试启动' })).toBeInTheDocument();
    await user.click(view.getByRole('button', { name: '连接与注册' }));
    expect(view.getByRole('button', { name: '注册或重新注册' })).toBeDisabled();
    expect(view.getByRole('button', { name: '重试启动' })).toBeInTheDocument();
  });

  it('日志和游戏在后台服务就绪前不请求本地通道', async () => {
    const user = userEvent.setup();
    let resolveStartup: (value: { status: string }) => void;
    vi.mocked(agentApi.ensureLocalAgent).mockImplementationOnce(() => new Promise((resolve) => {
      resolveStartup = resolve;
    }));
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '日志' }));
    expect(view.getByText('正在等待后台服务就绪。')).toBeInTheDocument();
    expect(agentApi.getLogTail).not.toHaveBeenCalled();
    resolveStartup!({ status: 'ready' });
    expect(await view.findByText('暂时没有可显示的运行记录。服务正常时，记录可能为空。')).toBeInTheDocument();
    expect(agentApi.getLogTail).toHaveBeenCalledOnce();

    await user.click(view.getByRole('button', { name: '游戏' }));
    expect(await view.findByText('未发现可用游戏。')).toBeInTheDocument();
    expect(agentApi.scanInstalledGames).toHaveBeenCalledOnce();
  });

  it('以中文安全摘要替代英文、协议和机器术语日志，同时保留中文脱敏记录', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getLogTail).mockResolvedValue({
      entries: [
        { level: 'warn', message: '[redacted agent log content]' },
        { level: 'error', message: 'Agent connected to local control' },
        { level: 'error', message: 'local.protocol.nonce_replayed' },
        { level: 'info', message: '127.0.0.1:50051' },
        { level: 'info', message: '已脱敏的运行记录' },
        { level: 'info', message: '服务注册已开始，正在安全领取凭据' },
        { level: 'info', message: '服务注册已完成，正在安全重连' },
        { level: 'warn', message: '服务注册失败（错误码：enrollment.network_failed）' },
      ],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '日志' }));
    const entries = await view.findAllByRole('listitem');
    expect(entries).toHaveLength(8);
    expect(entries[0]).toHaveTextContent('警告：该运行记录包含不适合展示的技术内容。');
    expect(entries[1]).toHaveTextContent('错误：该运行记录包含不适合展示的技术内容。');
    expect(entries[2]).toHaveTextContent('错误：该运行记录包含不适合展示的技术内容。');
    expect(entries[3]).toHaveTextContent('信息：该运行记录包含不适合展示的技术内容。');
    expect(entries[4]).toHaveTextContent('信息：已脱敏的运行记录');
    expect(entries[5]).toHaveTextContent('信息：服务注册已开始，正在安全领取凭据');
    expect(entries[6]).toHaveTextContent('信息：服务注册已完成，正在安全重连');
    expect(entries[7]).toHaveTextContent('警告：服务注册失败（错误码：enrollment.network_failed）');
    expect(entries[0]).not.toHaveTextContent('[redacted agent log content]');
    expect(entries[1]).not.toHaveTextContent('Agent connected to local control');
    expect(entries[2]).not.toHaveTextContent('local.protocol.nonce_replayed');
    expect(entries[3]).not.toHaveTextContent('127.0.0.1:50051');
  });
});
