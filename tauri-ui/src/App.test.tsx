import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const activation = vi.hoisted(() => ({ handler: undefined as undefined | (() => void) }));
const runtimeFailure = vi.hoisted(() => ({ handler: undefined as undefined | (() => void) }));
const emergencyReset = vi.hoisted(() => ({ handler: undefined as undefined | (() => void) }));
const emergencyResetFailed = vi.hoisted(() => ({ handler: undefined as undefined | (() => void) }));

vi.mock('./lib/agentApi', () => ({
  agentApi: {
    ensureLocalAgent: vi.fn().mockResolvedValue({ status: 'ready' }),
    onLocalAgentActivation: vi.fn(async (handler: () => void) => {
      activation.handler = handler;
      return () => {
        activation.handler = undefined;
      };
    }),
    onEmbeddedRuntimeFailed: vi.fn(async (handler: () => void) => {
      runtimeFailure.handler = handler;
      return () => {
        runtimeFailure.handler = undefined;
      };
    }),
    onEmergencyReset: vi.fn(async (handler: () => void) => {
      emergencyReset.handler = handler;
      return () => {
        emergencyReset.handler = undefined;
      };
    }),
    onEmergencyResetFailed: vi.fn(async (handler: () => void) => {
      emergencyResetFailed.handler = handler;
      return () => {
        emergencyResetFailed.handler = undefined;
      };
    }),
    getOverview: vi.fn().mockResolvedValue({ status: { state: 'ConnectedIdle', task_active: false, capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'idle_no_holds' }, doctor: { profiles: ['signed-profile'], runtime: 'production' } }),
    getConnectionStatus: vi.fn().mockResolvedValue({ control: 'connected', frame: 'connected', capture_active: false }),
    runEnvironmentCheck: vi.fn().mockResolvedValue({ registration_ready: true, registration_pending: false, checks: [] }),
    getLogTail: vi.fn().mockResolvedValue({ entries: [] }),
    scanInstalledGames: vi.fn().mockResolvedValue({ games: [] }),
    launchGame: vi.fn().mockResolvedValue({ profile_id: 'signed-profile', pid: 42, state: 'TargetLocked' }),
    closeGame: vi.fn().mockResolvedValue({ profile_id: 'signed-profile', closed: true, state: 'ConnectedIdle' }),
    capturePreview: vi.fn().mockResolvedValue({ mime_type: 'image/jpeg', width: 1, height: 1, bytes: [1] }),
    inputProbe: vi.fn().mockResolvedValue({ state: 'released' }),
    releaseAll: vi.fn().mockResolvedValue({ state: 'EmergencyStopped', holds: 0, cleanup_complete: true, error_code: null }),
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
    activation.handler = undefined;
    runtimeFailure.handler = undefined;
    emergencyReset.handler = undefined;
    emergencyResetFailed.handler = undefined;
    vi.mocked(agentApi.ensureLocalAgent).mockResolvedValue({ status: 'ready' });
    vi.mocked(agentApi.getOverview).mockResolvedValue({
      status: { state: 'ConnectedIdle', task_active: false, capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'idle_no_holds' },
      doctor: { profiles: ['signed-profile'], runtime: 'production' },
    });
    vi.mocked(agentApi.getLogTail).mockResolvedValue({ entries: [] });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValue({ games: [] });
  });

  it('仅显示中文产品导航并自动准备本机 Core', async () => {
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('heading', { name: '本机 Core 已就绪' })).toBeInTheDocument();
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

    expect(await view.findByText('已就绪，Hub 重连中')).toBeInTheDocument();
    expect(await view.findByText('Hub 正在重连，您仍可继续使用安全的本地功能。')).toBeInTheDocument();
    expect(view.queryByText('服务启动需要处理')).not.toBeInTheDocument();
  });

  it('重复打开触发恢复失败时立即清除旧的已连接状态', async () => {
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByText('已就绪，Hub 已连接')).toBeInTheDocument();
    await waitFor(() => expect(activation.handler).toBeTypeOf('function'));
    vi.mocked(agentApi.ensureLocalAgent).mockRejectedValueOnce(new Error('UAC denied'));
    await act(async () => activation.handler?.());

    expect(await view.findByText('服务启动需要处理')).toBeInTheDocument();
    expect(view.queryByText('已就绪，Hub 已连接')).not.toBeInTheDocument();
    expect(view.queryByRole('heading', { name: '本机 Core 已就绪' })).not.toBeInTheDocument();
    expect(view.queryByRole('button', { name: '重启后台服务' })).not.toBeInTheDocument();
    expect(view.queryByRole('button', { name: '修复后台服务' })).not.toBeInTheDocument();
    await userEvent.click(view.getByRole('button', { name: '重试启动' }));
    expect(await view.findByRole('heading', { name: '本机 Core 已就绪' })).toBeInTheDocument();
    expect(view.getByText('已就绪，Hub 已连接')).toHaveClass('online');
  });

  it('重复打开恢复期间隐藏旧状态，完成后恢复在线操作', async () => {
    let finishStartup: (value: { status: string }) => void;
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('heading', { name: '本机 Core 已就绪' })).toBeInTheDocument();
    await waitFor(() => expect(activation.handler).toBeTypeOf('function'));
    vi.mocked(agentApi.ensureLocalAgent).mockImplementationOnce(() => new Promise((resolve) => {
      finishStartup = resolve;
    }));

    act(() => activation.handler?.());

    expect(await view.findByText('正在准备本机 Core')).toBeInTheDocument();
    expect(view.getByRole('heading', { name: '正在准备本机 Core' })).toBeInTheDocument();
    expect(view.queryByRole('heading', { name: '本机 Core 已就绪' })).not.toBeInTheDocument();
    expect(view.queryByText(/运行状态：/)).not.toBeInTheDocument();

    finishStartup!({ status: 'ready' });

    const ready = await view.findByText('已就绪，Hub 已连接');
    expect(ready).toHaveClass('online');
    expect(await view.findByRole('heading', { name: '本机 Core 已就绪' })).toBeInTheDocument();
    await userEvent.click(view.getByRole('button', { name: '连接与注册' }));
    expect(view.getByRole('button', { name: '注册或重新注册' })).toBeEnabled();
  });

  it('Core 异常结束后立即锁定界面并清除在线状态', async () => {
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByText('已就绪，Hub 已连接')).toBeInTheDocument();
    await waitFor(() => expect(runtimeFailure.handler).toBeTypeOf('function'));
    act(() => runtimeFailure.handler?.());

    expect(await view.findByRole('heading', { name: '本机 Core 已停止' })).toBeInTheDocument();
    expect(view.queryByText('已就绪，Hub 已连接')).not.toBeInTheDocument();
    expect(view.queryByRole('heading', { name: '本机 Core 已就绪' })).not.toBeInTheDocument();
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

    expect(await view.findByRole('heading', { name: '本机 Core 已就绪' })).toBeInTheDocument();
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
    vi.mocked(agentApi.ensureLocalAgent)
      .mockResolvedValueOnce({ status: 'agent_ready' })
      .mockResolvedValueOnce({ status: 'ready' });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '连接与注册' }));
    await user.clear(view.getByLabelText('服务地址'));
    await user.type(view.getByLabelText('服务地址'), 'https://register.example');
    await user.type(view.getByLabelText('一次性注册码'), '0123456789abcdef');
    vi.mocked(agentApi.runEnvironmentCheck).mockResolvedValue({
      registration_ready: true,
      registration_pending: false,
      checks: [{ id: 'certificate', status: 'available', code: 'runtime.certificate_files_available', recovery: '无需操作' }],
    });
    await user.click(view.getByRole('button', { name: '注册或重新注册' }));
    expect(agentApi.registerHub).toHaveBeenCalledWith('https://register.example', '0123456789abcdef');
    expect(await view.findByText('注册已完成，正在连接服务。')).toBeInTheDocument();
    expect(await view.findByText('已就绪，Hub 已连接')).toBeInTheDocument();
    expect(agentApi.ensureLocalAgent).toHaveBeenCalledTimes(2);
    expect(view.getByRole('button', { name: '注册或重新注册' })).toBeEnabled();
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
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: '5.8.0', installed: true, supported: false, profile_id: null }],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '环境检查' }));
    expect(await view.findByText('运行模式：正常服务')).toBeInTheDocument();
    expect(await view.findByRole('listitem')).toHaveTextContent('守护服务：正常');
    expect(view.queryByText('无需操作')).not.toBeInTheDocument();
    expect(view.queryByText('guardian.binary_available')).not.toBeInTheDocument();

    await user.click(view.getByRole('button', { name: '游戏' }));
    expect(await view.findByText('原神')).toBeInTheDocument();
    expect(view.queryByText(/C:\\Games|YuanShen\.exe/)).not.toBeInTheDocument();
  });

  it('只为已签名 Profile 暴露固定的本地游戏控制', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getOverview)
      .mockResolvedValueOnce({
        status: { state: 'ConnectedIdle', task_active: false, capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'idle_no_holds' },
        doctor: { profiles: ['signed-profile'], runtime: 'production' },
      })
      .mockResolvedValueOnce({
        status: { state: 'TargetLocked', task_active: false, capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'active' },
        doctor: { profiles: ['signed-profile'], runtime: 'production' },
      })
      .mockResolvedValue({
        status: { state: 'ConnectedIdle', task_active: false, capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'idle_no_holds' },
        doctor: { profiles: ['signed-profile'], runtime: 'production' },
      });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValueOnce({
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: null, installed: true, supported: true, profile_id: 'signed-profile' }],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '游戏' }));
    await user.click(await view.findByRole('button', { name: '启动并锁定' }));
    expect(agentApi.launchGame).toHaveBeenCalledWith('signed-profile');
    await user.click(await view.findByRole('button', { name: 'W 前进探针' }));
    expect(agentApi.inputProbe).toHaveBeenCalledWith('move_forward');
    await user.click(view.getByRole('button', { name: '关闭游戏' }));
    expect(agentApi.closeGame).toHaveBeenCalledOnce();
    await user.click(view.getByRole('button', { name: '紧急停止并释放输入' }));
    expect(agentApi.releaseAll).toHaveBeenCalledOnce();
    expect(await view.findByText('已紧急停止并释放全部输入。')).toBeInTheDocument();
  });

  it('保护状态仍展示日志和已发现游戏，并在确认恢复前禁用启动', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getOverview)
      .mockResolvedValueOnce({
        status: { state: 'EmergencyStopped', task_active: false, capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'emergency_stopped' },
        doctor: { profiles: ['signed-profile'], runtime: 'production' },
      })
      .mockResolvedValue({
        status: { state: 'ConnectedIdle', task_active: false, capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'idle_no_holds' },
        doctor: { profiles: ['signed-profile'], runtime: 'production' },
      });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValueOnce({
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: null, installed: true, supported: true, profile_id: 'signed-profile' }],
    });
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('heading', { name: '本机 Core 处于保护状态' })).toBeInTheDocument();
    await waitFor(() => expect(emergencyResetFailed.handler).toBeTypeOf('function'));
    act(() => emergencyResetFailed.handler?.());
    expect(view.getByRole('alert')).toHaveTextContent('清理尚未完成，保护状态保持不变');
    expect(view.getByRole('heading', { name: '本机 Core 处于保护状态' })).toBeInTheDocument();
    await user.click(view.getByRole('button', { name: '日志' }));
    expect(await view.findByText('暂时没有可显示的运行记录。服务正常时，记录可能为空。')).toBeInTheDocument();
    expect(agentApi.getLogTail).toHaveBeenCalled();

    await user.click(view.getByRole('button', { name: '游戏' }));
    expect(await view.findByText('原神')).toBeInTheDocument();
    expect(view.getByText(/当前处于保护状态/)).toBeInTheDocument();
    const launch = view.getByRole('button', { name: '启动并锁定' });
    expect(launch).toBeDisabled();
    expect(view.getByText(/请从系统托盘选择“解除保护”/)).toBeInTheDocument();
    await waitFor(() => expect(emergencyReset.handler).toBeTypeOf('function'));
    act(() => emergencyReset.handler?.());
    await waitFor(() => expect(launch).toBeEnabled());
    expect(view.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('活动任务期间保留只读页面并禁用新的本地游戏启动', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getOverview).mockResolvedValueOnce({
      status: { state: 'TargetLocked', task_active: true, capture_active: true, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'active' },
      doctor: { profiles: ['signed-profile'], runtime: 'production' },
    });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValueOnce({
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: null, installed: true, supported: true, profile_id: 'signed-profile' }],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(await view.findByRole('button', { name: '日志' }));
    expect(await view.findByText('暂时没有可显示的运行记录。服务正常时，记录可能为空。')).toBeInTheDocument();
    await user.click(view.getByRole('button', { name: '游戏' }));
    expect(await view.findByText('原神')).toBeInTheDocument();
    expect(view.getByRole('button', { name: '启动并锁定' })).toBeDisabled();
    expect(view.queryByRole('button', { name: '更新截图' })).not.toBeInTheDocument();
  });

  it('重新打开游戏页时从 Core 锁定状态恢复设备控制', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getOverview).mockResolvedValueOnce({
      status: { state: 'TargetLocked', task_active: false, capture_active: true, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'active' },
      doctor: { profiles: ['signed-profile'], runtime: 'production' },
    });
    vi.mocked(agentApi.scanInstalledGames).mockResolvedValueOnce({
      games: [{ discovery_id: 'mihoyo:stable-id', name: '原神', version: null, installed: true, supported: true, profile_id: 'signed-profile' }],
    });
    const app = renderApp();
    const view = within(app.container);

    await user.click(await view.findByRole('button', { name: '游戏' }));
    expect(await view.findByRole('button', { name: '更新截图' })).toBeEnabled();
    expect(view.getByRole('button', { name: '关闭游戏' })).toBeEnabled();
    expect(view.getByRole('button', { name: '启动并锁定' })).toBeDisabled();

    vi.mocked(agentApi.getOverview).mockRejectedValueOnce(new Error('overview unavailable'));
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    await waitFor(() => expect(view.getByRole('button', { name: '更新截图' })).toBeDisabled());
    expect(view.getByRole('button', { name: '关闭游戏' })).toBeDisabled();
  });

  it('紧急停止结果未知时提示保持程序运行', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.releaseAll).mockRejectedValueOnce(new Error('unknown cleanup state'));
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '游戏' }));
    await user.click(view.getByRole('button', { name: '紧急停止并释放输入' }));

    expect(await view.findByText('紧急停止结果无法确认。请保持 FairyPam 运行、停止操作游戏并联系管理员。')).toBeInTheDocument();
  });

  it('紧急停止未完全收口时保持安全警告', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.releaseAll).mockResolvedValueOnce({ state: 'EmergencyStopped', holds: 0, cleanup_complete: false, error_code: 'cleanup_incomplete' });
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '游戏' }));
    await user.click(view.getByRole('button', { name: '紧急停止并释放输入' }));

    expect(await view.findByText('紧急停止未完全收口，请保持程序运行并联系管理员。')).toBeInTheDocument();
  });

  it('未知运行模式保持中性中文状态', async () => {
    const user = userEvent.setup();
    vi.mocked(agentApi.getOverview).mockResolvedValueOnce({
      status: { state: 'ConnectedIdle', task_active: false, capture_active: false, build_id: 'test-build', suite_version: '0.1.1', guardian_state: 'idle_no_holds' },
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

    expect(await view.findByRole('heading', { name: '本机 Core 状态不可用' })).toBeInTheDocument();
    expect(view.getByRole('button', { name: '重试启动' })).toBeInTheDocument();
    await user.click(view.getByRole('button', { name: '连接与注册' }));
    expect(view.getByRole('button', { name: '注册或重新注册' })).toBeDisabled();
    expect(view.getByRole('button', { name: '重试启动' })).toBeInTheDocument();
  });

  it('本机 Core 异常时只提供原进程内重试', async () => {
    vi.mocked(agentApi.ensureLocalAgent).mockRejectedValueOnce({
      code: 'startup.agent_repair_required',
      message: '需要修复',
    });
    const app = renderApp();
    const view = within(app.container);

    expect(await view.findByRole('button', { name: '重试启动' })).toBeInTheDocument();
    expect(view.getByText('本机 Core 需要修复')).toBeInTheDocument();
    expect(view.queryByRole('button', { name: '重启后台服务' })).not.toBeInTheDocument();
    expect(view.queryByRole('button', { name: '修复后台服务' })).not.toBeInTheDocument();
  });

  it('日志和游戏在本机 Core 就绪前不请求固定命令面', async () => {
    const user = userEvent.setup();
    let resolveStartup: (value: { status: string }) => void;
    vi.mocked(agentApi.ensureLocalAgent).mockImplementationOnce(() => new Promise((resolve) => {
      resolveStartup = resolve;
    }));
    const app = renderApp();
    const view = within(app.container);

    await user.click(view.getByRole('button', { name: '日志' }));
    expect(view.getByText('正在等待本机 Core 就绪。')).toBeInTheDocument();
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
