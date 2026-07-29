import { useCallback, useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { agentApi } from './lib/agentApi';
import { canMutate } from './lib/connectionReducer';
import { queryKeys } from './lib/queryKeys';
import { useAgentQueries } from './lib/useAgentQueries';
import { useConnectionState } from './lib/useConnectionState';
import { StatusPanel } from './components/StatusPanel';
import { ConnectionPage } from './pages/ConnectionPage';
import { DashboardPage } from './pages/DashboardPage';
import { DiagnosticsPage } from './pages/DiagnosticsPage';
import { GamesPage } from './pages/GamesPage';
import { LogsPage } from './pages/LogsPage';

type Page = 'dashboard' | 'connection' | 'environment' | 'logs' | 'games';

const navigation: Array<{ id: Page; label: string; hint: string }> = [
  { id: 'dashboard', label: '总览', hint: '运行概览' },
  { id: 'connection', label: '连接与注册', hint: 'Hub / Agent' },
  { id: 'environment', label: '环境检查', hint: '设备诊断' },
  { id: 'logs', label: '日志', hint: '最近日志' },
  { id: 'games', label: '游戏', hint: '本机发现' },
];

function startupLabel(isPending: boolean, error: unknown) {
  if (isPending) return '正在准备本机 Core';
  if (
    typeof error === 'object'
    && error !== null
    && 'code' in error
    && error.code === 'startup.agent_repair_required'
  ) return '本机 Core 需要修复';
  if (error) return '服务启动需要处理';
  return '已就绪';
}

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [activationState, setActivationState] = useState<'pending' | 'failed' | 'runtime-failed'>();
  const [emergencyResetFailed, setEmergencyResetFailed] = useState(false);
  const startup = useQuery({
    queryKey: queryKeys.startup,
    queryFn: agentApi.ensureLocalAgent,
    retry: false,
  });
  const queries = useAgentQueries(startup.isSuccess);
  const { connection, dispatch } = useConnectionState(queries.overview.isSuccess, queries.overview.error);
  const runtimeState = queries.overview.data?.status.state.toLowerCase();
  const taskActive = queries.overview.data?.status.task_active ?? false;
  const emergency = runtimeState === 'emergencystopped';
  const coreObservable = startup.isSuccess
    && !activationState
    && queries.overview.isSuccess
    && (connection.availability === 'online' || connection.availability === 'emergency');
  const canChangeRuntime = coreObservable && canMutate(connection) && runtimeState === 'connectedidle';
  const refreshAgentState = useCallback(async () => {
    const startupResult = await startup.refetch();
    if (startupResult.isError) {
      setActivationState('failed');
      return;
    }
    const [overviewResult] = await Promise.all([
      queries.overview.refetch(),
      queries.environment.refetch(),
    ]);
    if (overviewResult.isError) {
      setActivationState('failed');
      return;
    }
    dispatch({ type: 'QuerySucceeded' });
    setActivationState(undefined);
  }, [dispatch, queries.environment.refetch, queries.overview.refetch, startup.refetch]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void agentApi.onLocalAgentActivation(() => {
      setActivationState('pending');
      dispatch({ type: 'ExplicitOffline', code: 'startup.activation_pending' });
      void refreshAgentState();
    }).then((cleanup) => {
      if (disposed) cleanup();
      else unlisten = cleanup;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [dispatch, refreshAgentState]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void agentApi.onEmbeddedRuntimeFailed(() => {
      setActivationState('runtime-failed');
      dispatch({ type: 'ExplicitOffline', code: 'runtime.embedded_failed' });
    }).then((cleanup) => {
      if (disposed) cleanup();
      else unlisten = cleanup;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [dispatch]);

  useEffect(() => {
    if (emergency) {
      dispatch({ type: 'ExplicitEmergency', code: 'agent.guardian.emergency' });
    }
  }, [dispatch, emergency]);

  const refreshAfterEmergencyReset = useCallback(async () => {
    const overviewResult = await queries.overview.refetch();
    if (overviewResult.isError || overviewResult.data?.status.state.toLowerCase() === 'emergencystopped') {
      return;
    }
    setEmergencyResetFailed(false);
    dispatch({ type: 'Reset' });
    dispatch({ type: 'QuerySucceeded' });
    void queries.environment.refetch();
  }, [dispatch, queries.environment.refetch, queries.overview.refetch]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void agentApi.onEmergencyReset(() => {
      void refreshAfterEmergencyReset();
    }).then((cleanup) => {
      if (disposed) cleanup();
      else unlisten = cleanup;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [refreshAfterEmergencyReset]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void agentApi.onEmergencyResetFailed(() => {
      setEmergencyResetFailed(true);
    }).then((cleanup) => {
      if (disposed) cleanup();
      else unlisten = cleanup;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const common = {
    connection,
    canMutate: canChangeRuntime,
    environment: queries.environment,
    overview: queries.overview,
    startup,
    retryStartup: () => {
      void refreshAgentState();
    },
  };
  const startupText = activationState === 'runtime-failed'
    ? '本机 Core 已停止'
    : !activationState && queries.overview.error
      ? '状态不可用'
      : startupLabel(
        startup.isPending || activationState === 'pending',
        activationState === 'failed' ? new Error('activation failed') : startup.error,
      );
  const statusTone = connection.availability === 'online'
    ? 'green'
    : connection.availability === 'offline' || connection.availability === 'emergency'
      ? 'red'
      : 'warn';
  const currentPage = navigation.find((item) => item.id === page) ?? navigation[0];

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <span aria-hidden="true" className="brand-mark" />
          <div className="brand-title">
            <strong>FairyPam Agent</strong>
            <span>Night Ops Console</span>
          </div>
        </div>
        <div className="status-strip">
          <p aria-live="polite" className={`chip ${statusTone}`}>
            <span aria-hidden="true" className={`led ${statusTone}`} />
            本机 Core <strong className={connection.availability}>{startupText}</strong>
          </p>
          <p className="chip">协议 <strong>gRPC + mTLS V2</strong></p>
        </div>
      </header>
      <div className="shell">
        <nav aria-label="控制中心导航" className="nav">
          <div className="nav-card">
            <b>夜间值守</b>
            <span>可信设备控制台</span>
            <div aria-hidden="true" className="mini-bars"><i /><i /><i /></div>
          </div>
          <p className="nav-label">Control Surface</p>
          {navigation.map((item) => (
            <button
              aria-label={item.label}
              aria-current={page === item.id ? 'page' : undefined}
              className={page === item.id ? 'active' : undefined}
              key={item.id}
              onClick={() => setPage(item.id)}
              type="button"
            >
              <span>{item.label}<small>{item.hint}</small></span>
            </button>
          ))}
          <p className="nav-note">关闭窗口不会停止本机 Core。安全退出请使用系统托盘。</p>
        </nav>
        <main className="main">
          <div className="page-head">
            <div>
              <p className="kicker">FAIRYPAM // 夜间值守</p>
              <h1>控制中心</h1>
              <p className="sub">{currentPage.label} · {currentPage.hint}</p>
            </div>
            <span className="mode">SECURE CHANNEL / V2</span>
          </div>
          {activationState === 'pending' && (
            <StatusPanel availability="unknown" title="正在准备本机 Core" detail="正在检查本机运行状态。" />
          )}
          {activationState === 'runtime-failed' && (
            <StatusPanel
              availability="offline"
              title="本机 Core 已停止"
              detail="为保护游戏操作，本次会话已锁定。请从系统托盘安全退出 FairyPam，然后重新启动。"
            />
          )}
          {activationState === 'failed' && (
            <>
              <StatusPanel availability="offline" title="本机 Core 暂时无法使用" detail="请重试检查本机运行状态。" />
              <div className="actions">
                <button
                  onClick={() => {
                    setActivationState('pending');
                    void refreshAgentState();
                  }}
                  type="button"
                >
                  重试启动
                </button>
              </div>
            </>
          )}
          {emergencyResetFailed && (
            <p role="alert">清理尚未完成，保护状态保持不变。请再次执行紧急停止并释放输入后重试。</p>
          )}
          {!activationState && page === 'dashboard' && <DashboardPage {...common} hubStatus={queries.hubStatus} />}
          {!activationState && page === 'connection' && <ConnectionPage {...common} status={queries.hubStatus} />}
          {!activationState && page === 'environment' && (
            <DiagnosticsPage enabled={coreObservable} environment={queries.environment} overview={queries.overview} />
          )}
          {!activationState && page === 'logs' && <LogsPage enabled={coreObservable} />}
          {!activationState && page === 'games' && (
            <GamesPage
              canStart={canChangeRuntime}
              emergency={emergency}
              enabled={coreObservable}
              targetActive={runtimeState === 'targetlocked' && !taskActive}
            />
          )}
        </main>
        <aside className="operator" aria-label="值守状态">
          <section className="operator-card">
            <div aria-hidden="true" className="operator-visual"><span className="avatar"><i /></span></div>
            <h2>NIGHT OPS</h2>
            <p>设备执行、截图传输与游戏生命周期由同一受保护 Agent 进程承载。</p>
            <div className="side-rows">
              <div><span>通道</span><strong>gRPC + mTLS</strong></div>
              <div><span>协议</span><strong>FairyPam Agent V2</strong></div>
              <div><span>状态</span><strong>当前 / {startupText}</strong></div>
            </div>
            <div className="code-map"><span>KEYBOARD</span><span>MOUSE</span><span>CAPTURE</span><span>GAME</span></div>
          </section>
        </aside>
      </div>
    </div>
  );
}
