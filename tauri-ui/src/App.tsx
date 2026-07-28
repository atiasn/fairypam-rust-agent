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

const navigation: Array<{ id: Page; label: string }> = [
  { id: 'dashboard', label: '总览' },
  { id: 'connection', label: '连接与注册' },
  { id: 'environment', label: '环境检查' },
  { id: 'logs', label: '日志' },
  { id: 'games', label: '游戏' },
];

function startupLabel(status: string | undefined, isPending: boolean, error: unknown) {
  if (isPending) return '正在准备本机服务';
  if (
    typeof error === 'object'
    && error !== null
    && 'code' in error
    && error.code === 'startup.agent_repair_required'
  ) return '后台服务需要修复';
  if (error) return '服务启动需要处理';
  if (status === 'ready') return '服务已连接';
  if (status === 'hub_wait_timeout') return '服务已就绪，正在重试连接';
  if (status === 'agent_ready') return '服务已就绪，等待注册';
  return '服务已就绪';
}

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [activationState, setActivationState] = useState<'pending' | 'failed' | 'runtime-failed'>();
  const startup = useQuery({
    queryKey: queryKeys.startup,
    queryFn: agentApi.ensureLocalAgent,
    retry: false,
  });
  const queries = useAgentQueries(startup.isSuccess);
  const { connection, dispatch } = useConnectionState(queries.overview.isSuccess, queries.overview.error);
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
    if (queries.overview.data?.status.state.toLowerCase().includes('emergency')) {
      dispatch({ type: 'ExplicitEmergency', code: 'agent.guardian.emergency' });
    }
  }, [dispatch, queries.overview.data?.status.state]);

  const common = {
    connection,
    canMutate: canMutate(connection),
    environment: queries.environment,
    overview: queries.overview,
    startup,
    retryStartup: () => {
      void refreshAgentState();
    },
  };
  const agentReady = startup.isSuccess && !activationState && queries.overview.isSuccess;

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">FAIRYPAM // 夜间值守</p>
          <h1>控制中心</h1>
        </div>
        <p aria-live="polite" className={`connection ${connection.availability}`}>
          {activationState === 'runtime-failed'
            ? '本机服务已停止'
            : startupLabel(
              startup.data?.status,
              startup.isPending || activationState === 'pending',
              activationState === 'failed' ? new Error('activation failed') : startup.error,
            )}
        </p>
      </header>
      <div className="app-layout">
        <nav aria-label="控制中心导航" className="navigation">
          {navigation.map((item) => (
            <button
              aria-current={page === item.id ? 'page' : undefined}
              className={page === item.id ? 'active' : undefined}
              key={item.id}
              onClick={() => setPage(item.id)}
              type="button"
            >
              {item.label}
            </button>
          ))}
        </nav>
        <main>
          {activationState === 'pending' && (
            <StatusPanel availability="unknown" title="正在准备服务" detail="正在检查服务状态。" />
          )}
          {activationState === 'runtime-failed' && (
            <StatusPanel
              availability="offline"
              title="本机服务已停止"
              detail="为保护游戏操作，本次会话已锁定。请从系统托盘安全退出 FairyPam，然后重新启动。"
            />
          )}
          {activationState === 'failed' && (
            <>
              <StatusPanel availability="offline" title="服务暂时无法使用" detail="请重试检查本机服务。" />
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
          {!activationState && page === 'dashboard' && <DashboardPage {...common} />}
          {!activationState && page === 'connection' && <ConnectionPage {...common} />}
          {!activationState && page === 'environment' && <DiagnosticsPage environment={queries.environment} overview={queries.overview} />}
          {!activationState && page === 'logs' && <LogsPage enabled={agentReady} />}
          {!activationState && page === 'games' && <GamesPage enabled={agentReady} />}
        </main>
      </div>
    </div>
  );
}
