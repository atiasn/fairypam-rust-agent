import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { agentApi } from './lib/agentApi';
import { canMutate } from './lib/connectionReducer';
import { queryKeys } from './lib/queryKeys';
import { useAgentQueries } from './lib/useAgentQueries';
import { useConnectionState } from './lib/useConnectionState';
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

function startupLabel(status: string | undefined, isPending: boolean, isError: boolean) {
  if (isPending) return '正在准备本机服务';
  if (isError) return '服务启动需要处理';
  if (status === 'ready') return '服务已连接';
  if (status === 'hub_wait_timeout') return '服务已就绪，正在重试连接';
  if (status === 'agent_ready') return '服务已就绪，等待注册';
  return '服务已就绪';
}

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [recoveryAction, setRecoveryAction] = useState<'restart' | 'repair'>();
  const startup = useQuery({
    queryKey: queryKeys.startup,
    queryFn: agentApi.ensureLocalAgent,
    retry: false,
  });
  const queries = useAgentQueries(startup.isSuccess);
  const { connection, dispatch } = useConnectionState(queries.overview.isSuccess, queries.overview.error);

  useEffect(() => {
    if (queries.overview.data?.status.state.toLowerCase().includes('emergency')) {
      dispatch({ type: 'ExplicitEmergency', code: 'agent.guardian.emergency' });
    }
  }, [dispatch, queries.overview.data?.status.state]);

  const recoverAgent = async (
    action: 'restart' | 'repair',
    operation: () => Promise<unknown>,
  ) => {
    if (recoveryAction) return;
    setRecoveryAction(action);
    try {
      await operation();
      await startup.refetch();
      await Promise.all([queries.overview.refetch(), queries.environment.refetch()]);
    } catch {
      // The existing startup error remains visible and keeps Repair available.
    } finally {
      setRecoveryAction(undefined);
    }
  };

  const common = {
    connection,
    canMutate: canMutate(connection),
    environment: queries.environment,
    overview: queries.overview,
    startup,
    retryStartup: () => {
      void startup.refetch().then((result) => {
        if (!result.isError) {
          void queries.overview.refetch();
          void queries.environment.refetch();
        }
      });
    },
    restartAgent: () => {
      void recoverAgent('restart', agentApi.restartLocalAgent);
    },
    repairAgent: () => {
      void recoverAgent('repair', agentApi.repairAgentTasks);
    },
    recoveryAction,
  };
  const agentReady = startup.isSuccess && queries.overview.isSuccess;

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">FAIRYPAM // 夜间值守</p>
          <h1>控制中心</h1>
        </div>
        <p aria-live="polite" className={`connection ${connection.availability}`}>
          {startupLabel(startup.data?.status, startup.isPending, startup.isError)}
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
          {page === 'dashboard' && <DashboardPage {...common} />}
          {page === 'connection' && <ConnectionPage {...common} />}
          {page === 'environment' && <DiagnosticsPage environment={queries.environment} overview={queries.overview} />}
          {page === 'logs' && <LogsPage enabled={agentReady} />}
          {page === 'games' && <GamesPage enabled={agentReady} />}
        </main>
      </div>
    </div>
  );
}
