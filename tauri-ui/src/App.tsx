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
import { EnrollmentPage } from './pages/EnrollmentPage';
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

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const enrollmentMode = useQuery({ queryKey: queryKeys.enrollmentMode, queryFn: agentApi.getEnrollmentMode });
  const startup = useQuery({
    queryKey: queryKeys.startup,
    queryFn: agentApi.ensureLocalAgent,
    retry: false,
    enabled: enrollmentMode.data?.status === 'standard',
  });
  const queries = useAgentQueries(startup.isSuccess);
  const { connection, dispatch } = useConnectionState(queries.overview.isSuccess, queries.overview.error);

  useEffect(() => {
    if (queries.overview.data?.status.state.toLowerCase().includes('emergency')) {
      dispatch({ type: 'ExplicitEmergency', code: 'agent.guardian.emergency' });
    }
  }, [dispatch, queries.overview.data?.status.state]);

  if (enrollmentMode.data?.status === 'elevated') return <EnrollmentPage />;

  const common = {
    connection,
    canMutate: canMutate(connection),
    overview: queries.overview,
    startup,
    retryStartup: () => void startup.refetch(),
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">FAIRYPAM // NIGHT OPS</p>
          <h1>AGENT CONTROL</h1>
        </div>
        <p aria-live="polite" className={`connection ${connection.availability}`}>
          {startup.isPending ? '正在唤醒本地 Agent' : startup.isError ? 'Agent 启动需要处理' : 'Agent 已就绪'}
        </p>
      </header>
      <div className="app-layout">
        <nav aria-label="Agent UI 导航" className="navigation">
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
          {page === 'environment' && <DiagnosticsPage overview={queries.overview} />}
          {page === 'logs' && <LogsPage />}
          {page === 'games' && <GamesPage />}
        </main>
      </div>
    </div>
  );
}
