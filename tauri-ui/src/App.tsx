import { useEffect, useState } from 'react';

import { canMutate } from './lib/connectionReducer';
import { useAgentQueries } from './lib/useAgentQueries';
import { useConnectionState } from './lib/useConnectionState';
import { ConnectionPage } from './pages/ConnectionPage';
import { DashboardPage } from './pages/DashboardPage';
import { DiagnosticsPage } from './pages/DiagnosticsPage';
import { GamesPage } from './pages/GamesPage';
import { InputSafetyPage } from './pages/InputSafetyPage';
import { OnboardingWizard } from './pages/OnboardingWizard';
import { ProfilesPage } from './pages/ProfilesPage';
import { StartupPage } from './pages/StartupPage';
import { TargetsPage } from './pages/TargetsPage';
import { UpdatePage } from './pages/UpdatePage';

type Page =
  | 'dashboard'
  | 'onboarding'
  | 'profiles'
  | 'targets'
  | 'connection'
  | 'safety'
  | 'update'
  | 'startup'
  | 'diagnostics'
  | 'games';

const navigation: Array<{ id: Page; label: string }> = [
  { id: 'dashboard', label: '总览' },
  { id: 'onboarding', label: '首次向导' },
  { id: 'profiles', label: 'Profile' },
  { id: 'targets', label: '目标与预览' },
  { id: 'connection', label: '连接' },
  { id: 'safety', label: '输入安全' },
  { id: 'update', label: '更新' },
  { id: 'startup', label: '自启动' },
  { id: 'diagnostics', label: '诊断' },
  { id: 'games', label: '游戏' },
];

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [profileId, setProfileId] = useState<string>();
  const queries = useAgentQueries(profileId);
  const { connection, dispatch } = useConnectionState(
    queries.overview.isSuccess,
    queries.overview.error,
  );

  useEffect(() => {
    if (queries.overview.data?.status.state.toLowerCase().includes('emergency')) {
      dispatch({ type: 'ExplicitEmergency', code: 'agent.guardian.emergency' });
    }
  }, [dispatch, queries.overview.data?.status.state]);

  const common = {
    connection,
    canMutate: canMutate(connection),
    overview: queries.overview,
    doctor: queries.doctor,
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">FAIRYPAM / LOCAL CONTROL</p>
          <h1>FairyPam Agent UI</h1>
        </div>
        <p aria-live="polite" className={`connection ${connection.availability}`}>
          连接状态：{connection.availability}
          {connection.reasonCode ? `（${connection.reasonCode}）` : ''}
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
          {page === 'onboarding' && <OnboardingWizard {...common} />}
          {page === 'profiles' && (
            <ProfilesPage
              onSelect={(id) => {
                setProfileId(id);
                setPage('targets');
              }}
              profiles={queries.profiles}
              selectedProfileId={profileId}
            />
          )}
          {page === 'targets' && (
            <TargetsPage
              canMutate={common.canMutate}
              profileId={profileId}
              targets={queries.targets}
            />
          )}
          {page === 'connection' && <ConnectionPage {...common} />}
          {page === 'safety' && <InputSafetyPage {...common} />}
          {page === 'update' && <UpdatePage />}
          {page === 'startup' && <StartupPage />}
          {page === 'diagnostics' && <DiagnosticsPage overview={queries.overview} />}
          {page === 'games' && <GamesPage />}
        </main>
      </div>
    </div>
  );
}
