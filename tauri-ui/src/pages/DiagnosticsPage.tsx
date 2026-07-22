import type { UseQueryResult } from '@tanstack/react-query';

import type { EnvironmentCheck, Overview } from '../lib/contracts';

type Props = { environment: UseQueryResult<EnvironmentCheck>; overview: UseQueryResult<Overview> };

const checkLabels: Record<string, string> = {
  binary_or_task: '服务安装',
  agent: '后台服务',
  guardian: '守护服务',
  certificate: '证书',
  control: '控制连接',
  frame: '画面传输',
  profiles: '已验证的游戏配置',
  game_discovery: '游戏识别',
};

const checkStatusLabels: Record<string, string> = {
  available: '正常',
  connected: '已连接',
  pending: '等待处理',
  unavailable: '需要处理',
};

function checkStatusLabel(status: string) {
  return checkStatusLabels[status.toLowerCase()] ?? '正在确认';
}

function serviceStateLabel(state: string | undefined) {
  const labels: Record<string, string> = {
    connectedidle: '已连接，等待操作',
    disconnected: '未连接',
    starting: '正在启动',
  };
  return state ? labels[state.toLowerCase()] ?? '正在更新' : '不可用';
}

function runtimeLabel(runtime: string | undefined) {
  const labels: Record<string, string> = {
    dry_run: '演练模式',
    production: '正常服务',
  };
  return runtime ? labels[runtime.toLowerCase()] ?? '正在确认' : '不可用';
}

export function DiagnosticsPage({ environment, overview }: Props) {
  return (
    <section className="status-card" aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">环境检查</h2>
      <p>状态：{serviceStateLabel(overview.data?.status.state)}</p>
      <p>运行模式：{runtimeLabel(overview.data?.doctor.runtime)}</p>
      <button disabled={environment.isFetching} onClick={() => void environment.refetch()} type="button">检查本地环境</button>
      {environment.isFetching && <p>正在检查。</p>}
      {environment.isError && <p role="status">环境检查失败。</p>}
      {environment.data && (
        <ul className="check-list">
          {environment.data.checks.map((check) => (
            <li key={check.id}><strong>{checkLabels[check.id] ?? '服务项目'}</strong>：{checkStatusLabel(check.status)}</li>
          ))}
        </ul>
      )}
    </section>
  );
}
