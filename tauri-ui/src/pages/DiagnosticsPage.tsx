import { useMutation, type UseQueryResult } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';
import type { Overview } from '../lib/contracts';

type Props = { overview: UseQueryResult<Overview> };

const checkLabels: Record<string, string> = {
  binary_or_task: '二进制/任务',
  agent: 'Agent',
  guardian: 'Guardian',
  certificate: '证书',
  control: 'Control gRPC',
  frame: 'Frame gRPC',
  profiles: '签名 Profile',
  game_discovery: '游戏发现',
};

export function DiagnosticsPage({ overview }: Props) {
  const environment = useMutation({ mutationFn: agentApi.runEnvironmentCheck });
  return (
    <section className="status-card" aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">环境检查</h2>
      <p>状态：{overview.data?.status.state ?? '不可用'}</p>
      <p>运行模式：{overview.data?.doctor.runtime ?? '不可用'}</p>
      <button onClick={() => environment.mutate()} type="button">检查本地环境</button>
      {environment.isPending && <p>正在检查。</p>}
      {environment.isError && <p role="status">环境检查失败。</p>}
      {environment.data && (
        <ul className="check-list">
          {environment.data.checks.map((check) => (
            <li key={check.id}><strong>{checkLabels[check.id] ?? check.id}</strong>：{check.status}（{check.code}）{check.recovery && `；${check.recovery}`}</li>
          ))}
        </ul>
      )}
    </section>
  );
}
