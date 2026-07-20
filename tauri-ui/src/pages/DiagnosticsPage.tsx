import { useState } from 'react';
import { useMutation, useQuery, type UseQueryResult } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';
import type { Overview } from '../lib/contracts';
import { queryKeys } from '../lib/queryKeys';

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
  const [message, setMessage] = useState<string>();
  const [level, setLevel] = useState<'error' | 'warn' | 'info'>('info');
  const exportDiagnostics = useMutation({
    mutationFn: agentApi.exportDiagnostics,
    onSuccess: (result) => setMessage(result.saved ? '诊断已导出。' : (result.reasonCode ?? '诊断导出不可用。')),
    onError: () => setMessage('诊断导出失败。'),
  });
  const environment = useMutation({ mutationFn: agentApi.runEnvironmentCheck });
  const logs = useQuery({
    queryKey: queryKeys.logTail(level),
    queryFn: () => agentApi.getLogTail(100, level),
  });
  return (
    <>
      <section className="status-card" aria-labelledby="diagnostics-heading">
        <h2 id="diagnostics-heading">诊断</h2>
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
        <button onClick={() => exportDiagnostics.mutate()} type="button">导出脱敏诊断</button>
        {message && <p role="status">{message}</p>}
      </section>
      <section className="status-card" aria-labelledby="agent-log-heading">
        <h2 id="agent-log-heading">Agent 日志</h2>
        <label>
          最低级别
          <select onChange={(event) => setLevel(event.target.value as typeof level)} value={level}>
            <option value="error">错误</option>
            <option value="warn">警告</option>
            <option value="info">信息</option>
          </select>
        </label>
        {logs.isError && <p role="status">无法读取固定日志源。</p>}
        <ul className="log-list">
          {logs.data?.entries.map((entry, index) => <li key={`${entry.level}-${index}`}><strong>{entry.level}</strong>：{entry.message}</li>)}
        </ul>
        <p className="notice">仅显示 Agent 固定日志源的脱敏尾部，不支持路径输入。</p>
      </section>
    </>
  );
}
