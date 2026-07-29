import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';
import { queryKeys } from '../lib/queryKeys';

const levelLabels = {
  error: '错误',
  warn: '警告',
  info: '信息',
} as const;

const safeLogMessage = /^[\p{Script=Han}\p{P}\p{Zs}]+$/u;
const unsafeLogMessageFallback = '该运行记录包含不适合展示的技术内容。';
const registrationFailure = /^服务注册失败（错误码：[a-z][a-z0-9_.-]*）$/u;

function displayLogMessage(message: string) {
  if (registrationFailure.test(message)) return message;
  // ponytail: only render Chinese text and punctuation; future technical formats use one safe summary.
  return safeLogMessage.test(message) ? message : unsafeLogMessageFallback;
}

export function LogsPage({ enabled }: { enabled: boolean }) {
  const [level, setLevel] = useState<'error' | 'warn' | 'info'>('info');
  const logs = useQuery({
    queryKey: queryKeys.logTail(level),
    queryFn: () => agentApi.getLogTail(100, level),
    enabled,
    refetchInterval: 1_000,
    refetchIntervalInBackground: false,
  });

  return (
    <section className="status-card" aria-labelledby="service-log-heading">
      <h2 id="service-log-heading">服务记录</h2>
      <label>
        最低级别
        <select onChange={(event) => setLevel(event.target.value as typeof level)} value={level}>
          <option value="error">错误</option>
          <option value="warn">警告</option>
          <option value="info">信息</option>
        </select>
      </label>
      {!enabled && <p role="status">正在等待本机 Core 就绪。</p>}
      {enabled && logs.isError && <p role="status">无法读取固定日志源。</p>}
      {logs.isSuccess && logs.data.entries.length === 0 && <p role="status">暂时没有可显示的运行记录。服务正常时，记录可能为空。</p>}
      <ul className="log-list">
        {logs.data?.entries.map((entry, index) => <li key={`${entry.level}-${index}`}><strong>{levelLabels[entry.level]}</strong>：{displayLogMessage(entry.message)}</li>)}
      </ul>
      <p className="notice">服务记录会自动刷新，仅显示已脱敏的最近记录，不能选择其他文件或路径。</p>
    </section>
  );
}
