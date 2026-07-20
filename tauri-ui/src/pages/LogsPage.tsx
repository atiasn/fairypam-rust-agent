import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';
import { queryKeys } from '../lib/queryKeys';

export function LogsPage() {
  const [level, setLevel] = useState<'error' | 'warn' | 'info'>('info');
  const logs = useQuery({
    queryKey: queryKeys.logTail(level),
    queryFn: () => agentApi.getLogTail(100, level),
  });

  return (
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
  );
}
