import { useQuery } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';
import { queryKeys } from '../lib/queryKeys';

export function StartupPage() {
  const startup = useQuery({ queryKey: queryKeys.startup, queryFn: agentApi.getStartupStatus });
  return <section className="status-card"><h2>自启动状态</h2><p>{startup.data?.status ?? '正在读取自启动状态。'}</p><p>此界面不编辑 Windows Task。</p></section>;
}
