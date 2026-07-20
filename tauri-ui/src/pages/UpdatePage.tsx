import { useQuery } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';
import { queryKeys } from '../lib/queryKeys';

export function UpdatePage() {
  const update = useQuery({ queryKey: queryKeys.update, queryFn: agentApi.getUpdateStatus });
  return <section className="status-card"><h2>更新状态</h2><p>{update.data?.status ?? '正在读取更新状态。'}</p><p>此界面不安装或替换程序。</p></section>;
}
