import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';

import { RecoveryCard } from '../components/RecoveryCard';
import { StatusPanel } from '../components/StatusPanel';
import { agentApi } from '../lib/agentApi';
import type { ConnectionState } from '../lib/connectionReducer';
import type { Doctor, Overview } from '../lib/contracts';
import { queryKeys } from '../lib/queryKeys';

type Props = { connection: ConnectionState; overview: UseQueryResult<Overview>; doctor: UseQueryResult<Doctor> };

export function ConnectionPage({ connection, overview }: Props) {
  const status = useQuery({ queryKey: queryKeys.connection, queryFn: agentApi.getConnectionStatus });
  const queryClient = useQueryClient();
  const enrollment = useMutation({
    mutationFn: agentApi.startEnrollment,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.connection }),
  });
  return (
    <>
      <StatusPanel availability={connection.availability} title="本地控制连接" detail={overview.data ? '使用经过身份校验的本地命名管道。' : '等待 Agent 本地控制服务。'} />
      <section className="status-card" aria-labelledby="hub-connection-heading">
        <h2 id="hub-connection-heading">Hub 连接</h2>
        {status.isLoading && <p>正在读取连接状态。</p>}
        {status.isError && <p role="status">无法读取 Hub 连接状态。</p>}
        {status.data && (
          <dl>
            <dt>Hub 地址</dt><dd>{status.data.hub_address || '未注册'}</dd>
            <dt>Control</dt><dd>{status.data.control}</dd>
            <dt>Frame</dt><dd>{status.data.frame}</dd>
            <dt>采集</dt><dd>{status.data.capture_active ? '活动' : '未活动'}</dd>
          </dl>
        )}
        <button disabled={enrollment.isPending} onClick={() => enrollment.mutate()} type="button">注册或重新注册</button>
        {enrollment.isSuccess && <p role="status">已请求 Windows UAC。请在高权限注册窗口完成后刷新此页。</p>}
        {enrollment.isError && <p role="status">无法启动高权限注册 helper。</p>}
        <p className="notice">重新注册需要 Windows UAC 明示确认；注册码、CA 和私钥不会出现在此界面。</p>
      </section>
      <RecoveryCard reason={connection.reasonCode} />
      <p className="notice">管道名、令牌和私钥不会显示或复制到此页面。</p>
    </>
  );
}
