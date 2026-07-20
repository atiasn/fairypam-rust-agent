import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';

import { RecoveryCard } from '../components/RecoveryCard';
import { StatusPanel } from '../components/StatusPanel';
import { agentApi } from '../lib/agentApi';
import type { ConnectionState } from '../lib/connectionReducer';
import type { Overview, SupportStatus } from '../lib/contracts';
import { queryKeys } from '../lib/queryKeys';

type Props = {
  connection: ConnectionState;
  overview: UseQueryResult<Overview>;
  startup: UseQueryResult<SupportStatus>;
  retryStartup: () => void;
};

export function ConnectionPage({ connection, overview, startup, retryStartup }: Props) {
  const status = useQuery({
    queryKey: queryKeys.connection,
    queryFn: agentApi.getConnectionStatus,
    enabled: overview.isSuccess,
  });
  const queryClient = useQueryClient();
  const enrollment = useMutation({
    mutationFn: agentApi.startEnrollment,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.connection }),
  });
  return (
    <>
      <StatusPanel
        availability={connection.availability}
        title="本地 Agent"
        detail={startup.isError ? '本地 Agent 尚未就绪。' : '界面会在打开时自动唤醒本地 Agent。'}
      />
      <section className="status-card" aria-labelledby="hub-connection-heading">
        <h2 id="hub-connection-heading">Hub 连接</h2>
        {status.isLoading && <p>正在读取 Agent 的连接状态。</p>}
        {status.isError && <p role="status">Agent 正在恢复 Hub 连接。</p>}
        {status.data && (
          <dl>
            <dt>Hub 地址</dt><dd>{status.data.hub_address || '尚未注册'}</dd>
            <dt>Control</dt><dd>{status.data.control}</dd>
            <dt>Frame</dt><dd>{status.data.frame}</dd>
            <dt>采集</dt><dd>{status.data.capture_active ? '活动' : '未活动'}</dd>
          </dl>
        )}
        <button disabled={enrollment.isPending} onClick={() => enrollment.mutate()} type="button">注册或重新注册</button>
        {enrollment.isSuccess && <p role="status">已请求 Windows UAC，请在 FairyPam 注册窗口完成操作。</p>}
        {enrollment.isError && <p role="status">无法打开注册窗口。</p>}
        <p className="notice">注册码、证书与私钥只在受保护的注册窗口处理，不会显示或写入命令行。</p>
      </section>
      {startup.isError && <button onClick={retryStartup} type="button">重试启动</button>}
      <RecoveryCard reason={connection.reasonCode} />
    </>
  );
}
