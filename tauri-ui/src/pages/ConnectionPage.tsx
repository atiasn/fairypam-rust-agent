import { useState } from 'react';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';

import { StatusPanel } from '../components/StatusPanel';
import { agentApi } from '../lib/agentApi';
import type { ConnectionState } from '../lib/connectionReducer';
import type { EnvironmentCheck, Overview, SupportStatus } from '../lib/contracts';
import { queryKeys } from '../lib/queryKeys';

type Props = {
  connection: ConnectionState;
  canMutate: boolean;
  environment: UseQueryResult<EnvironmentCheck>;
  overview: UseQueryResult<Overview>;
  startup: UseQueryResult<SupportStatus>;
  retryStartup: () => void;
};

function connectionStatusLabel(status: string) {
  const labels: Record<string, string> = {
    connected: '已连接',
    connecting: '正在连接',
    disconnected: '未连接',
    offline: '未连接',
  };
  return labels[status.toLowerCase()] ?? '正在确认';
}

export function ConnectionPage({ canMutate, connection, environment, overview, startup, retryStartup }: Props) {
  const [hubAddress, setHubAddress] = useState('https://');
  const [registrationCode, setRegistrationCode] = useState('');
  const status = useQuery({
    queryKey: queryKeys.connection,
    queryFn: agentApi.getConnectionStatus,
    enabled: overview.isSuccess,
  });
  const queryClient = useQueryClient();
  const registration = useMutation({
    mutationFn: () => agentApi.registerHub(hubAddress.trim(), registrationCode),
    onSuccess: () => {
      setRegistrationCode('');
      void queryClient.invalidateQueries({ queryKey: queryKeys.connection });
      void queryClient.invalidateQueries({ queryKey: queryKeys.environment });
    },
  });
  const registrationReady = environment.data?.registration_ready === true;
  const registrationEnabled = canMutate && overview.isSuccess && startup.isSuccess && registrationReady;
  return (
    <>
      <StatusPanel
        availability={connection.availability}
        title="后台服务"
        detail={startup.isError ? '后台服务尚未就绪。' : '打开界面时会自动准备后台服务。'}
      />
      <section className="status-card" aria-labelledby="hub-connection-heading">
        <h2 id="hub-connection-heading">服务连接</h2>
        {status.isLoading && <p>正在读取服务连接状态。</p>}
        {status.isError && <p role="status">服务正在恢复连接。</p>}
        {status.data && (
          <dl>
            <dt>服务地址</dt><dd>{status.data.hub_address || '尚未注册'}</dd>
            <dt>控制连接</dt><dd>{connectionStatusLabel(status.data.control)}</dd>
            <dt>画面传输</dt><dd>{connectionStatusLabel(status.data.frame)}</dd>
            <dt>采集功能</dt><dd>{status.data.capture_active ? '已开启' : '未开启'}</dd>
          </dl>
        )}
        <form
          className="enrollment-form"
          onSubmit={(event) => {
            event.preventDefault();
            registration.mutate();
          }}
        >
          <label>
            服务地址
            <input autoComplete="url" onChange={(event) => setHubAddress(event.target.value)} required type="url" value={hubAddress} />
          </label>
          <label>
            一次性注册码
            <input autoComplete="one-time-code" onChange={(event) => setRegistrationCode(event.target.value)} required type="password" value={registrationCode} />
          </label>
          <button disabled={registration.isPending || !registrationEnabled} type="submit">注册或重新注册</button>
        </form>
        {registration.isSuccess && <p role="status">请在系统确认窗口中确认注册；确认前不会使用注册码。若未在短时间内确认，本次注册会失效。</p>}
        {registration.isError && <p role="status">注册未完成。请确认后台服务已就绪后重试。</p>}
        {!registrationReady && <p role="status">请先完成本机环境检查，再提交注册。</p>}
        {environment.isError && <p role="status">本机环境暂时无法确认，请稍后重试。</p>}
        {!startup.isSuccess && <p role="status">请先等待后台服务就绪，再提交注册。</p>}
        <p className="notice">注册码只会通过受保护的通道提交，界面不会保存它。</p>
      </section>
      {(startup.isError || overview.isError) && <button onClick={retryStartup} type="button">重试启动</button>}
    </>
  );
}
