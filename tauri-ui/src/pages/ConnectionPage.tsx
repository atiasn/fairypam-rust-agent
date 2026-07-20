import { useState } from 'react';
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
    },
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
        <form
          className="enrollment-form"
          onSubmit={(event) => {
            event.preventDefault();
            registration.mutate();
          }}
        >
          <label>
            Hub HTTPS 地址
            <input autoComplete="url" onChange={(event) => setHubAddress(event.target.value)} required type="url" value={hubAddress} />
          </label>
          <label>
            一次性注册码
            <input autoComplete="one-time-code" onChange={(event) => setRegistrationCode(event.target.value)} required type="password" value={registrationCode} />
          </label>
          <button disabled={registration.isPending || !startup.isSuccess} type="submit">注册或重新注册</button>
        </form>
        {registration.isSuccess && <p role="status">请在高权限 FairyPam Agent 确认注册；确认前不会使用注册码。若未在短时间内确认，本次注册会失效。</p>}
        {registration.isError && <p role="status">注册未完成。请确认 Agent 已就绪后重试。</p>}
        {!startup.isSuccess && <p role="status">请先等待本地 Agent 就绪，再提交注册。</p>}
        <p className="notice">注册码只经已验证的本地 Agent 通道提交，不会被界面保存。</p>
      </section>
      {startup.isError && <button onClick={retryStartup} type="button">重试启动</button>}
      <RecoveryCard reason={connection.reasonCode} />
    </>
  );
}
