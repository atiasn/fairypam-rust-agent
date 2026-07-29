import { useEffect, useState, type FormEvent } from 'react';
import { useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';

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

export function ConnectionPage({
  canMutate,
  connection,
  environment,
  overview,
  startup,
  retryStartup,
}: Props) {
  const [registrationStatus, setRegistrationStatus] = useState<'idle' | 'submitting' | 'submitted' | 'completed' | 'error'>('idle');
  const [registrationPendingAt, setRegistrationPendingAt] = useState(0);
  const status = useQuery({
    queryKey: queryKeys.connection,
    queryFn: agentApi.getConnectionStatus,
    enabled: overview.isSuccess,
  });
  const queryClient = useQueryClient();
  const registrationReady = environment.data?.registration_ready === true;
  const registrationEnabled = canMutate
    && overview.isSuccess
    && startup.isSuccess
    && environment.isSuccess
    && !environment.isFetching
    && !environment.isError
    && !environment.data.registration_pending
    && registrationReady;

  useEffect(() => {
    if (registrationStatus !== 'submitted') return;
    if (environment.isError) {
      setRegistrationStatus('error');
      return;
    }
    if (environment.dataUpdatedAt <= registrationPendingAt || environment.data?.registration_pending) return;
    const certificate = environment.data?.checks.find((check) => check.id === 'certificate');
    setRegistrationStatus(certificate?.status === 'available' ? 'completed' : 'error');
  }, [environment.data, environment.dataUpdatedAt, environment.isError, registrationPendingAt, registrationStatus]);

  const submitRegistration = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!registrationEnabled || registrationStatus === 'submitting' || registrationStatus === 'submitted') return;

    const form = event.currentTarget;
    const data = new FormData(form);
    const hubAddress = data.get('hubAddress');
    const registrationCode = data.get('registrationCode');
    if (typeof hubAddress !== 'string' || typeof registrationCode !== 'string') return;
    const clearRegistrationFields = () => {
      for (const name of ['hubAddress', 'registrationCode']) {
        const input = form.elements.namedItem(name);
        if (input instanceof HTMLInputElement) input.value = '';
      }
    };

    setRegistrationStatus('submitting');
    setRegistrationPendingAt(0);
    void agentApi.registerHub(hubAddress.trim(), registrationCode).then(
      async () => {
        clearRegistrationFields();
        const environmentResult = await environment.refetch();
        const certificate = environmentResult.data?.checks.find((check) => check.id === 'certificate');
        if (environmentResult.isError) {
          setRegistrationStatus('error');
        } else if (certificate?.status === 'available') {
          setRegistrationStatus('completed');
        } else if (environmentResult.data?.registration_pending) {
          setRegistrationPendingAt(environmentResult.dataUpdatedAt);
          setRegistrationStatus('submitted');
        } else {
          setRegistrationStatus('error');
        }
        retryStartup();
        void Promise.all([
          queryClient.invalidateQueries({ queryKey: queryKeys.connection }),
          queryClient.invalidateQueries({ queryKey: ['agent-ui', 'log-tail'] }),
        ]);
      },
      () => {
        clearRegistrationFields();
        setRegistrationStatus('error');
      },
    );
  };

  return (
    <>
      <StatusPanel
        availability={connection.availability}
        title="本机 Core"
        detail={startup.isError ? '本机 Core 尚未就绪。' : '打开界面时会自动准备同一进程内的本机 Core。'}
      />
      <section className="status-card" aria-labelledby="hub-connection-heading">
        <h2 id="hub-connection-heading">Hub 连接</h2>
        {status.isLoading && <p>正在读取 Hub 连接状态。</p>}
        {status.isError && <p role="status">服务正在恢复连接。</p>}
        {status.data && (
          <dl>
            <dt>控制连接</dt><dd>{connectionStatusLabel(status.data.control)}</dd>
            <dt>画面传输</dt><dd>{connectionStatusLabel(status.data.frame)}</dd>
            <dt>采集功能</dt><dd>{status.data.capture_active ? '已开启' : '未开启'}</dd>
          </dl>
        )}
        <form
          className="enrollment-form"
          onSubmit={submitRegistration}
        >
          <label>
            服务地址
            <input autoComplete="off" name="hubAddress" placeholder="https://" required type="url" />
          </label>
          <label>
            一次性注册码
            <input autoComplete="off" name="registrationCode" required type="password" />
          </label>
          <button disabled={registrationStatus === 'submitting' || registrationStatus === 'submitted' || !registrationEnabled} type="submit">注册或重新注册</button>
        </form>
        {registrationStatus === 'submitting' && <p role="status">正在提交注册请求。</p>}
        {registrationStatus === 'submitted' && <p role="status">正在完成注册，请稍候。</p>}
        {registrationStatus === 'completed' && <p role="status">注册已完成，正在连接服务。</p>}
        {registrationStatus === 'error' && <p role="status">注册未完成。请获取新的注册码后重试。</p>}
        {!registrationReady && <p role="status">请先完成本机环境检查，再提交注册。</p>}
        {environment.isError && <p role="status">本机环境暂时无法确认，请稍后重试。</p>}
        {!startup.isSuccess && <p role="status">请先等待本机 Core 就绪，再提交注册。</p>}
        <p className="notice">注册码只会通过受保护的通道提交，界面不会保存它。</p>
      </section>
      {(startup.isError || overview.isError) && (
        <div className="actions">
          <button onClick={retryStartup} type="button">重试启动</button>
        </div>
      )}
    </>
  );
}
