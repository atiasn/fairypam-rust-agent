import type { UseQueryResult } from '@tanstack/react-query';

import { StatusPanel } from '../components/StatusPanel';
import type { ConnectionState } from '../lib/connectionReducer';
import type { Overview, SupportStatus } from '../lib/contracts';

type Props = {
  connection: ConnectionState;
  overview: UseQueryResult<Overview>;
  startup: UseQueryResult<SupportStatus>;
  retryStartup: () => void;
};

function connectionSummary(status: string | undefined) {
  if (status === 'ready') return '服务连接已就绪。';
  if (status === 'agent_ready') return '尚未完成注册。请在“连接与注册”中继续。';
  if (status === 'hub_wait_timeout') return '正在持续尝试连接，您仍可继续使用本地功能。';
  return '正在恢复服务连接。';
}

function serviceStateLabel(state: string) {
  const labels: Record<string, string> = {
    connectedidle: '已连接，等待操作',
    disconnected: '未连接',
    starting: '正在启动',
  };
  return labels[state.toLowerCase()] ?? '正在更新';
}

export function DashboardPage({
  connection,
  overview,
  startup,
  retryStartup,
}: Props) {
  if (startup.isPending || overview.isLoading) {
    return <StatusPanel availability="unknown" title="正在准备服务" detail="正在检查服务状态。" />;
  }
  if (startup.isError) {
    return (
      <>
        <StatusPanel availability="offline" title="服务暂时无法使用" detail="请检查安装或完成注册，然后重试。" />
        <div className="actions">
          <button onClick={retryStartup} type="button">重试启动</button>
        </div>
      </>
    );
  }
  if (overview.isError || !overview.data) {
    return (
      <>
        <StatusPanel availability={connection.availability} title="服务暂时无法使用" detail="服务连接已中断，请手动重试。" />
        <div className="actions">
          <button onClick={retryStartup} type="button">重试启动</button>
        </div>
      </>
    );
  }
  const data = overview.data;
  return (
    <>
      <StatusPanel
        availability={connection.availability}
        detail={`运行状态：${serviceStateLabel(data.status.state)}；采集功能：${data.status.capture_active ? '已开启' : '未开启'}`}
        title="后台服务已就绪"
      />
      <section className="status-card" aria-labelledby="startup-heading">
        <h2 id="startup-heading">连接摘要</h2>
        <p>{connectionSummary(startup.data?.status)}</p>
        <p>关闭窗口不会停止后台服务。</p>
      </section>
    </>
  );
}
