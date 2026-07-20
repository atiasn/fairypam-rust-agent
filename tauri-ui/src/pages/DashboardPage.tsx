import type { UseQueryResult } from '@tanstack/react-query';

import { RecoveryCard } from '../components/RecoveryCard';
import { StatusPanel } from '../components/StatusPanel';
import type { ConnectionState } from '../lib/connectionReducer';
import type { Overview, SupportStatus } from '../lib/contracts';

type Props = {
  connection: ConnectionState;
  overview: UseQueryResult<Overview>;
  startup: UseQueryResult<SupportStatus>;
  retryStartup: () => void;
};

export function DashboardPage({ connection, overview, startup, retryStartup }: Props) {
  if (startup.isPending || overview.isLoading) {
    return <StatusPanel availability="unknown" title="正在启动本地 Agent" detail="正在使用受控启动入口检查服务状态。" />;
  }
  if (startup.isError) {
    return (
      <>
        <StatusPanel availability="offline" title="Agent 未能在限定时间内就绪" detail="请检查安装或完成注册，然后重试。" />
        <button onClick={retryStartup} type="button">重试启动</button>
        <RecoveryCard reason="本地 Agent 启动失败；界面没有启动未知程序。" />
      </>
    );
  }
  if (overview.isError || !overview.data) {
    return <StatusPanel availability={connection.availability} title="正在读取 Agent 状态" detail="本地服务刚刚启动，请稍候。" />;
  }
  const data = overview.data;
  return (
    <>
      <StatusPanel
        availability={connection.availability}
        detail={`运行状态：${data.status.state}；采集：${data.status.capture_active ? '活动' : '未活动'}`}
        title="Agent 已运行"
      />
      <section className="status-card" aria-labelledby="startup-heading">
        <h2 id="startup-heading">连接摘要</h2>
        <p>{startup.data?.status === 'ready' ? 'Hub Control 与 Frame 通道已就绪。' : 'Agent 正在自行恢复 Hub 连接。'}</p>
        <p>关闭界面不会停止 Agent。</p>
      </section>
    </>
  );
}
