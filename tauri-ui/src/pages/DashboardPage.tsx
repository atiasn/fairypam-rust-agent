import type { UseQueryResult } from '@tanstack/react-query';

import { RecoveryCard } from '../components/RecoveryCard';
import { StatusPanel } from '../components/StatusPanel';
import type { ConnectionState } from '../lib/connectionReducer';
import type { Doctor, Overview } from '../lib/contracts';

type Props = {
  connection: ConnectionState;
  overview: UseQueryResult<Overview>;
  doctor: UseQueryResult<Doctor>;
};

export function DashboardPage({ connection, overview, doctor }: Props) {
  if (overview.isLoading) return <StatusPanel availability="unknown" title="正在读取 Agent 状态" detail="请稍候。" />;
  if (overview.isError) {
    return (
      <>
        <StatusPanel availability={connection.availability} title="无法连接 Agent" detail="本地控制通道未返回可用状态。" />
        <RecoveryCard reason={connection.reasonCode} />
      </>
    );
  }
  const data = overview.data;
  if (!data) {
    return <StatusPanel availability="unknown" title="等待 Agent 状态" detail="查询尚未返回可用数据。" />;
  }

  return (
    <>
      <StatusPanel
        availability={connection.availability}
        detail={`运行状态：${data.status.state}；采集：${data.status.capture_active ? '活动' : '未活动'}`}
        title="Agent 概览"
      />
      <section className="status-card" aria-labelledby="doctor-heading">
        <h2 id="doctor-heading">运行诊断</h2>
        <p>运行模式：{doctor.data?.runtime ?? data.doctor.runtime}</p>
        <p>已发现 Profile：{doctor.data?.profiles.length ?? data.doctor.profiles.length}</p>
      </section>
    </>
  );
}
