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
  if (status === 'ready') return 'Hub 控制与画面连接已就绪。';
  if (status === 'agent_ready') return '尚未完成注册。请在“连接与注册”中继续。';
  if (status === 'hub_wait_timeout') return 'Hub 正在重连，您仍可继续使用安全的本地功能。';
  return '正在恢复 Hub 连接。';
}

function serviceStateLabel(state: string) {
  const labels: Record<string, string> = {
    connectedidle: 'Core 空闲，等待操作',
    disconnected: '未连接',
    emergencystopped: '保护状态，输入已释放',
    starting: '正在启动',
    taskactive: '正在执行 Hub 任务',
    targetlocked: '已锁定游戏目标',
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
    return <StatusPanel availability="unknown" title="正在准备本机 Core" detail="正在检查本机运行状态。" />;
  }
  if (startup.isError) {
    return (
      <>
        <StatusPanel availability="offline" title="本机 Core 暂时无法使用" detail="请检查安装或完成注册，然后重试。" />
        <div className="actions">
          <button onClick={retryStartup} type="button">重试启动</button>
        </div>
      </>
    );
  }
  if (overview.isError || !overview.data) {
    return (
      <>
        <StatusPanel availability={connection.availability} title="本机 Core 状态不可用" detail="本机状态读取失败，请手动重试。" />
        <div className="actions">
          <button onClick={retryStartup} type="button">重试启动</button>
        </div>
      </>
    );
  }
  const data = overview.data;
  const emergency = data.status.state.toLowerCase() === 'emergencystopped';
  return (
    <>
      <StatusPanel
        availability={emergency ? 'emergency' : connection.availability}
        detail={emergency
          ? '输入已释放，游戏启动和设备操作已锁定；请在“游戏”页面确认清理后解除保护。'
          : `运行状态：${serviceStateLabel(data.status.state)}；采集功能：${data.status.capture_active ? '已开启' : '未开启'}`}
        title={emergency ? '本机 Core 处于保护状态' : '本机 Core 已就绪'}
      />
      <section className="status-card" aria-labelledby="startup-heading">
        <h2 id="startup-heading">Hub 连接摘要</h2>
        <p>{connectionSummary(startup.data?.status)}</p>
        <p>关闭窗口不会停止同一进程内的本机 Core。</p>
      </section>
    </>
  );
}
