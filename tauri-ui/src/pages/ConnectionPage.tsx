import type { UseQueryResult } from '@tanstack/react-query';

import { RecoveryCard } from '../components/RecoveryCard';
import { StatusPanel } from '../components/StatusPanel';
import type { ConnectionState } from '../lib/connectionReducer';
import type { Doctor, Overview } from '../lib/contracts';

type Props = { connection: ConnectionState; overview: UseQueryResult<Overview>; doctor: UseQueryResult<Doctor> };

export function ConnectionPage({ connection, overview }: Props) {
  return (
    <>
      <StatusPanel availability={connection.availability} title="本地控制连接" detail={overview.data ? '使用经过身份校验的本地命名管道。' : '等待 Agent 本地控制服务。'} />
      <RecoveryCard reason={connection.reasonCode} />
      <p className="notice">管道名、令牌和私钥不会显示或复制到此页面。</p>
    </>
  );
}
