import { useState } from 'react';
import { useMutation, type UseQueryResult } from '@tanstack/react-query';

import { StopAgentDialog } from '../components/StopAgentDialog';
import { agentApi } from '../lib/agentApi';
import type { ConnectionState } from '../lib/connectionReducer';
import type { Doctor, Overview } from '../lib/contracts';

type Props = { connection: ConnectionState; canMutate: boolean; overview: UseQueryResult<Overview>; doctor: UseQueryResult<Doctor> };

export function InputSafetyPage({ canMutate }: Props) {
  const [message, setMessage] = useState<string>();
  const release = useMutation({
    mutationFn: agentApi.releaseAll,
    onSuccess: () => setMessage('已请求释放全部输入状态。'),
    onError: () => setMessage('无法释放输入状态；请检查 Agent 诊断。'),
  });
  return (
    <>
      <section className="status-card" aria-labelledby="safety-heading">
        <h2 id="safety-heading">输入安全</h2>
        <p>UI 不提供 Armed、输入注入或紧急停止复位。唯一的安全操作是明确确认的 ReleaseAll。</p>
        <button
          disabled={!canMutate || release.isPending}
          onClick={() => {
            if (window.confirm('确认释放全部输入状态？')) release.mutate();
          }}
          type="button"
        >
          释放全部输入状态
        </button>
        {message && <p role="status">{message}</p>}
      </section>
      <StopAgentDialog />
    </>
  );
}
