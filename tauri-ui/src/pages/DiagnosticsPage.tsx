import { useState } from 'react';
import { useMutation, type UseQueryResult } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';
import type { Overview } from '../lib/contracts';

type Props = { overview: UseQueryResult<Overview> };

export function DiagnosticsPage({ overview }: Props) {
  const [message, setMessage] = useState<string>();
  const exportDiagnostics = useMutation({
    mutationFn: agentApi.exportDiagnostics,
    onSuccess: (result) => setMessage(result.saved ? '诊断已导出。' : (result.reasonCode ?? '诊断导出不可用。')),
    onError: () => setMessage('诊断导出失败。'),
  });
  return (
    <section className="status-card" aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">诊断</h2>
      <p>状态：{overview.data?.status.state ?? '不可用'}</p>
      <p>运行模式：{overview.data?.doctor.runtime ?? '不可用'}</p>
      <button onClick={() => exportDiagnostics.mutate()} type="button">导出脱敏诊断</button>
      {message && <p role="status">{message}</p>}
    </section>
  );
}
