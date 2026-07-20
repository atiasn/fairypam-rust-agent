import { useState } from 'react';
import { useMutation, type UseQueryResult } from '@tanstack/react-query';

import { PreviewPanel } from '../components/PreviewPanel';
import { agentApi } from '../lib/agentApi';
import type { Targets } from '../lib/contracts';

type Props = { profileId?: string; canMutate: boolean; targets: UseQueryResult<Targets> };

export function TargetsPage({ profileId, canMutate, targets }: Props) {
  const [message, setMessage] = useState<string>();
  const lockTarget = useMutation({
    mutationFn: (candidateId: string) => agentApi.lockTarget(profileId ?? '', candidateId),
    onSuccess: (target) => setMessage(`已请求锁定 ${target.profile_id}（${target.state}）`),
    onError: () => setMessage('目标锁定失败。'),
  });
  const focusTarget = useMutation({
    mutationFn: agentApi.focusTarget,
    onSuccess: (target) => setMessage(target.foreground ? '目标已聚焦。' : '目标没有进入前台。'),
    onError: () => setMessage('目标聚焦失败。'),
  });

  return (
    <>
      <section className="status-card" aria-labelledby="targets-heading">
        <h2 id="targets-heading">目标窗口</h2>
        {!profileId && <p>请先在 Profile 页面选择一个已签名 Profile。</p>}
        {targets.isLoading && profileId && <p>正在读取目标窗口。</p>}
        {targets.isError && <p role="alert">目标窗口不可用或候选已经过期。</p>}
        {targets.data?.candidates.length === 0 && <p>当前没有匹配的目标窗口。</p>}
        <div className="target-list">
          {targets.data?.candidates.map((target) => (
            <article key={target.candidate_id}>
              <h3>{target.title}</h3>
              <p>{target.window_class} / PID {target.pid}</p>
              <button disabled={!canMutate || lockTarget.isPending} onClick={() => lockTarget.mutate(target.candidate_id)} type="button">锁定目标</button>
            </article>
          ))}
        </div>
        <button disabled={!canMutate || focusTarget.isPending} onClick={() => focusTarget.mutate()} type="button">聚焦已锁定目标</button>
        {message && <p role="status">{message}</p>}
      </section>
      <PreviewPanel />
    </>
  );
}
