import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';

import { agentApi } from '../lib/agentApi';

export function EnrollmentPage() {
  const [hub, setHub] = useState('https://');
  const [code, setCode] = useState('');
  const enrollment = useMutation({ mutationFn: () => agentApi.completeEnrollment(hub.trim(), code) });

  return (
    <main className="enrollment-shell">
      <p className="eyebrow">FAIRYPAM // SECURE REGISTRATION</p>
      <h1>连接 FairyPam Hub</h1>
      <p>此窗口已获得 Windows 管理员授权，用于完成本机 Agent 注册。</p>
      <form
        className="status-card enrollment-form"
        onSubmit={(event) => {
          event.preventDefault();
          enrollment.mutate();
        }}
      >
        <label>
          Hub HTTPS 地址
          <input autoComplete="url" onChange={(event) => setHub(event.target.value)} required type="url" value={hub} />
        </label>
        <label>
          一次性注册码
          <input autoComplete="one-time-code" onChange={(event) => setCode(event.target.value)} required type="password" value={code} />
        </label>
        <button disabled={enrollment.isPending} type="submit">完成注册</button>
        {enrollment.isSuccess && <p role="status">注册完成，Agent 已通过受控入口启动。现在可关闭此窗口。</p>}
        {enrollment.isError && <p role="status">注册未完成。请检查 Hub 地址和注册码后重试。</p>}
      </form>
    </main>
  );
}
