import { useState } from 'react';

import { agentApi } from '../lib/agentApi';

export function StopAgentDialog() {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState<string>();

  return (
    <section className="status-card" aria-labelledby="stop-agent-heading">
      <h2 id="stop-agent-heading">停止 Agent</h2>
      <p>停止 Agent 是独立操作，不会由关闭窗口或退出界面触发。</p>
      <button onClick={() => setOpen(true)} type="button">请求停止 Agent</button>
      {open && (
        <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="stop-agent-title">
          <h3 id="stop-agent-title">确认停止 Agent</h3>
          <p>当前协议没有停止 Agent 的领域命令；此操作不会启动子进程或尝试绕过限制。</p>
          <button
            onClick={() => {
              void agentApi.stopAgentAfterConfirmation().catch((error: unknown) => {
                setMessage(typeof error === 'object' && error && 'code' in error ? String(error.code) : '请求不可用');
              });
            }}
            type="button"
          >
            确认
          </button>
          <button onClick={() => setOpen(false)} type="button">取消</button>
          {message && <p role="status">{message}</p>}
        </div>
      )}
    </section>
  );
}
