type Props = { reason?: string; message?: string };

const recoveryMessages: Record<string, string> = {
  'local.transport.disconnected': '后台服务暂时无法连接，请稍候后重试。',
  'local.transport.pipe_not_found': '后台服务尚未准备完成，请稍候后重试。',
  'local.transport.timeout': '等待服务响应超时，请稍候后重试。',
  'agent.guardian.emergency': '服务已进入保护状态，请检查后再试。',
};

export function RecoveryCard({ reason, message }: Props) {
  return (
    <section className="recovery-card" aria-labelledby="recovery-heading">
      <h2 id="recovery-heading">恢复建议</h2>
      <p>{message ?? recoveryMessages[reason ?? ''] ?? '服务暂时不可用，请稍候后重新打开此界面。'}</p>
      <p>此界面不会自行提升权限、安装程序或启动未知可执行文件。</p>
    </section>
  );
}
