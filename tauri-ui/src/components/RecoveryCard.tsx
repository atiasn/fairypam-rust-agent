type Props = { reason?: string };

export function RecoveryCard({ reason }: Props) {
  return (
    <section className="recovery-card" aria-labelledby="recovery-heading">
      <h2 id="recovery-heading">恢复建议</h2>
      <p>{reason ?? '确认 Agent 已通过受控安装入口启动，然后重新打开此界面。'}</p>
      <p>此界面不会自行提升权限、安装程序或启动未知可执行文件。</p>
    </section>
  );
}
