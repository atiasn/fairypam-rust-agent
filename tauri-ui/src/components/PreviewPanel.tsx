export function PreviewPanel() {
  return (
    <section className="status-card" aria-labelledby="preview-heading">
      <h2 id="preview-heading">受控预览</h2>
      <p>
        当前 local-control protocol 不提供经过验证的本地预览 sink；界面不会伪造截图、读取文件或直接调用
        Windows capture。
      </p>
      <p className="code">capture.local_sink_unavailable</p>
    </section>
  );
}
