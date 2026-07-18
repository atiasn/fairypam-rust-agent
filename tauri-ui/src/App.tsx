import { useEffect, useMemo, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api, commandError, type Target } from './api';
import {
  effectiveAgentState,
  reduceAuthority,
  type AgentStateEvent,
  type AuthorityOverride,
} from './state';
import { useBoundedPreview, type ControlledPreview } from './preview';

type Page = 'home' | 'wizard' | 'targets' | 'connection' | 'safety' | 'maintenance' | 'diagnostics';

const pages: Array<[Page, string]> = [
  ['home', '首页'],
  ['wizard', '首次向导'],
  ['targets', 'Profile 与目标'],
  ['connection', '连接'],
  ['safety', '输入安全'],
  ['maintenance', '更新与自启动'],
  ['diagnostics', '日志诊断'],
];

export function App() {
  const queryClient = useQueryClient();
  const [page, setPage] = useState<Page>('home');
  const [authority, setAuthority] = useState<AuthorityOverride>(null);
  const [stopRequested, setStopRequested] = useState(false);
  const [profileId, setProfileId] = useState('');
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(null);
  const [preview, setPreview] = useState<ControlledPreview | null>(null);
  const [previewError, setPreviewError] = useState('');
  const previewUrl = useBoundedPreview(preview);

  const statusQuery = useQuery({
    queryKey: ['agent-status'],
    queryFn: api.status,
    refetchInterval: 3000,
  });
  const diagnosticsQuery = useQuery({
    queryKey: ['diagnostics'],
    queryFn: api.diagnostics,
    enabled: statusQuery.isSuccess,
    refetchInterval: 5000,
  });
  const suiteQuery = useQuery({
    queryKey: ['suite-status'],
    queryFn: api.suiteStatus,
    enabled: statusQuery.isSuccess,
    refetchInterval: 5000,
  });
  const doctorQuery = useQuery({
    queryKey: ['doctor'],
    queryFn: api.doctor,
    enabled: statusQuery.isSuccess,
  });
  const profilesQuery = useQuery({
    queryKey: ['profiles'],
    queryFn: api.profiles,
    enabled: statusQuery.isSuccess,
  });
  const targetsQuery = useQuery({
    queryKey: ['targets', profileId],
    queryFn: () => api.targets(profileId),
    enabled: Boolean(profileId),
  });

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<AgentStateEvent>('agent-state', ({ payload }) => {
      if (payload.kind === 'stop_requested') {
        setStopRequested(true);
        setPage('safety');
        return;
      }
      setAuthority((current) => reduceAuthority(current, payload));
      if (payload.kind === 'status') {
        queryClient.setQueryData(['agent-status'], payload.status);
      }
    }).then((dispose) => {
      if (disposed) dispose();
      else unlisten = dispose;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [queryClient]);

  const effective = effectiveAgentState(statusQuery.data, authority);
  const error = effective.error ?? (statusQuery.error ? commandError(statusQuery.error) : null);

  const selectMutation = useMutation({
    mutationFn: (targetId: string) => api.selectTarget(profileId, targetId),
    onSuccess: (target) => {
      setSelectedTarget(target);
      void queryClient.invalidateQueries({ queryKey: ['agent-status'] });
    },
  });
  const focusMutation = useMutation({ mutationFn: api.focusTarget });
  const closeMutation = useMutation({
    mutationFn: () => api.closeTarget(),
    onSuccess: () => {
      setSelectedTarget(null);
      void queryClient.invalidateQueries({ queryKey: ['agent-status'] });
    },
  });
  const releaseMutation = useMutation({
    mutationFn: api.releaseAll,
    onSuccess: (release) => setAuthority({ kind: 'emergency', release }),
  });
  const previewMutation = useMutation({
    mutationFn: () => api.preview(),
    onSuccess: (value) => {
      setPreviewError('');
      setPreview(value);
    },
    onError: (failure) => {
      setPreview(null);
      setPreviewError(commandError(failure).message);
    },
  });
  const updateMutation = useMutation({
    mutationFn: api.requestUpdate,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['suite-status'] }),
  });
  const autostartMutation = useMutation({
    mutationFn: api.setAutostart,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['suite-status'] }),
  });

  const content = useMemo(() => {
    const props = {
      effective,
      error,
      diagnosticsQuery,
      suiteQuery,
      doctorQuery,
      profilesQuery,
      profileId,
      setProfileId,
      targetsQuery,
      selectedTarget,
      selectMutation,
      focusMutation,
      closeMutation,
      releaseMutation,
      previewUrl,
      previewError,
      setPreviewError,
      previewMutation,
      updateMutation,
      autostartMutation,
      stopRequested,
      setStopRequested,
    };
    switch (page) {
      case 'wizard': return <Wizard {...props} />;
      case 'targets': return <TargetsPage {...props} />;
      case 'connection': return <ConnectionPage {...props} />;
      case 'safety': return <SafetyPage {...props} />;
      case 'maintenance': return <MaintenancePage {...props} />;
      case 'diagnostics': return <DiagnosticsPage {...props} />;
      default: return <HomePage {...props} />;
    }
  }, [
    page, effective, error, diagnosticsQuery, suiteQuery, doctorQuery, profilesQuery, profileId, targetsQuery,
    selectedTarget, selectMutation, focusMutation, closeMutation, releaseMutation, previewUrl,
    previewError, previewMutation, updateMutation, autostartMutation, stopRequested,
  ]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div><strong>FairyPam Agent</strong><span>普通权限控制中心</span></div>
        <StatusBadge effective={effective} loading={statusQuery.isLoading} />
      </header>
      <aside>
        <nav aria-label="主导航">
          {pages.map(([id, label]) => (
            <button key={id} className={page === id ? 'active' : ''} aria-current={page === id ? 'page' : undefined} onClick={() => setPage(id)}>
              {label}
            </button>
          ))}
        </nav>
        <p className="boundary">界面退出不会停止 Agent。此 UI 不持有截图、输入、进程或系统任务权限。</p>
      </aside>
      <main id="main-content" tabIndex={-1}>{content}</main>
    </div>
  );
}

type PageProps = any;

function HomePage({ effective, error, diagnosticsQuery, suiteQuery }: PageProps) {
  const recovery = error ? recoveryMessage(error.code) : null;
  return <Page title="运行总览" subtitle="状态来自管理员 Agent 的本地领域接口，不由界面推断。">
    {recovery && <Alert title={recovery.title}>{recovery.body}</Alert>}
    <div className="card-grid">
      <Metric label="Agent" value={effective.online ? '在线' : '离线'} tone={effective.online ? 'ok' : 'danger'} />
      <Metric label="Guardian" value={suiteQuery.data?.guardian === 'installed' ? '已安装，健康未验证' : '缺失或未验证'} tone={suiteQuery.data?.guardian === 'installed' ? 'warn' : 'danger'} />
      <Metric label="Core" value={diagnosticsQuery.data?.controlConnected ? '已连接' : '未连接'} />
      <Metric label="控制状态" value={effective.emergency ? '紧急停止已生效' : suiteQuery.data?.controlMode === 'dry_run' ? 'DryRun' : '未验证'} tone={effective.emergency ? 'danger' : 'warn'} />
    </div>
    <section className="panel"><h2>安全边界</h2><p>GUI 仅通过命名管道 local client 查询和调用显式命令。关闭、崩溃或更新 GUI 不会终止 Agent、Guardian 或 Core Channel。</p></section>
  </Page>;
}

function Wizard(props: PageProps) {
  const { effective, diagnosticsQuery, suiteQuery, doctorQuery, profilesQuery, profileId, setProfileId,
    targetsQuery, selectedTarget, selectMutation, releaseMutation, previewMutation } = props;
  const doctorOk = Boolean(doctorQuery.data?.length) && doctorQuery.data.every((item: any) => item.status !== 'error');
  const guardianPresent = suiteQuery.data?.guardian === 'installed';
  // ponytail: file presence is not a heartbeat; keep this gate closed until Guardian owns a health query.
  const guardianOk = false;
  const coreOk = diagnosticsQuery.data?.controlConnected === true;
  const dryRunVerified = suiteQuery.data?.controlMode === 'dry_run';
  const previewReady = previewMutation.isSuccess;
  const startupReady = suiteQuery.data?.autostart === 'enabled';
  const installationReady = suiteQuery.data?.installation === 'healthy';
  const complete = installationReady && doctorOk && effective.online && guardianOk && Boolean(profileId) && Boolean(selectedTarget) && previewReady && coreOk && dryRunVerified && Boolean(releaseMutation.data) && startupReady;
  const agentUnavailable = !effective.online || effective.emergency;
  return <Page title="首次向导" subtitle="每一步独立验证；完成向导也不会进入 Armed 或发送真实输入。">
    <ol className="wizard-list">
      <WizardStep title="1. 安装完整性" ok={installationReady && doctorOk} detail={suiteQuery.isLoading ? '检查中' : installationReady && doctorOk ? '套件 manifest 与 Doctor 检查通过' : '请从安装维护入口修复套件'} />
      <WizardStep title="2. Agent 与 Guardian" ok={effective.online && guardianOk} detail={guardianPresent ? 'Guardian 已安装，但运行健康尚未由协议证明' : 'Guardian 成员缺失或完整性未知'} />
      <li><h2>3. Profile</h2><select aria-label="选择 Profile" disabled={agentUnavailable} value={profileId} onChange={(event) => setProfileId(event.target.value)}><option value="">请选择</option>{profilesQuery.data?.map((id: string) => <option key={id}>{id}</option>)}</select></li>
      <li><h2>4. 目标窗口</h2>{targetsQuery.data?.length ? targetsQuery.data.map((target: Target) => <button disabled={agentUnavailable} key={target.targetId} onClick={() => selectMutation.mutate(target.targetId)}>{target.title} · {target.processName}</button>) : <p>没有可用目标</p>}</li>
      <li><h2>5. 受控截图</h2><p>截图由 Agent 对已锁定目标执行；GUI 只接收有界预览。</p><button disabled={agentUnavailable || !selectedTarget || previewMutation.isPending} onClick={() => previewMutation.mutate()}>刷新预览</button></li>
      <WizardStep title="6. Core 连接" ok={coreOk} detail={coreOk ? '控制通道已连接' : '等待 Core 连接'} />
      <WizardStep title="7. DryRun" ok={dryRunVerified} detail={dryRunVerified ? 'Agent 明确报告 DryRun' : '未取得控制模式证据'} />
      <li><h2>8. 紧急停止</h2><button className="danger" disabled={agentUnavailable} onClick={() => releaseMutation.mutate()}>验证释放全部输入</button>{releaseMutation.data && <p>已释放 {releaseMutation.data.holds} 个保持项。</p>}</li>
      <WizardStep title="9. Agent 自启动" ok={startupReady} detail={startupReady ? '固定 Agent Task 已启用' : '固定 Agent Task 未启用或已漂移'} />
    </ol>
    <button disabled={!complete}>完成向导</button>
  </Page>;
}

function TargetsPage({ profileId, setProfileId, profilesQuery, targetsQuery, selectedTarget,
  selectMutation, focusMutation, closeMutation, previewUrl, previewError, previewMutation, effective }: PageProps) {
  const controlsDisabled = !effective.online || effective.emergency;
  return <Page title="Profile 与目标" subtitle="目标枚举、锁定、聚焦和关闭全部由管理员 Agent 执行。">
    <section className="panel"><label>Profile<select disabled={controlsDisabled} value={profileId} onChange={(event) => setProfileId(event.target.value)}><option value="">请选择</option>{profilesQuery.data?.map((id: string) => <option key={id}>{id}</option>)}</select></label>
      <div className="target-list">{targetsQuery.isLoading ? <p>正在扫描目标…</p> : targetsQuery.data?.length ? targetsQuery.data.map((target: Target) => <button disabled={controlsDisabled} key={target.targetId} onClick={() => selectMutation.mutate(target.targetId)}>{target.title}<small>{target.processName}</small></button>) : <p>没有匹配目标。</p>}</div>
    </section>
    <section className="panel"><h2>当前目标</h2><p>{selectedTarget?.title ?? '尚未锁定'}</p><div className="actions"><button disabled={controlsDisabled || !selectedTarget} onClick={() => focusMutation.mutate()}>聚焦</button><button disabled={controlsDisabled || !selectedTarget} onClick={() => window.confirm('确认请求 Agent 关闭当前目标窗口？') && closeMutation.mutate()}>关闭目标</button></div></section>
    <section className="panel"><h2>受控预览</h2>{previewUrl ? <img className="preview" src={previewUrl} alt="Agent 提供的目标预览" /> : <p>{previewError || '锁定目标后可请求一次 Agent 预览。'}</p>}<button disabled={controlsDisabled || !selectedTarget || previewMutation.isPending} onClick={() => previewMutation.mutate()}>刷新预览</button></section>
  </Page>;
}

function ConnectionPage({ diagnosticsQuery }: PageProps) {
  return <Page title="连接" subtitle="只展示本地 Agent 汇总后的非敏感连接状态。">
    <dl className="details"><Row name="Core Channel" value={diagnosticsQuery.data?.controlConnected ? '已连接' : '未连接'} /><Row name="协议" value={diagnosticsQuery.data?.protocol ?? '未知'} /><Row name="审计" value={diagnosticsQuery.data?.auditEnabled ? '已启用' : '未启用'} /></dl>
    <Alert title="凭据隔离">GUI 不读取或展示 mTLS 私钥、完整 token、API Key 或远程地址配置。</Alert>
  </Page>;
}

function SafetyPage({ effective, releaseMutation, stopRequested, setStopRequested }: PageProps) {
  return <Page title="输入安全" subtitle="紧急停止事件优先于查询缓存；本页没有 Armed 命令。">
    {stopRequested && <div role="dialog" aria-modal="true" aria-labelledby="stop-title" className="panel danger-panel"><h2 id="stop-title">停止 Agent</h2><p>当前生产 local protocol 未提供停止 Agent 命令，因此没有执行任何操作。请使用受支持的安装维护入口。</p><button onClick={() => setStopRequested(false)}>知道了</button></div>}
    <Metric label="安全状态" value={effective.emergency ? '紧急停止已生效' : '未触发紧急停止'} tone={effective.emergency ? 'danger' : 'warn'} />
    <button className="danger large" disabled={releaseMutation.isPending} onClick={() => window.confirm('确认请求管理员 Agent 释放全部输入？') && releaseMutation.mutate()}>紧急停止并释放全部输入</button>
    {releaseMutation.error && <Alert title="释放失败">{commandError(releaseMutation.error).message}</Alert>}
  </Page>;
}

function MaintenancePage({ suiteQuery, updateMutation, autostartMutation }: PageProps) {
  const suite = suiteQuery.data;
  return <Page title="更新与自启动" subtitle="界面不会自行写注册表、计划任务、安装目录或启动进程。">
    {suite?.installation !== 'healthy' && <Alert title="安装不完整">套件 manifest 校验未通过；Repair 必须从受支持的提升安装入口执行。</Alert>}
    <dl className="details"><Row name="更新状态" value={suite?.update ?? '未知'} /><Row name="自启动" value={suite?.autostart ?? '未知'} /><Row name="控制模式" value={suite?.controlMode ?? '未知'} /></dl>
    <div className="actions"><button disabled={!suite || suite.installation !== 'healthy' || !suite.canRequestUpdate || updateMutation.isPending} onClick={() => window.confirm('确认启动固定 Updater Task 检查并应用可用更新？') && updateMutation.mutate()}>检查并应用更新</button><button disabled title="Repair 需要独立的管理员安装入口">修复安装</button><button disabled={!suite || suite.autostart === 'missing' || autostartMutation.isPending} onClick={() => autostartMutation.mutate(suite.autostart !== 'enabled')}>{suite?.autostart === 'enabled' ? '关闭 Agent 自启动' : '启用 Agent 自启动'}</button></div>
    {updateMutation.data?.accepted && <p>已提交固定 Updater Task；最终结果以更新状态和审计回执为准。</p>}
    {autostartMutation.data?.accepted && <p>固定 Agent Task 自启动设置已更新。</p>}
    {updateMutation.error && <Alert title="更新请求失败">{commandError(updateMutation.error).message}</Alert>}
    {autostartMutation.error && <Alert title="自启动修改失败">{commandError(autostartMutation.error).message}</Alert>}
  </Page>;
}

function DiagnosticsPage({ diagnosticsQuery, doctorQuery }: PageProps) {
  return <Page title="日志诊断" subtitle="仅展示 Agent 返回的脱敏诊断摘要；不授予任意文件读取权限。">
    {diagnosticsQuery.isLoading ? <p>正在读取诊断…</p> : diagnosticsQuery.error ? <Alert title="诊断失败">{commandError(diagnosticsQuery.error).message}</Alert> : <dl className="details"><Row name="Agent 版本" value={diagnosticsQuery.data?.agentVersion ?? '-'} /><Row name="Build" value={diagnosticsQuery.data?.buildCommit ?? '-'} /><Row name="协议" value={diagnosticsQuery.data?.protocol ?? '-'} /></dl>}
    <section className="panel"><h2>Doctor</h2>{doctorQuery.data?.length ? <ul>{doctorQuery.data.map((item: any) => <li key={item.component}><strong>{item.component}</strong>：{item.summary}（{item.status}）</li>)}</ul> : <p>暂无检查结果。</p>}</section>
    <button disabled>导出脱敏诊断</button>
  </Page>;
}

function Page({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return <><header className="page-head"><p>FairyPam / Desktop Suite</p><h1>{title}</h1><span>{subtitle}</span></header>{children}</>;
}

function StatusBadge({ effective, loading }: { effective: ReturnType<typeof effectiveAgentState>; loading: boolean }) {
  const label = loading ? '读取中' : effective.emergency ? '紧急停止' : effective.online ? 'Agent 在线' : 'Agent 离线';
  return <div className={`status ${effective.online ? 'ok' : effective.emergency ? 'danger' : 'warn'}`} role="status"><i />{label}</div>;
}

function Metric({ label, value, tone = '' }: { label: string; value: string; tone?: string }) {
  return <section className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong></section>;
}

function Alert({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="alert" role="alert"><h2>{title}</h2><p>{children}</p></section>;
}

function WizardStep({ title, ok, detail }: { title: string; ok: boolean; detail: string }) {
  return <li><h2>{title}</h2><p><span className="text-status">{ok ? '已通过' : '待处理'}：</span>{detail}</p></li>;
}

function Row({ name, value }: { name: string; value: string }) {
  return <><dt>{name}</dt><dd>{value}</dd></>;
}

function recoveryMessage(code: string) {
  if (code === 'agent_unavailable' || code === 'io_error' || code === 'timeout') return { title: 'Agent 未运行或本地管道不可用', body: '确认 Agent 与 Guardian 固定任务正在运行；若安装损坏，请使用安装维护入口 Repair。' };
  if (code === 'protocol_version_mismatch' || code === 'protocol_error') return { title: '版本不一致', body: 'UI 与 Agent 本地协议不兼容。请更新为同一套件版本。' };
  if (code === 'permission_denied') return { title: '当前用户无权访问 Agent', body: '保持 GUI 普通权限运行，并由管理员修复本地 ACL；不要提升 GUI。' };
  return { title: '无法读取 Agent 状态', body: '打开日志诊断查看错误，并从受支持的维护入口恢复。' };
}
