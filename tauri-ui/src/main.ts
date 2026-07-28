import { invoke } from '@tauri-apps/api/core';
import './styles.css';

type Page = 'dashboard' | 'runtime' | 'connection' | 'capture' | 'logs' | 'selftest';

type RuntimeStatus = {
  phase: string;
  label: string;
  message: string;
  can_start: boolean;
  can_stop: boolean;
  can_restart: boolean;
};

type AppConfig = {
  hub: { ws_url: string; api_key: string };
  agent: { name: string; log_level: string };
  runtime: {
    auto_update: boolean;
    auto_start: boolean;
    command_timeout_s: number;
    launch_allowlist: string[];
  };
  capture: {
    target_display: number;
    fps: number;
    jpeg_quality: number;
    encoder: string;
  };
};

type DashboardState = {
  agent_name: string;
  hub_url: string;
  runtime: RuntimeStatus;
  fps: number;
  encoder: string;
  config_path: string;
  log_path: string;
  cli_preview: string;
};

type GameCandidate = {
  discovery_id: string;
  display_name: string;
  display_version?: string;
  launch_path?: string;
  supported: boolean;
  exists_on_disk: boolean;
  status: string;
  self_test_target?: {
    profile_id: string;
    executable: string;
    working_dir: string;
  };
};

type TargetWindow = {
  pid: number;
  title: string;
  class_name?: string;
  rect: { left: number; top: number; right: number; bottom: number };
};

type SelfTestLaunch = {
  pid: number;
  window: TargetWindow;
  privilege: string;
};

type SelfTestCapture = {
  width: number;
  height: number;
  bytes: number;
  jpeg: number[];
};

const pages: Array<{ id: Page; label: string; hint: string }> = [
  { id: 'dashboard', label: '总览', hint: '运行概览' },
  { id: 'runtime', label: '运行控制', hint: '启动与停止' },
  { id: 'connection', label: '连接配置', hint: 'Hub / Agent' },
  { id: 'capture', label: '采集设置', hint: '采集参数' },
  { id: 'logs', label: '日志', hint: '最近日志' },
  { id: 'selftest', label: '本地自检', hint: '游戏自检' },
];

const state = {
  page: 'dashboard' as Page,
  config: null as AppConfig | null,
  dashboard: null as DashboardState | null,
  runtime: {
    phase: 'stopped',
    label: '正在读取',
    message: '正在读取运行状态',
    can_start: false,
    can_stop: false,
    can_restart: false,
  } as RuntimeStatus,
  runtimeBusy: false,
  logs: '',
  logFilter: '',
  games: [] as GameCandidate[],
  selectedGameId: '',
  scanning: false,
  selfTestBusy: false,
  selfTestPid: null as number | null,
  selfTestWindow: null as TargetWindow | null,
  selfTestStatus: '',
  selfTestPreviewUrl: '',
  selfTestPreviewLabel: '',
  status: '控制台已就绪',
  error: '',
};

const app = document.querySelector<HTMLDivElement>('#app')!;
let runtimePollId: number | null = null;

window.addEventListener('contextmenu', (event) => event.preventDefault());

function command<T>(name: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(name, args);
}

async function refreshAll(): Promise<void> {
  try {
    state.dashboard = await command<DashboardState>('load_dashboard_state');
    state.runtime = state.dashboard.runtime;
    state.config = await command<AppConfig>('load_config');
    state.status = '状态已刷新';
    state.error = '';
  } catch (error) {
    state.status = `读取失败：${String(error)}`;
    state.error = state.status;
  }
  render();
}

function isActiveRuntimePhase(): boolean {
  return ['starting', 'running', 'stopping'].includes(state.runtime.phase);
}

function syncRuntimePolling(): void {
  const shouldPoll = isActiveRuntimePhase();
  if (shouldPoll && runtimePollId === null) {
    runtimePollId = window.setInterval(() => void refreshRuntimeStatus(), 1_000);
  }
  if (!shouldPoll && runtimePollId !== null) {
    window.clearInterval(runtimePollId);
    runtimePollId = null;
  }
}

async function refreshRuntimeStatus(): Promise<void> {
  if (state.runtimeBusy) return;
  try {
    const nextRuntime = await command<RuntimeStatus>('runtime_status');
    const changed =
      state.runtime.phase !== nextRuntime.phase ||
      state.runtime.label !== nextRuntime.label ||
      state.runtime.message !== nextRuntime.message ||
      state.runtime.can_start !== nextRuntime.can_start ||
      state.runtime.can_stop !== nextRuntime.can_stop ||
      state.runtime.can_restart !== nextRuntime.can_restart;
    if (!changed) return;
    state.runtime = nextRuntime;
  } catch (error) {
    state.status = '运行状态读取失败';
    state.error = `${state.status}：${String(error)}`;
    render();
    return;
  }
  render();
}

function setPage(page: Page): void {
  state.page = page;
  render();
}

async function saveConfig(): Promise<void> {
  if (!state.config) return;
  try {
    state.config = await command<AppConfig>('save_config', { config: state.config });
    await refreshAll();
    state.status = '配置已保存';
  } catch (error) {
    state.status = `保存失败：${String(error)}`;
    state.error = state.status;
    render();
  }
}

async function runtimeAction(action: 'start_runtime' | 'stop_runtime' | 'restart_runtime'): Promise<void> {
  if (!runtimeActionAllowed(action)) return;
  state.runtimeBusy = true;
  state.error = '';
  state.status = '正在提交运行请求...';
  render();
  try {
    state.runtime = await command<RuntimeStatus>(action);
    state.status =
      action === 'stop_runtime'
        ? '已提交停止请求'
        : action === 'restart_runtime'
          ? '已提交重启请求，等待 Agent 就绪'
          : '已提交启动请求，等待 Agent 就绪';
  } catch (error) {
    state.status = '运行请求失败';
    state.error = `${state.status}：${String(error)}`;
  } finally {
    state.runtimeBusy = false;
  }
  render();
}

function runtimeActionAllowed(action: 'start_runtime' | 'stop_runtime' | 'restart_runtime'): boolean {
  if (state.runtimeBusy || state.scanning || state.selfTestBusy) return false;
  if (action === 'start_runtime') return state.runtime.can_start === true;
  if (action === 'stop_runtime') return state.runtime.can_stop === true;
  return state.runtime.can_restart === true;
}

async function refreshLogs(): Promise<void> {
  try {
    state.logs = await command<string>('read_log_tail', { filter: state.logFilter || null });
    state.status = '日志已刷新';
  } catch (error) {
    state.logs = `日志读取失败：${String(error)}`;
    state.error = state.logs;
  }
  render();
}

async function scanGames(): Promise<void> {
  if (state.runtimeBusy || state.scanning || state.selfTestBusy) return;
  state.scanning = true;
  state.status = '扫描中...';
  state.error = '';
  render();
  try {
    state.games = await command<GameCandidate[]>('scan_local_games');
    if (!state.selectedGameId) {
      state.selectedGameId = state.games.find((game) => game.self_test_target)?.discovery_id ?? '';
    }
    state.status = `扫描完成：发现 ${state.games.length} 项`;
  } catch (error) {
    state.status = `扫描失败：${String(error)}`;
    state.error = state.status;
  } finally {
    state.scanning = false;
  }
  render();
}

async function selfTestLaunch(): Promise<void> {
  const selected = selectedGame();
  if (!selected?.self_test_target || state.runtimeBusy || state.scanning || state.selfTestBusy) return;
  state.selfTestBusy = true;
  state.selfTestStatus = '启动中...';
  state.error = '';
  render();
  try {
    clearSelfTestPreview();
    const result = await command<SelfTestLaunch>('self_test_launch', {
      discoveryId: selected.discovery_id,
    });
    state.selfTestPid = result.pid;
    state.selfTestWindow = result.window;
    state.selfTestStatus = `已启动 PID=${result.pid}，窗口：${result.window.title}`;
  } catch (error) {
    state.selfTestStatus = formatSelfTestLaunchError(error);
    state.status = '自检启动失败';
    state.error = state.selfTestStatus;
  } finally {
    state.selfTestBusy = false;
  }
  render();
}

async function selfTestCapture(): Promise<void> {
  if (!state.selfTestPid || state.runtimeBusy || state.scanning || state.selfTestBusy) return;
  state.selfTestBusy = true;
  state.selfTestStatus = '截图中...';
  state.error = '';
  render();
  try {
    const frame = await command<SelfTestCapture>('self_test_capture');
    setSelfTestPreview(frame);
    state.selfTestStatus = `截图成功：${frame.width}x${frame.height} / ${Math.round(frame.bytes / 1024)} KB`;
  } catch (error) {
    state.selfTestStatus = `截图失败：${String(error)}`;
    state.error = state.selfTestStatus;
  } finally {
    state.selfTestBusy = false;
  }
  render();
}

async function selfTestInput(action: string): Promise<void> {
  if (!state.selfTestPid || state.runtimeBusy || state.scanning || state.selfTestBusy) return;
  state.selfTestBusy = true;
  state.selfTestStatus = '发送输入中...';
  state.error = '';
  render();
  try {
    state.selfTestWindow = await command<TargetWindow>('self_test_input', { action });
    state.selfTestStatus = action === 'release_all' ? '已释放全部输入' : `输入已发送：${action}`;
  } catch (error) {
    state.selfTestStatus = `输入失败：${String(error)}`;
    state.error = state.selfTestStatus;
  } finally {
    state.selfTestBusy = false;
  }
  render();
}

async function selfTestClose(): Promise<void> {
  if (!state.selfTestPid || state.runtimeBusy || state.scanning || state.selfTestBusy) return;
  state.selfTestBusy = true;
  state.selfTestStatus = '关闭中...';
  state.error = '';
  render();
  try {
    await command<void>('self_test_close');
    state.selfTestPid = null;
    state.selfTestWindow = null;
    state.selfTestStatus = '已关闭测试目标';
  } catch (error) {
    state.selfTestStatus = `关闭失败：${String(error)}`;
    state.error = state.selfTestStatus;
  } finally {
    state.selfTestBusy = false;
  }
  render();
}

function render(): void {
  const config = state.config;
  const dash = state.dashboard;
  app.innerHTML = `
    <div class="app">
      <header class="top">
        <div class="brand">
          <div class="brand-mark"></div>
          <div class="brand-title">
            <strong>FairyPam Agent</strong>
            <span>Local Rust Control Deck</span>
          </div>
        </div>
        <div class="status-strip">
          ${topChip('RUNTIME', state.runtime.label, phaseTone(state.runtime.phase), true)}
          ${topChip('HUB', dash?.hub_url ?? config?.hub.ws_url ?? '未读取')}
          ${topChip('STATUS', state.status, '', true)}
        </div>
      </header>
      <div class="shell">
        <nav class="nav">
          <div class="nav-card"><b>Night Ops</b><span>本地运行控制</span><div class="mini-bars"><i></i><i></i><i></i></div></div>
          <div class="nav-label">Navigation</div>
          ${pages
            .map(
              (page) => `
                <button data-page="${page.id}" class="${state.page === page.id ? 'active' : ''}">
                  <span>${page.label}<small>${page.hint}</small></span>
                </button>`,
            )
            .join('')}
          <div class="nav-note">本地控制台显示运行状态和安全自检结果。</div>
        </nav>
        <main class="main">
          ${state.error ? `<div class="operation-error" role="alert">${escapeHtml(state.error)}</div>` : ''}
          ${renderPage(config, dash)}
        </main>
        <aside class="operator">
          ${operatorPanel(config, dash)}
        </aside>
      </div>
    </div>
  `;

  document.querySelectorAll<HTMLButtonElement>('[data-page]').forEach((button) => {
    button.addEventListener('click', () => setPage(button.dataset.page as Page));
  });
  wireForms();
  syncRuntimePolling();
}

function topChip(label: string, value: string, tone = '', live = false): string {
  const liveAttributes = live ? ' aria-live="polite" aria-atomic="true"' : '';
  return `<div class="chip ${tone}"><span class="led ${tone}"></span>${label}<strong${liveAttributes}>${escapeHtml(value)}</strong></div>`;
}

function renderPage(config: AppConfig | null, dash: DashboardState | null): string {
  switch (state.page) {
    case 'runtime':
      return pageFrame('运行控制', '启动、停止和重启由 Agent 统一管理，状态会自动刷新。', runtimePanel());
    case 'connection':
      return pageFrame('连接配置', '保存 Hub、Agent 和本地运行设置。', connectionPanel(config));
    case 'capture':
      return pageFrame('采集设置', '保存采集参数，采集随 Agent 运行状态统一调度。', capturePanel(config));
    case 'logs':
      return pageFrame('日志', '显示已脱敏的最近日志，可按关键字过滤。', logsPanel());
    case 'selftest':
      return pageFrame('本地自检', '原神本机能力检查；选择可自检游戏并启动会话后启用操作。', selfTestPanel());
    default:
      return pageFrame('总览', 'Mission board：只读状态、路径、采集和本地能力概览。', dashboardPanel(config, dash));
  }
}

function pageFrame(title: string, sub: string, body: string): string {
  return `
    <section class="page active">
      <div class="page-head">
        <div><div class="kicker">FairyPam Agent</div><h1>${title}</h1><div class="sub">${sub}</div></div>
        <div class="mode">本地控制台</div>
      </div>
      ${body}
    </section>
  `;
}

function dashboardPanel(config: AppConfig | null, dash: DashboardState | null): string {
  return `
    <div class="hero-grid">
      <section class="hero-panel">
        <div class="hero-copy">
          <span class="kicker">LOCAL AGENT / NIGHT OPS</span>
          <h2>${escapeHtml(config?.agent.name ?? dash?.agent_name ?? 'FairyPam Agent')}</h2>
          <p>${escapeHtml(state.runtime.message)}</p>
        </div>
        <div class="signal-orbit" aria-hidden="true"><i></i><i></i><i></i></div>
      </section>
      <div class="stat-grid">
        ${statCard('Runtime', state.runtime.label, phaseTone(state.runtime.phase))}
        ${statCard('FPS', String(config?.capture.fps ?? dash?.fps ?? '-'))}
        ${statCard('Encoder', config?.capture.encoder ?? dash?.encoder ?? '-')}
        ${statCard('Discovery', `${state.games.length} 项`)}
      </div>
    </div>
    <div class="grid two">
      ${panel('Core Matrix', rows([
        ['Agent', config?.agent.name ?? dash?.agent_name ?? '-'],
        ['Hub URL', config?.hub.ws_url ?? dash?.hub_url ?? '-'],
        ['配置文件', dash?.config_path ?? 'config.yaml'],
        ['日志文件', dash?.log_path ?? 'logs/agent.log'],
        ['CLI', dash?.cli_preview ?? 'fairypam-agent --run --config "config.yaml" --log-file "logs/agent.log"'],
      ]))}
      ${panel('Capture Telemetry', rows([
        ['目标显示器', String(config?.capture.target_display ?? '-')],
        ['FPS', String(config?.capture.fps ?? dash?.fps ?? '-')],
        ['JPEG 质量', `${config?.capture.jpeg_quality ?? '-'}%`],
        ['编码器', config?.capture.encoder ?? dash?.encoder ?? '-'],
      ]))}
    </div>
  `;
}

function runtimePanel(): string {
  const startDisabled = runtimeActionAllowed('start_runtime') ? '' : 'disabled';
  const restartDisabled = runtimeActionAllowed('restart_runtime') ? '' : 'disabled';
  const stopDisabled = runtimeActionAllowed('stop_runtime') ? '' : 'disabled';
  return `
    <div class="grid two">
      ${panel('运行状态', `
        ${rows([['状态', state.runtime.label], ['详情', state.runtime.message]])}
        <div class="actions">
          <button id="start-runtime" ${startDisabled}>启动 Agent</button>
          <button id="restart-runtime" ${restartDisabled}>重启 Agent</button>
          <button id="stop-runtime" ${stopDisabled}>停止 Agent</button>
        </div>
      `)}
      ${panel('操作提示', `
        ${rows([['状态刷新', isActiveRuntimePhase() ? '每秒刷新' : '等待操作'], ['操作状态', state.runtimeBusy || state.scanning || state.selfTestBusy ? '处理中' : '可用'], ['失败反馈', '会显示在窗口内']])}
        <p class="muted">启动完成前，界面会保持“正在启动”状态，不会提前显示为运行中。</p>
      `)}
    </div>
  `;
}

function connectionPanel(config: AppConfig | null): string {
  return `
    ${panel('Hub / Agent', `
      <label>Hub URL<input id="hub-url" value="${escapeAttr(config?.hub.ws_url ?? '')}" /></label>
      <label>API Key<input id="api-key" type="password" value="${escapeAttr(config?.hub.api_key ?? '')}" /></label>
      <label>Agent 名称<input id="agent-name" value="${escapeAttr(config?.agent.name ?? '')}" /></label>
      <label>日志级别<select id="log-level">${['trace', 'debug', 'info', 'warn', 'error'].map((level) => `<option ${config?.agent.log_level === level ? 'selected' : ''}>${level}</option>`).join('')}</select></label>
      <label class="check"><input id="auto-update" type="checkbox" ${config?.runtime.auto_update ? 'checked' : ''} />自动更新</label>
      <label class="check"><input id="auto-start" type="checkbox" ${config?.runtime.auto_start ? 'checked' : ''} />自动启动</label>
      <label>命令超时时间（秒）<input id="command-timeout" type="number" min="10" max="600" value="${config?.runtime.command_timeout_s ?? 60}" /></label>
      <label>允许启动列表<textarea id="allowlist">${escapeHtml((config?.runtime.launch_allowlist ?? []).join('\n'))}</textarea></label>
      <p class="muted">允许启动列表为空时，会拒绝远程启动游戏。</p>
      <button id="save-connection">保存配置</button>
    `)}
  `;
}

function capturePanel(config: AppConfig | null): string {
  return `
    ${panel('采集参数', `
      <label>目标显示器<input id="target-display" type="number" min="0" value="${config?.capture.target_display ?? 0}" /></label>
      <label>FPS<input id="fps" type="number" min="1" max="120" value="${config?.capture.fps ?? 30}" /></label>
      <label>JPEG 质量<input id="jpeg-quality" type="number" min="1" max="100" value="${config?.capture.jpeg_quality ?? 80}" /></label>
      <label>编码器<select id="encoder">${['media_foundation', 'gdi'].map((encoder) => `<option ${config?.capture.encoder === encoder ? 'selected' : ''}>${encoder}</option>`).join('')}</select></label>
      <button id="save-capture">保存配置</button>
    `)}
  `;
}

function logsPanel(): string {
  return `
    ${panel('最近日志', `
      <div class="inline"><input id="log-filter" placeholder="过滤：error / warn / hub / runtime" value="${escapeAttr(state.logFilter)}" /><button id="refresh-logs">刷新</button></div>
      <pre>${escapeHtml(state.logs || '暂无日志，请点击刷新。')}</pre>
    `)}
  `;
}

function selfTestPanel(): string {
  const selected = state.games.find((game) => game.discovery_id === state.selectedGameId);
  const canLaunch = Boolean(selected?.self_test_target && selected.supported && selected.exists_on_disk);
  const hasTarget = Boolean(state.selfTestPid);
  const busy = state.runtimeBusy || state.scanning || state.selfTestBusy;
  const scanDisabled = busy ? 'disabled' : '';
  const launchDisabled = !canLaunch || busy ? 'disabled' : '';
  const actionDisabled = !hasTarget || busy ? 'disabled' : '';
  return `
    ${panel('游戏发现', `
      <button id="scan-games" ${scanDisabled}>${state.scanning ? '扫描中...' : '扫描本机游戏'}</button>
      <div class="games">
        ${state.games.map((game) => `
          <button class="game ${state.selectedGameId === game.discovery_id ? 'selected' : ''}" data-game="${escapeAttr(game.discovery_id)}">
            <strong>${escapeHtml(game.display_name)}</strong>
            <span>${game.self_test_target ? '可自检' : escapeHtml(game.status === 'ok' ? '已发现，暂不支持操作' : game.status)}</span>
            <small>${escapeHtml(game.launch_path ?? game.status)}</small>
          </button>
        `).join('') || '<p class="muted">尚未扫描。</p>'}
      </div>
      ${selected ? rows([
        ['配置档', selected.self_test_target?.profile_id ?? '-'],
        ['启动路径', selected.self_test_target?.executable ?? selected.launch_path ?? '-'],
        ['窗口', state.selfTestWindow?.title ?? '-'],
        ['PID', state.selfTestPid ? String(state.selfTestPid) : '-'],
      ]) : ''}
      <div class="actions">
        <button id="selftest-launch" ${launchDisabled}>启动游戏</button>
        <button id="selftest-close" ${actionDisabled}>关闭游戏</button>
        <button id="selftest-capture" ${actionDisabled}>截取一帧</button>
        <button data-self-action="move_center" ${actionDisabled}>移动到窗口中心</button>
        <button data-self-action="click_left" ${actionDisabled}>左键点击一次</button>
        <button data-self-action="tap_space" ${actionDisabled}>短按 Space</button>
        <button data-self-action="tap_esc" ${actionDisabled}>短按 Esc</button>
        <button data-self-action="release_all" ${actionDisabled}>释放全部输入</button>
      </div>
      <div class="capture-preview">
        ${
          state.selfTestPreviewUrl
            ? `<img src="${state.selfTestPreviewUrl}" alt="自检截图预览" /><span>${escapeHtml(state.selfTestPreviewLabel)}</span>`
            : '<span>截图预览会在“截取一帧”成功后显示。</span>'
        }
      </div>
      <p class="muted" aria-live="polite" aria-atomic="true">${escapeHtml(state.selfTestStatus || (canLaunch ? '已选择可操作游戏。' : '请选择可自检的原神发现项。'))}</p>
    `)}
  `;
}

function setSelfTestPreview(frame: SelfTestCapture): void {
  clearSelfTestPreview();
  const bytes = new Uint8Array(frame.jpeg);
  state.selfTestPreviewUrl = URL.createObjectURL(new Blob([bytes.buffer], { type: 'image/jpeg' }));
  state.selfTestPreviewLabel = `${frame.width}x${frame.height} / ${Math.round(frame.bytes / 1024)} KB`;
}

function clearSelfTestPreview(): void {
  if (state.selfTestPreviewUrl) {
    URL.revokeObjectURL(state.selfTestPreviewUrl);
  }
  state.selfTestPreviewUrl = '';
  state.selfTestPreviewLabel = '';
}

function panel(title: string, body: string): string {
  return `<section class="panel"><h2>${title}</h2>${body}</section>`;
}

function statCard(label: string, value: string, tone = ''): string {
  return `<section class="stat-card ${tone}"><span>${label}</span><strong>${escapeHtml(value)}</strong></section>`;
}

function rows(items: Array<[string, string]>): string {
  return `<div class="rows">${items.map(([key, value]) => `<div><span>${key}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}</div>`;
}

function wireForms(): void {
  document.querySelector('#start-runtime')?.addEventListener('click', () => runtimeAction('start_runtime'));
  document.querySelector('#restart-runtime')?.addEventListener('click', () => runtimeAction('restart_runtime'));
  document.querySelector('#stop-runtime')?.addEventListener('click', () => runtimeAction('stop_runtime'));
  document.querySelector('#refresh-logs')?.addEventListener('click', () => {
    state.logFilter = inputValue('log-filter');
    void refreshLogs();
  });
  document.querySelector('#scan-games')?.addEventListener('click', () => void scanGames());
  document.querySelector('#selftest-launch')?.addEventListener('click', () => void selfTestLaunch());
  document.querySelector('#selftest-close')?.addEventListener('click', () => void selfTestClose());
  document.querySelector('#selftest-capture')?.addEventListener('click', () => void selfTestCapture());
  document.querySelectorAll<HTMLButtonElement>('[data-self-action]').forEach((button) => {
    button.addEventListener('click', () => void selfTestInput(button.dataset.selfAction ?? ''));
  });
  document.querySelectorAll<HTMLButtonElement>('[data-game]').forEach((button) => {
    button.addEventListener('click', () => {
      state.selectedGameId = button.dataset.game ?? '';
      state.selfTestStatus = '';
      render();
    });
  });
  document.querySelector('#save-connection')?.addEventListener('click', () => {
    if (!state.config) return;
    state.config.hub.ws_url = inputValue('hub-url');
    state.config.hub.api_key = inputValue('api-key');
    state.config.agent.name = inputValue('agent-name');
    state.config.agent.log_level = inputValue('log-level');
    state.config.runtime.auto_update = checked('auto-update');
    state.config.runtime.auto_start = checked('auto-start');
    state.config.runtime.command_timeout_s = numberValue('command-timeout', 60);
    state.config.runtime.launch_allowlist = inputValue('allowlist')
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
    void saveConfig();
  });
  document.querySelector('#save-capture')?.addEventListener('click', () => {
    if (!state.config) return;
    state.config.capture.target_display = numberValue('target-display', 0);
    state.config.capture.fps = numberValue('fps', 30);
    state.config.capture.jpeg_quality = numberValue('jpeg-quality', 80);
    state.config.capture.encoder = inputValue('encoder');
    void saveConfig();
  });
}

function inputValue(id: string): string {
  return (document.getElementById(id) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null)?.value ?? '';
}

function checked(id: string): boolean {
  return (document.getElementById(id) as HTMLInputElement | null)?.checked ?? false;
}

function numberValue(id: string, fallback: number): number {
  const value = Number(inputValue(id));
  return Number.isFinite(value) ? value : fallback;
}

function formatSelfTestLaunchError(error: unknown): string {
  const message = String(error);
  if (message.includes('os error 740') || message.includes('请求的操作需要提升')) {
    return '启动失败：目标需要管理员权限（Windows error 740）。请关闭当前 Tauri GUI，右键以管理员身份运行 FairyPam Agent/Tauri GUI 后重试；如果出现 UAC，请手动确认。';
  }
  return `启动失败：${message}`;
}

function phaseTone(phase: string): string {
  if (phase === 'running') return 'green';
  if (phase === 'starting' || phase === 'stopping') return 'warn';
  if (phase === 'error') return 'red';
  return '';
}

function operatorPanel(config: AppConfig | null, dash: DashboardState | null): string {
  const pageMap: Record<Page, Array<[string, string]>> = {
    dashboard: [
      ['控制台', '本地运行面板'],
      ['服务', 'FairyPam Agent'],
      ['Runtime', state.runtime.label],
      ['Config', dash?.config_path ?? 'config.yaml'],
    ],
    runtime: [
      ['启动', state.runtime.can_start ? '可用' : '不可用'],
      ['停止', state.runtime.can_stop ? '可用' : '不可用'],
      ['重启', state.runtime.can_restart ? '可用' : '不可用'],
      ['状态', state.runtime.label],
    ],
    connection: [
      ['Hub URL', config?.hub.ws_url ?? '-'],
      ['API Key', config?.hub.api_key ? '***' : '未填写'],
      ['Agent', config?.agent.name ?? '-'],
      ['RuntimeConfig', `${config?.runtime.command_timeout_s ?? 60}s timeout`],
    ],
    capture: [
      ['Display', String(config?.capture.target_display ?? '-')],
      ['FPS', String(config?.capture.fps ?? '-')],
      ['JPEG', `${config?.capture.jpeg_quality ?? '-'}%`],
      ['Encoder', config?.capture.encoder ?? '-'],
    ],
    logs: [
      ['Reader', 'redacted tail'],
      ['Filter', state.logFilter || 'none'],
      ['Bytes', `${state.logs.length}`],
      ['Secret', 'masked in Rust'],
    ],
    selftest: [
      ['Scan', state.scanning ? 'running' : 'idle'],
      ['Found', `${state.games.length}`],
      ['Profile', selectedGame()?.self_test_target?.profile_id ?? '-'],
      ['Target', state.selfTestPid ? `PID ${state.selfTestPid}` : 'idle'],
    ],
  };

  return `
    <div class="operator-card">
      <div class="operator-visual"><span class="avatar"><i></i></span></div>
      <h2>Ops Stack</h2>
      <p>${operatorCopy()}</p>
      <div class="side-rows">
        ${pageMap[state.page].map(([key, value]) => `<div><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}
      </div>
      <div class="code-map"><span>本地</span><span>安全</span><span>运行</span></div>
    </div>
  `;
}

function selectedGame(): GameCandidate | undefined {
  return state.games.find((game) => game.discovery_id === state.selectedGameId);
}

function operatorCopy(): string {
  const copy: Record<Page, string> = {
    dashboard: '总览聚合本地 Agent 状态，不触发副作用。',
    runtime: '运行控制会请求 Agent 管理运行状态。',
    connection: '连接配置写入本地 config，API Key 只以掩码表达。',
    capture: '采集设置只保存参数，采集随 runtime 生命周期运行。',
    logs: '日志尾部由 Rust 读取并脱敏，前端只展示过滤结果。',
    selftest: '自检只对已发现的原神启用，操作结果由 Rust 返回。',
  };
  return copy[state.page];
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
}

function escapeAttr(value: string): string {
  return escapeHtml(value);
}

render();
void refreshAll();
