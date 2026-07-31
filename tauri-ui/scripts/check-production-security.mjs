import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = process.env.FAIRYPAM_TAURI_UI_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), '..');
const agentRoot = process.env.FAIRYPAM_AGENT_ROOT ?? resolve(root, '..');
const read = (relativePath) => readFileSync(resolve(root, relativePath), 'utf8');
const readAgent = (relativePath) => readFileSync(resolve(agentRoot, relativePath), 'utf8');
const fail = (message) => {
  throw new Error(`production security check failed: ${message}`);
};

const manifest = read('src-tauri/windows-app-manifest.xml');
if (!manifest.includes('level="requireAdministrator"') || !manifest.includes('uiAccess="false"')) {
  fail('Windows manifest must requireAdministrator with uiAccess=false');
}

const cargoToml = read('src-tauri/Cargo.toml');
if (!/^fairypam-agent\s*=/m.test(cargoToml)) {
  fail('Tauri host must link the unique in-process Agent core');
}

const capability = read('src-tauri/capabilities/default.json');
for (const forbidden of ['core:default', 'shell:', 'fs:', 'http:', 'process:', 'registry:', 'input:']) {
  if (capability.includes(forbidden)) fail(`forbidden capability ${forbidden}`);
}

const config = JSON.parse(read('src-tauri/tauri.conf.json'));
const csp = config?.app?.security?.csp ?? '';
if (!csp.includes("script-src 'self'") || /script-src[^;]*https?:\/\//.test(csp)) {
  fail('CSP must keep scripts self-contained');
}
if (JSON.stringify(config).includes('fairypam-agent.exe')) {
  fail('Tauri bundle must not contain a sibling Agent executable');
}

const commands = read('src-tauri/src/commands.rs');
const gateway = read('src-tauri/src/local_gateway.rs');
const app = read('src-tauri/src/app.rs');
for (const forbidden of [
  'fn invoke',
  'fn exec',
  'fn spawn',
  'fn read_file',
  'ShellExecuteExW',
  'restart_local_agent',
  'repair_agent_tasks',
  'WindowsNamedPipeClientTransport',
]) {
  if (commands.includes(forbidden) || gateway.includes(forbidden)) {
    fail(`forbidden renderer bridge ${forbidden}`);
  }
}

for (const required of [
  'runtime::start_embedded',
  'ProductionGateway::new(runtime)',
  'app.path().app_local_data_dir()?.join("webview")',
  'let webview_data_guard = pin_webview_data_root(&webview_data_root)?',
  'FILE_FLAG_OPEN_REPARSE_POINT',
  'FILE_FLAG_BACKUP_SEMANTICS',
  'FILE_SHARE_READ | FILE_SHARE_WRITE',
  'drop(webview_data_guard)',
  '.data_directory(webview_data_root)',
  '.incognito(true)',
  '.devtools(cfg!(debug_assertions))',
  '.additional_browser_args(WEBVIEW_BROWSER_ARGS)',
  '.on_navigation(allows_application_navigation)',
  'NewWindowResponse::Deny',
  'embedded-runtime-failed',
  'shutdown_local_agent_for_exit',
  'clear_all_browsing_data()',
  'window.destroy()',
]) {
  if (!app.includes(required)) fail(`missing single-process safety boundary ${required}`);
}
if (app.indexOf('.build()?;') > app.indexOf('drop(webview_data_guard)')) {
  fail('the pinned UDF guard must cover Tauri WebviewWindowBuilder::build');
}
if (app.includes('std::fs::create_dir_all')) {
  fail('the elevated host must not create the ordinary-user UDF');
}
if (app.includes('ImpersonateLoggedOnUser') || app.includes('DuplicateTokenEx')) {
  fail('the elevated host must not impersonate a linked token');
}
for (const required of [
  'for path in [&gui, &pointer]',
  'verify_protected_program_files_path(path)',
  'resolve_active_suite(install_root)',
]) {
  if (!commands.includes(required)) fail(`missing active-suite guard ${required}`);
}
if (!gateway.includes('EmbeddedRuntimeHandle') || !gateway.includes('runtime.execute(&command)')) {
  fail('Tauri Gateway must call the embedded runtime directly');
}

const transport = readAgent('crates/fairypam-agent-transport/src/tls.rs');
const transportManifest = readAgent('crates/fairypam-agent-transport/Cargo.toml');
const transportLocks = `${readAgent('Cargo.lock')}\n${read('src-tauri/Cargo.lock')}`;
for (const forbidden of ['CngMachine', 'rustls-cng', 'rustls_cng', 'Microsoft Software KSP']) {
  if (transport.includes(forbidden) || transportManifest.includes(forbidden) || transportLocks.includes(forbidden)) {
    fail(`obsolete transport identity path ${forbidden}`);
  }
}
if (!transport.includes('identity_key_pem')) fail('transport must use the protected PEM identity');

const windowsTarget = readAgent('crates/fairypam-agent-windows/src/window.rs');
for (const required of [
  'fn revalidate_or_focus_target(',
  'Duration::from_secs(5)',
  'api.check_environment()?',
  'api.focus_target(&current.identity, true)',
  'Duration::from_millis(200)',
]) {
  if (!windowsTarget.includes(required)) fail(`missing shared foreground recovery ${required}`);
}
if (windowsTarget.includes('click_target_point')) fail('foreground recovery must not click');
const execution = readAgent('bins/fairypam-agent/src/execution.rs');
if ((execution.match(/self\.focus_task_input_target\(binding\)\?/g) ?? []).length !== 2
    || (execution.match(/self\.validate_task_input_session\(session\)\?/g) ?? []).length !== 2
    || !execution.includes('self.targets.focus(binding).map_err(|error|')
    || !execution.includes('let release_error = self.release_task_input().err();')) {
  fail('capture and input must share the foreground recovery boundary');
}

console.log('production security check passed');
