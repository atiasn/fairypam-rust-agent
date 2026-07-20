import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = process.env.FAIRYPAM_TAURI_UI_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (relativePath) => readFileSync(resolve(root, relativePath), 'utf8');
const installGuardPath = process.env.FAIRYPAM_INSTALL_GUARD_SOURCE;
const fail = (message) => {
  throw new Error(`production security check failed: ${message}`);
};

const manifest = read('src-tauri/windows-app-manifest.xml');
if (!manifest.includes('level="asInvoker"') || !manifest.includes('uiAccess="false"')) {
  fail('Windows manifest must use asInvoker with uiAccess=false');
}

const cargoToml = read('src-tauri/Cargo.toml');
if (!cargoToml.includes('fairypam-agent-local-client') || /^fairypam-agent\s*=/m.test(cargoToml)) {
  fail('UI must use the shared local client without depending on fairypam-agent');
}

const capability = read('src-tauri/capabilities/default.json');
for (const forbidden of ['core:default', 'shell:', 'fs:', 'http:', 'process:', 'registry', 'input']) {
  if (capability.includes(forbidden)) fail(`forbidden capability ${forbidden}`);
}

const config = JSON.parse(read('src-tauri/tauri.conf.json'));
const csp = config?.app?.security?.csp ?? '';
if (!csp.includes("script-src 'self'") || /script-src[^;]*https?:\/\//.test(csp)) {
  fail('CSP must keep scripts self-contained');
}

const commandSource = read('src-tauri/src/commands.rs');
const installGuardSource = installGuardPath
  ? readFileSync(resolve(installGuardPath), 'utf8')
  : read('../crates/fairypam-agent-local-client/src/windows_named_pipe.rs');
for (const forbidden of ['fn invoke', 'fn exec', 'fn spawn', 'fn read_file', 'serde_json::Value']) {
  if (commandSource.includes(forbidden)) fail(`forbidden generic command surface ${forbidden}`);
}

for (const required of [
  'for path in [&gui, &agent]',
  'verify_protected_program_files_path(path)',
]) {
  if (!commandSource.includes(required)) fail(`missing fixed UAC target guard ${required}`);
}
for (const required of [
  'protected_install_chain',
  'for component in relative',
  'path_is_writable(&current)?',
  'has_reparse_component(path)',
  'fs::canonicalize(path)',
  'SHGetKnownFolderPath',
  'FOLDERID_ProgramFiles',
  'FOLDERID_ProgramFilesX86',
]) {
  if (!installGuardSource.includes(required)) fail(`missing shared UAC install-chain guard ${required}`);
}
if (commandSource.includes('std::env::var("ProgramFiles")')) {
  fail('UAC trust root must not come from a user-controlled ProgramFiles environment variable');
}
const canonicalHelper = installGuardSource.indexOf('fn protected_install_path');
const reparseGuard = installGuardSource.indexOf('has_reparse_component(path)', canonicalHelper);
const canonicalize = installGuardSource.indexOf('fs::canonicalize(path)', canonicalHelper);
if (canonicalHelper < 0 || reparseGuard < canonicalHelper || canonicalize < reparseGuard) {
  fail('UAC trust chain must reject reparse points before canonicalizing a path');
}

console.log('production security check passed');
