import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = process.env.FAIRYPAM_TAURI_UI_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (relativePath) => readFileSync(resolve(root, relativePath), 'utf8');
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
for (const forbidden of ['fn invoke', 'fn exec', 'fn spawn', 'fn read_file', 'serde_json::Value']) {
  if (commandSource.includes(forbidden)) fail(`forbidden generic command surface ${forbidden}`);
}

console.log('production security check passed');
