import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const script = resolve(dirname(fileURLToPath(import.meta.url)), 'check-production-security.mjs');

function fixture(capability = '"core:window:default"') {
  const root = mkdtempSync(join(tmpdir(), 'fairypam-ui-security-'));
  mkdirSync(join(root, 'src-tauri/capabilities'), { recursive: true });
  mkdirSync(join(root, 'src-tauri/src'), { recursive: true });
  writeFileSync(join(root, 'src-tauri/windows-app-manifest.xml'), '<requestedExecutionLevel level="asInvoker" uiAccess="false" />');
  writeFileSync(join(root, 'src-tauri/Cargo.toml'), 'fairypam-agent-local-client = { path = "client" }');
  writeFileSync(join(root, 'src-tauri/capabilities/default.json'), `{ "permissions": [${capability}] }`);
  writeFileSync(join(root, 'src-tauri/tauri.conf.json'), JSON.stringify({ app: { security: { csp: "script-src 'self'" } } }));
  writeFileSync(join(root, 'src-tauri/src/commands.rs'), `
#[tauri::command] fn get_overview() {}
fn fixed_agent_path() {
  for path in [&gui, &agent] { verify_protected_program_files_path(path); }
}
`);
  writeFileSync(join(root, 'install-guard.rs'), `
fn protected_install_path(path: &Path) {
  has_reparse_component(path);
  fs::canonicalize(path);
}
fn protected_install_chain() {
  for component in relative { path_is_writable(&current)?; }
}
// SHGetKnownFolderPath FOLDERID_ProgramFiles FOLDERID_ProgramFilesX86
`);
  return root;
}

test('production security scanner accepts the least-privilege fixture', () => {
  const root = fixture();
  try {
    execFileSync(process.execPath, [script], {
      env: {
        ...process.env,
        FAIRYPAM_TAURI_UI_ROOT: root,
        FAIRYPAM_INSTALL_GUARD_SOURCE: join(root, 'install-guard.rs'),
      },
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('production security scanner rejects a broad core capability', () => {
  const root = fixture('"core:default"');
  try {
    assert.throws(() => execFileSync(process.execPath, [script], {
      env: {
        ...process.env,
        FAIRYPAM_TAURI_UI_ROOT: root,
        FAIRYPAM_INSTALL_GUARD_SOURCE: join(root, 'install-guard.rs'),
      },
    }));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
