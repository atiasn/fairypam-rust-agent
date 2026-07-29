import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const script = resolve(dirname(fileURLToPath(import.meta.url)), 'check-production-security.mjs');
const uiRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function fixture(capability = '"core:window:default"', protectPointer = true) {
  const root = mkdtempSync(join(tmpdir(), 'fairypam-ui-security-'));
  mkdirSync(join(root, 'src-tauri/capabilities'), { recursive: true });
  mkdirSync(join(root, 'src-tauri/src'), { recursive: true });
  writeFileSync(join(root, 'src-tauri/windows-app-manifest.xml'), '<requestedExecutionLevel level="requireAdministrator" uiAccess="false" />');
  writeFileSync(join(root, 'src-tauri/Cargo.toml'), 'fairypam-agent = { path = "agent" }');
  writeFileSync(join(root, 'src-tauri/capabilities/default.json'), `{ "permissions": [${capability}] }`);
  writeFileSync(join(root, 'src-tauri/tauri.conf.json'), JSON.stringify({ app: { security: { csp: "script-src 'self'" } } }));
  const commands = readFileSync(join(uiRoot, 'src-tauri/src/commands.rs'), 'utf8');
  writeFileSync(
    join(root, 'src-tauri/src/commands.rs'),
    protectPointer ? commands : commands.replace('for path in [&gui, &pointer]', 'for path in [&gui]'),
  );
  writeFileSync(
    join(root, 'src-tauri/src/app.rs'),
    readFileSync(join(uiRoot, 'src-tauri/src/app.rs'), 'utf8'),
  );
  writeFileSync(
    join(root, 'src-tauri/src/local_gateway.rs'),
    readFileSync(join(uiRoot, 'src-tauri/src/local_gateway.rs'), 'utf8'),
  );
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

test('production security scanner accepts the single-process fixture', () => {
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

test('production security scanner rejects an unguarded active-suite pointer', () => {
  const root = fixture('"core:window:default"', false);
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
