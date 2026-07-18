import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (path) => readFileSync(resolve(root, path), 'utf8');
const capability = read('src-tauri/capabilities/default.json');
const config = read('src-tauri/tauri.conf.json');
const manifest = read('src-tauri/windows-app-manifest.xml');
const backend = read('src-tauri/src/lib.rs');
const frontend = read('src/api.ts');

const forbiddenPermissions = /(shell|plugin:fs|core:process|http:|registry|input)/i;
if (forbiddenPermissions.test(capability)) throw new Error('forbidden production permission');
if (!manifest.includes('level="asInvoker" uiAccess="false"')) throw new Error('manifest must be asInvoker/uiAccess=false');
if (manifest.includes('requireAdministrator') || manifest.includes('highestAvailable')) throw new Error('elevation manifest detected');
const csp = JSON.parse(config).app.security.csp.replace('http://ipc.localhost', '');
if (/https?:\/\//.test(csp)) throw new Error('remote CSP source detected');
if (backend.includes('fairypam_agent::') || backend.includes('std::process')) throw new Error('runtime/process ownership detected');
if (/invoke\s*\(\s*(method|name)/.test(frontend)) throw new Error('generic invoke bridge detected');

const commands = backend.match(/#\[tauri::command\]/g)?.length ?? 0;
if (commands !== 13) throw new Error(`expected 13 explicit commands, found ${commands}`);
console.log('production surface: explicit commands=13, asInvoker=true, forbidden permissions=0');
