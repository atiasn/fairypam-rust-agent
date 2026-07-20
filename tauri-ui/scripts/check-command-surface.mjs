import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (relativePath) => readFileSync(resolve(root, relativePath), 'utf8');
const fail = (message) => {
  throw new Error(`command surface check failed: ${message}`);
};
const commandNames = [...read('src-tauri/src/command_surface.rs').matchAll(/"([a-z_]+)"/g)].map((match) => match[1]);
const app = read('src-tauri/src/app.rs');
const capability = read('src-tauri/capabilities/default.json');
const api = read('src/lib/agentApi.ts');

for (const command of commandNames) {
  if (!app.includes(`commands::${command}`)) fail(`handler missing ${command}`);
  if (!capability.includes(`allow-${command.replaceAll('_', '-')}`)) fail(`capability missing ${command}`);
  if (!api.includes(`'${command}'`)) fail(`frontend API missing ${command}`);
}

if (/(?:invoke|method|payload)\s*[:=]/.test(api)) fail('dynamic invoke bridge detected');
for (const file of readdirSync(resolve(root, 'dist/assets'))) {
  if (readFileSync(resolve(root, 'dist/assets', file), 'utf8').includes('dev_')) {
    fail(`production bundle contains dev marker: ${file}`);
  }
}

console.log('command surface check passed');
