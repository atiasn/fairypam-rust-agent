import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const [endpoint, outputDirectory] = process.argv.slice(2);
if (!endpoint || !outputDirectory) {
  throw new Error('usage: write-live-test-bootstrap.mjs <https-base-url> <output-directory>');
}

const url = new URL(endpoint);
const canonical = url.pathname === '/' ? url.origin : url.toString();
if (
  url.protocol !== 'https:'
  || url.username
  || url.password
  || url.search
  || url.hash
  || canonical !== endpoint
) {
  throw new Error('live-test enrollment base URL must be canonical HTTPS without credentials, query, or fragment');
}

const document = JSON.stringify({
  enrollment_base_url: endpoint,
  schema_version: 1,
});
const digest = createHash('sha256').update(document, 'utf8').digest();
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const signature = sign(null, digest, privateKey);
if (!verify(null, digest, publicKey, signature)) {
  throw new Error('generated bootstrap signature failed self-verification');
}

const publicJwk = publicKey.export({ format: 'jwk' });
if (typeof publicJwk.x !== 'string') {
  throw new Error('generated Ed25519 public key is missing');
}
const publicKeyHex = Buffer.from(publicJwk.x, 'base64url').toString('hex');
if (!/^[0-9a-f]{64}$/.test(publicKeyHex) || signature.length !== 64) {
  throw new Error('generated Ed25519 key material is invalid');
}

const output = resolve(outputDirectory);
mkdirSync(output, { recursive: true });
writeFileSync(resolve(output, 'agent-bootstrap.json'), `${document}\n`, { encoding: 'utf8', flag: 'wx' });
writeFileSync(resolve(output, 'agent-bootstrap.json.sig'), `${signature.toString('hex')}\n`, {
  encoding: 'ascii',
  flag: 'wx',
});
process.stdout.write(publicKeyHex);
