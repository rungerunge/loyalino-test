'use strict';
// Offentlig transportkode. Appkilde, signering og output findes kun som AEAD-cipher.
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { open, seal, sha } = require('./ios-cipher-envelope.cjs');
const repo = 'rungerunge/loyalino-test';
const env = process.env;
function assert(ok) { if (!ok) throw Error('POLICY'); }
function buildEnvironment(source, extra = {}) {
  // Dependency scripts have no need for the GitHub transport credential or AES key.
  const allowed = ['PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'TMPDIR', 'LANG', 'LC_ALL', 'DEVELOPER_DIR', 'SDKROOT'];
  return { ...Object.fromEntries(allowed.filter(k => typeof source[k] === 'string').map(k => [k, source[k]])), ...extra };
}
function tarEntries(archive, scope = 'input') {
  assert(scope === 'input' || scope === 'output');
  assert(Buffer.isBuffer(archive) && archive.length >= 1024 && archive.length <= 512 * 1024 * 1024 && archive.length % 512 === 0);
  const text = b => { const nul = b.indexOf(0), raw = nul < 0 ? b : b.subarray(0, nul); if (nul >= 0) assert(b.subarray(nul).every(x => x === 0)); const value = raw.toString('utf8'); assert(Buffer.from(value).equals(raw)); return value; };
  const octal = b => { const value = b.toString('ascii').replace(/\0/g, '').trim(); assert(/^[0-7]{1,12}$/.test(value)); const n = Number.parseInt(value, 8); assert(Number.isSafeInteger(n)); return n; };
  const entries = [], seen = new Set(); let offset = 0;
  while (offset + 512 <= archive.length) {
    const h = archive.subarray(offset, offset + 512);
    if (h.every(x => x === 0)) { assert(archive.length - offset >= 1024 && archive.subarray(offset).every(x => x === 0)); break; }
    let checksum = 0; for (let i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? 32 : h[i];
    assert(checksum === octal(h.subarray(148, 156)) && text(h.subarray(257, 263)) === 'ustar');
    const prefix = text(h.subarray(345, 500)), name = text(h.subarray(0, 100));
    const rawPath = (prefix ? prefix + '/' : '') + name;
    const directory = h[156] === 53, regular = h[156] === 0 || h[156] === 48;
    assert((directory || regular) && text(h.subarray(157, 257)) === '');
    const relative = rawPath.replace(/^\.\//, '').replace(directory ? /\/$/ : /$^/, '');
    if ((relative === '.' || relative === '') && directory && scope === 'output') { assert(octal(h.subarray(124, 136)) === 0); offset += 512; continue; }
    assert(relative.length > 0 && relative.length <= 255 && !/[\\\p{Cc}]/u.test(relative) && !relative.startsWith('/') && relative.split('/').every(segment => segment && segment !== '.' && segment !== '..'));
    if (scope === 'input') assert(relative === 'source' && directory || relative === 'signing' && directory || relative.startsWith('source/') || relative.startsWith('signing/'));
    else assert(!directory && ['Okayscale.ipa', 'build-report.json', 'ipa-audit.json', 'cleanup.json', 'build.log', 'runner-report.json'].includes(relative));
    assert(!seen.has(relative)); seen.add(relative);
    const size = octal(h.subarray(124, 136)); assert(!directory || size === 0);
    const start = offset + 512, end = start + size; assert(end <= archive.length);
    entries.push({ relative, directory, executable: (octal(h.subarray(100, 108)) & 0o111) !== 0, bytes: archive.subarray(start, end) });
    assert(entries.length <= 50000); offset = start + Math.ceil(size / 512) * 512;
  }
  assert(offset <= archive.length - 1024 && entries.length > 0);
  if (scope === 'input') {
    const signing = entries.filter(e => e.relative.startsWith('signing/') && !e.directory).map(e => e.relative).sort();
    assert(signing.join(',') === ['signing/AuthKey.p8', 'signing/config.json', 'signing/password.txt', 'signing/profile.mobileprovision', 'signing/signing.p12'].sort().join(','));
    assert(entries.some(e => e.relative === 'source/mobile/scripts/ios-cipher-build.sh' && !e.directory));
  }
  const entryTypes = new Map(entries.map(e => [e.relative, e.directory]));
  for (const entry of entries) for (let parent = path.posix.dirname(entry.relative); parent !== '.'; parent = path.posix.dirname(parent)) assert(entryTypes.get(parent) !== false);
  return entries;
}
async function extractInput(archive, root, scope = 'input') {
  const entries = tarEntries(archive, scope);
  const rootStat = await fs.lstat(root);
  assert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && await fs.realpath(root) === path.resolve(root) && (await fs.readdir(root)).length === 0);
  for (const entry of entries) {
    const destination = path.resolve(root, entry.relative); assert(destination.startsWith(path.resolve(root) + path.sep));
    if (entry.directory) await fs.mkdir(destination, { recursive: true, mode: 0o700 });
    else { await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 }); await fs.writeFile(destination, entry.bytes, { flag: 'wx', mode: entry.executable ? 0o700 : 0o600 }); }
  }
}
async function api(route, method = 'GET', body, binary = false) {
  const res = await fetch(`https://api.github.com/repos/${repo}${route}`, { method, redirect: method === 'GET' ? 'follow' : 'error',
    headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}`, Accept: binary ? 'application/octet-stream' : 'application/vnd.github+json',
      'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28' }, body: body && JSON.stringify(body), signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw Error(`GITHUB_${res.status}`);
  return binary ? Buffer.from(await res.arrayBuffer()) : res.status === 204 ? null : res.json();
}
async function command(name, args, cwd, extra = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(name, args, { cwd, env: buildEnvironment(env, extra), stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = []; let bytes = 0;
    p.stdout.on('data', b => { bytes += b.length; if (bytes < 30000000) chunks.push(b); });
    p.stderr.on('data', b => { bytes += b.length; if (bytes < 30000000) chunks.push(b); });
    p.on('error', () => reject(Error('SPAWN')));
    p.on('close', code => resolve({ code, output: Buffer.concat(chunks).toString('utf8') }));
  });
}
async function main() {
  const context = { operation: env.OKAY_OPERATION, workflowSha: env.OKAY_WORKFLOW_SHA };
  assert(env.GITHUB_REPOSITORY === repo && env.GITHUB_ACTOR === 'rungerunge' && env.GITHUB_EVENT_NAME === 'workflow_dispatch' && env.GITHUB_RUN_ATTEMPT === '1');
  assert(env.GITHUB_SHA === context.workflowSha && env.GITHUB_WORKFLOW_SHA === context.workflowSha && env.GITHUB_REF === `refs/tags/okayscale-${context.operation}`);
  assert(!env.NODE_OPTIONS && !env.NODE_DEBUG && !env.NODE_DEBUG_NATIVE && /^[a-f0-9]{64}$/.test(env.OKAY_AES_KEY || ''));
  assert(env.RUNNER_OS === 'macOS' && env.RUNNER_ARCH === 'ARM64' && env.ImageOS === 'macos26');
  assert(Number.isFinite(Date.parse(env.OKAY_EXPIRES)) && Date.now() < Date.parse(env.OKAY_EXPIRES));
  const key = Buffer.from(env.OKAY_AES_KEY, 'hex');
  delete env.OKAY_AES_KEY;
  assert(path.isAbsolute(env.RUNNER_TEMP));
  const base = await fs.realpath(env.RUNNER_TEMP);
  const root = path.join(base, `okayscale-${context.operation}`);
  assert(path.dirname(root) === base);
  let uploaded = false, cleaned = false, created = false;
  try {
    await fs.mkdir(root, { mode: 0o700 });
    created = true;
    const release = await api(`/releases/${env.OKAY_RELEASE_ID}`);
    assert(release.tag_name === `okayscale-${context.operation}` && release.prerelease === true);
    assert(release.assets.some(a => a.id === Number(env.OKAY_INPUT_ASSET_ID) && a.name === 'input.okaycipher' && a.size === Number(env.OKAY_INPUT_BYTES)));
    // En claim gør genkørsel af samme operation umulig, også efter en usikker upload.
    assert(!release.assets.some(a => a.name === 'claimed.json'));
    const claim = Buffer.from(JSON.stringify({ runId: env.GITHUB_RUN_ID }));
    const claimRes = await fetch(`https://uploads.github.com/repos/${repo}/releases/${release.id}/assets?name=claimed.json`, {
      method: 'POST', headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}`, 'Content-Type': 'application/json' }, body: claim });
    assert(claimRes.ok);
    const cipher = await api(`/releases/assets/${env.OKAY_INPUT_ASSET_ID}`, 'GET', undefined, true);
    assert(cipher.length === Number(env.OKAY_INPUT_BYTES) && sha(cipher) === env.OKAY_INPUT_SHA);
    const plain = open(cipher, key, context, 'input');
    try { await extractInput(plain, root); } finally { plain.fill(0); }
    const config = JSON.parse(await fs.readFile(path.join(root, 'signing/config.json')));
    const forbidden = [key.toString('hex'), env.GITHUB_TOKEN, await fs.readFile(path.join(root, 'signing/AuthKey.p8'), 'utf8'),
      await fs.readFile(path.join(root, 'signing/password.txt'), 'utf8'),
      (await fs.readFile(path.join(root, 'signing/signing.p12'))).toString('base64'),
      (await fs.readFile(path.join(root, 'signing/profile.mobileprovision'))).toString('base64')].filter(Boolean);
    process.stdout.write('{"stage":"build","protected":true}\n');
    const result = await command('bash', ['source/mobile/scripts/ios-cipher-build.sh'], root, { OKAY_PRIVATE_ROOT: root, OKAY_RUN_ID: env.GITHUB_RUN_ID });
    let safeLog = result.output;
    for (const value of forbidden.sort((a,b) => b.length - a.length)) safeLog = safeLog.split(value).join('[redigeret]');
    safeLog = safeLog.replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '[redigeret PEM]');
    await fs.mkdir(path.join(root, 'return'), { recursive: true });
    await fs.writeFile(path.join(root, 'return/build.log'), safeLog, { mode: 0o600 });
    await fs.writeFile(path.join(root, 'return/runner-report.json'), JSON.stringify({ passed: result.code === 0, code: result.code,
      runId: env.GITHUB_RUN_ID, sourceSha: config.sourceSha, buildNumber: config.buildNumber, completedAt: new Date().toISOString() }));
    const packed = await command('tar', ['--format=ustar', '-cf', 'return.tar', '-C', 'return', '.'], root); assert(packed.code === 0);
    const output = seal(await fs.readFile(path.join(root, 'return.tar')), key, context, 'output');
    const response = await fetch(`https://uploads.github.com/repos/${repo}/releases/${release.id}/assets?name=output.okaycipher`, {
      method: 'POST', headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}`, 'Content-Type': 'application/octet-stream' }, body: output });
    assert(response.ok); uploaded = true;
    process.stdout.write(JSON.stringify({ stage: 'returned', passed: result.code === 0, outputSha256: sha(output), outputBytes: output.length }) + '\n');
    if (result.code !== 0) process.exitCode = 1;
  } finally {
    key.fill(0);
    // Byggescriptets trap sletter nøglering/profil. Den isolerede mappe fjernes også ved fejl.
    if (created) {
      const rootStat = await fs.lstat(root).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
      if (rootStat) { assert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && await fs.realpath(root) === root && path.dirname(root) === base); await fs.rm(root, { recursive: true, force: false }); }
    }
    cleaned = !(await fs.lstat(root).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; }));
    process.stdout.write(JSON.stringify({ stage: 'cleanup', privateDirectoryAbsent: cleaned, encryptedReturn: uploaded }) + '\n');
  }
}
module.exports = { buildEnvironment, tarEntries, extractInput, main };
if (require.main === module) main().catch(() => { process.stdout.write('{"protectedRunFailed":true}\n'); process.exitCode = 1; });
