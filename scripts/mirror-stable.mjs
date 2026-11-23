import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import {
  expectedAssets,
  manifestUrl,
  origin,
  planRelease,
  policyDecision,
  publishedTagFor,  readPolicy,
  releaseNotes,
  repository,
  signer,
  sumsFor,
} from './stable-policy.mjs';

async function policyAt(url) {
  const response = await fetch(url, { redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(20000) });
  if (response.status === 404) return { missing: true };
  assert.equal(response.status, 200, 'Unable to check the stable rollout');
  const chunks = [];
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    assert.ok(bytes <= 65536, 'Update manifest is too large');
    chunks.push(chunk);
  }
  return { offer: readPolicy(JSON.parse(Buffer.concat(chunks).toString('utf8'))) };
}

function noTokens() {
  const env = { ...process.env };
  delete env.GH_TOKEN;
  delete env.GITHUB_TOKEN;
  return env;
}
async function authorization() {
  const heads = await Promise.all([manifestUrl, manifestUrl.replace(origin, 'https://vpn.tbcc.com')].map(policyAt));
  const decision = policyDecision(heads);
  if (decision?.source === 'catalog') {
    const output = execFileSync('python3', ['scripts/manual_catalog.py'], {
      encoding: 'utf8',
      timeout: 45000,
      env: noTokens(),
    });
    const c = JSON.parse(output);
    assert.ok(Number.isSafeInteger(c.code) && c.code >= 1 && c.code <= 2100000000);
    assert.match(c.arm64_sha256, /^[0-9a-f]{64}$/);
    const files = ['arm64-v8a', 'universal'].map((abi) => {
      const url = origin + '/downloads/android/stable/' + c.code + '/' + abi + '.apk';
      assert.equal(c.urls[abi], url);
      return {
        name: 'TBCC-VPN-' + abi + '.apk',
        abi,
        url,
        sha256: abi === 'arm64-v8a' ? c.arm64_sha256 : null,
        size: null,
      };
    });
    return { source: 'manual', code: c.code, arm64_sha256: c.arm64_sha256, files };
  }
  return decision;
}
function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 360000 });
}
export function releaseSnapshot(expectedTag, request = gh) {
  const endpoint = '/repos/' + repository + '/releases';
  const rows = JSON.parse(request(['api', '--paginate', '--slurp', endpoint + '?per_page=100'])).flat();
  const latest = JSON.parse(request(['api', endpoint + '/latest']));
  assert.ok(!latest.draft && !latest.prerelease && latest.tag_name, 'Invalid public latest release');
  // GitHub's paginated list can lag both draft creation and asset uploads.
  // Read our exact tag on every mutation plan; the policy still validates all
  // immutable metadata/assets and fences newer published releases in the list.
  let releases = [...rows.filter((r) => r.tag_name !== latest.tag_name), latest];
  if (expectedTag) {
    let exact;
    try { exact = JSON.parse(request(['api', endpoint + '/tags/' + encodeURIComponent(expectedTag)])); }
    catch (error) { if (!String(error.stderr).includes('HTTP 404')) throw error; }
    if (exact) {
      assert.equal(exact.tag_name, expectedTag, 'Exact release endpoint returned another tag');
      releases = [...releases.filter(r => r.tag_name !== expectedTag), exact];
    }
  }
  return { releases, latestTag: latest.tag_name };
}

async function requireApproval(approval, readApproval = authorization) {
  assert.deepEqual(await readApproval(), approval, 'Stable publication is no longer current');
}

const latestActions = {
  snapshot: releaseSnapshot,
  readApproval: authorization,
  markLatest: (tag) => gh(['release', 'edit', tag, '--repo', repository, '--latest']),
};

/** Bounded read-after-create retry; never retries a failed policy validation. */
export async function waitForDraft(plan, tag, wait = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  for (let attempt = 0; attempt < 10; attempt++) {
    const stage = plan();
    if (stage.action === 'unchanged' || stage.draft) return stage;
    assert.ok(attempt < 9, 'Created draft is not visible for ' + tag);
    await wait(1000);
  }
}

export async function verifyLatest(approval, tag, verifyOnly, actions = latestActions) {
  function currentTag() {
    const { releases, latestTag } = actions.snapshot(tag);
    assert.equal(publishedTagFor(approval, releases), tag, 'The approved APKs are no longer published');
    return latestTag;
  }
  if (currentTag() === tag) return;
  assert.ok(!verifyOnly, 'GitHub /releases/latest differs from approved ' + tag);
  await requireApproval(approval, actions.readApproval);
  if (currentTag() !== tag) actions.markLatest(tag);
  assert.equal(currentTag(), tag, 'GitHub /releases/latest still differs from approved ' + tag);
}

export async function fetchApk(dir, item, version, code) {
  const dest = path.join(dir, item.name);
  const response = await fetch(item.url, { redirect: 'error', signal: AbortSignal.timeout(420000) });
  assert.equal(response.status, 200, 'APK unavailable: ' + item.abi);
  const hash = createHash('sha256');
  let bytes = 0;
  const validate = new Transform({
    transform(chunk, _, done) {
      bytes += chunk.length;
      if (bytes > (item.size ?? 256 * 1024 * 1024)) return done(new Error('APK larger than signed size'));
      hash.update(chunk);
      done(null, chunk);
    },
  });
  await pipeline(Readable.fromWeb(response.body), validate, createWriteStream(dest, { flags: 'wx' }));
  const sha256 = hash.digest('hex');
  assert.ok(bytes > 0);
  if (item.size !== null) assert.equal(bytes, item.size, 'Downloaded APK size differs from signed size');
  if (item.sha256 !== null) assert.equal(sha256, item.sha256, 'Downloaded APK hash differs from published hash');
  const tools = path.join(process.env.ANDROID_HOME, 'build-tools', '36.0.0');
  await access(path.join(tools, 'apksigner'));
  const options = { env: noTokens(), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 90000 };
  const sig = execFileSync(path.join(tools, 'apksigner'), ['verify', '--print-certs', dest], options);
  assert.deepEqual(
    [...sig.matchAll(/^Signer #\d+ certificate SHA-256 digest: ([a-f0-9]{64})$/gm)].map((m) => m[1]),
    [signer],
  );
  const badging = execFileSync(path.join(tools, 'aapt'), ['dump', 'badging', dest], options);
  const pkg = badging.match(/^package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'/m);
  assert.deepEqual(pkg?.slice(1, 3), ['app.tbcc.vpn', String(code)], 'Unexpected APK identity');
  assert.match(pkg[3], /^[0-9]+\.[0-9]+\.[0-9]+$/);
  if (version) assert.equal(pkg[3], version, 'APK versionName mismatch');
  assert.match(badging, /^sdkVersion:'28'$/m);
  const native = badging.match(/^native-code:(.*)$/m)?.[1] ?? '';
  const abis = [...native.matchAll(/'([^']+)'/g)].map((m) => m[1]).sort();
  assert.deepEqual(
    abis,
    item.abi === 'universal' ? ['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'] : [item.abi],
    'Unexpected APK ABI',
  );
  return { version: pkg[3], file: { ...item, sha256, size: bytes } };
}

async function reconcile(verifyOnly) {
  const approval = await authorization();
  if (!approval) {
    console.log('No active 100% stable rollout. The current public release is retained.');
    return;
  }
  const tag = publishedTagFor(approval, releaseSnapshot().releases);
  if (tag) {
    await verifyLatest(approval, tag, verifyOnly);
    console.log('Current public stable release verified. Version code: ' + approval.code);
    return;
  }
  const dir = await mkdtemp(path.join(tmpdir(), 'tbcc-mirror-'));
  try {
    const verified = [];
    let version = approval.version;
    for (const item of approval.files) {
      const checked = await fetchApk(dir, item, version, approval.code);
      version = checked.version;
      verified.push(checked.file);
    }
    const selected = { source: approval.source, tag: 'v' + version, version, code: approval.code, notes: approval.notes, files: verified };
    await requireApproval(approval);
    const plan = () => planRelease(selected, releaseSnapshot(selected.tag).releases);
    const before = plan();
    if (before.action === 'unchanged') return await verifyLatest(approval, selected.tag, verifyOnly);
    if (verifyOnly) {
      console.log('Dry run: verified ' + selected.files.length + ' signed APKs for ' + selected.tag);
      return;
    }
    if (!before.draft) {
      const notes = path.join(dir, 'notes.md');
      await writeFile(notes, releaseNotes(selected));
      gh([
        'release',
        'create',
        selected.tag,
        '--repo',
        repository,
        '--draft',
        '--target',
        'main',
        '--title',
        'TBCC VPN for Android ' + selected.version,
        '--notes-file',
        notes,
      ]);
      await waitForDraft(plan, selected.tag);
    }
    for (const id of before.emptyAssetSlots) {
      await requireApproval(approval);
      if (plan().emptyAssetSlots?.includes(id))
        gh(['api', '--method', 'DELETE', '/repos/' + repository + '/releases/assets/' + id]);
    }
    await writeFile(path.join(dir, 'SHA256SUMS.txt'), sumsFor(before.files));
    for (const item of expectedAssets(before.files)) {
      await requireApproval(approval);
      const stage = plan();
      if (stage.action === 'unchanged') return await verifyLatest(approval, selected.tag, verifyOnly);
      assert.ok(stage.draft, 'Expected a draft for ' + selected.tag);
      if (!stage.draft.assets.some((a) => a.name === item.name && a.state === 'uploaded'))
        gh(['release', 'upload', selected.tag, path.join(dir, item.name), '--repo', repository]);
    }
    await requireApproval(approval);
    const final = plan();
    if (final.action === 'unchanged') return await verifyLatest(approval, selected.tag, verifyOnly);
    assert.ok(
      final.draft && !final.emptyAssetSlots.length && final.draft.assets.length === expectedAssets(before.files).length,
      'Incomplete draft',
    );
    gh(['release', 'edit', selected.tag, '--repo', repository, '--draft=false', '--latest']);
    await verifyLatest(approval, selected.tag, true);
    console.log('Published ' + selected.tag);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.ok(
    process.argv.slice(2).every((v) => v === '--publish'),
    'Unknown option',
  );
  await reconcile(!process.argv.includes('--publish'));
}
