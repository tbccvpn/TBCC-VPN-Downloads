import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import {
  expectedAssets,
  manualNeeded,
  origin,
  planRelease,
  policyDecision,
  readPolicy,
  recordedMetadata,
  releaseNotes,
  signer,
} from '../scripts/stable-policy.mjs';

const now = 1800000000000;
const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
function makePolicy(code = 15, version = '0.4.6') {
  return {
    schema: 1,
    packageName: 'app.tbcc.vpn',
    channel: 'stable',
    releaseId: 'stable-' + code,
    versionCode: code,
    versionName: version,
    certificateSha256: signer,
    minSdk: 28,
    sequence: 1,
    issuedAt: now - 1000,
    expiresAt: now + 100000,
    status: 'active',
    rolloutPercent: 100,
    artifacts: ['arm64-v8a', 'universal', 'x86'].map((abi) => ({
      abi,
      bytes: 10,
      sha256: 'a'.repeat(64),
      urls: [origin + '/downloads/android/stable/' + code + '/' + abi + '.apk'],
    })),
  };
}
function envelope(p) {
  const bytes = Buffer.from(JSON.stringify(p));
  const signature = sign('sha256', Buffer.concat([Buffer.from('TBCC-APP-UPDATE-v1\n'), bytes]), {
    key: keys.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return { keyId: 'tbcc-updates-2026-1', payload: bytes.toString('base64'), signature: signature.toString('base64') };
}
function read(p) {
  return readPolicy(envelope(p), now, keys.publicKey);
}
function assets(items) {
  return expectedAssets(items).map((f) => ({
    name: f.name,
    size: f.size,
    state: 'uploaded',
    digest: 'sha256:' + f.sha256,
  }));
}
const bootstrap = { tag_name: 'v0.4.5', draft: false, prerelease: false, body: '', assets: [] };

test('honors complete stable rollout and mirrors exactly the signed architectures', () => {
  const p = read(makePolicy());
  assert.deepEqual(
    p.files.map((f) => f.abi),
    ['arm64-v8a', 'universal', 'x86'],
  );
  assert.equal(p.tag, 'v0.4.6');
  assert.equal(planRelease(p, [bootstrap]).action, 'publish');
  for (const rolloutPercent of [5, 25]) assert.equal(read({ ...makePolicy(), rolloutPercent }), null);
  assert.equal(read({ ...makePolicy(), status: 'paused' }), null);
});
test('rejects stale, modified, development, path mismatch and incomplete offers', () => {
  const bad = envelope(makePolicy());
  bad.payload = envelope({ ...makePolicy(), versionCode: 52 }).payload;
  assert.throws(() => readPolicy(bad, now, keys.publicKey));
  for (const change of [
    { expiresAt: now },
    { issuedAt: now + 600000 },
    { channel: 'development' },
    { certificateSha256: '0'.repeat(64) },
    { versionName: '../oops' },
    { releaseId: 'development-15' },
  ]) {
    assert.throws(() => read({ ...makePolicy(), ...change }));
  }
  const wrong = makePolicy();
  wrong.artifacts[0].urls = [origin + '/downloads/android/stable/16/arm64-v8a.apk'];
  assert.throws(() => read(wrong));
  assert.throws(() => read({ ...makePolicy(), artifacts: makePolicy().artifacts.slice(1) }));
  assert.throws(() => read({ ...makePolicy(), artifacts: [...makePolicy().artifacts, makePolicy().artifacts[0]] }));
});
test('preserves manually published bootstrap; fails closed on missing or conflicting active assets', () => {
  const s = read(makePolicy(14, '0.4.5'));
  Object.assign(
    s.files.find((a) => a.abi === 'arm64-v8a'),
    { size: 46029797, sha256: '13a5fa12f1cf3f8673e96eb1ec4397a46b81b2667a6c1a23eb88c0c16a6b6e5f' },
  );
  Object.assign(
    s.files.find((a) => a.abi === 'universal'),
    { size: 149086141, sha256: '2f66c4b6ba3f91d0808fb56c2f7d22d121c1482e34978c96a345e7758d93bed7' },
  );
  const existing = { ...bootstrap, assets: assets(s.files.filter((f) => f.abi !== 'x86')) };
  assert.equal(planRelease(s, [existing]).action, 'unchanged');
  assert.throws(() => planRelease(s, [{ ...existing, assets: existing.assets.slice(0, 1) }]));
  assert.throws(() =>
    planRelease(s, [
      { ...existing, assets: [{ ...existing.assets[0], digest: 'mismatch' }, ...existing.assets.slice(1)] },
    ]),
  );
});
test('rejects code reuse or downgrade across already published future tags', () => {
  const future = {
    tag_name: 'v0.5.0',
    body: '<!-- tbcc-stable-version-code: 20 -->',
    assets: [],
    draft: false,
    prerelease: false,
  };
  for (const code of [14, 17, 20])
    assert.throws(() => planRelease(read(makePolicy(code, '0.4.9')), [bootstrap, future]));
  assert.throws(() => planRelease(read(makePolicy(21, '0.5.0')), [bootstrap, future]));
  assert.equal(planRelease(read(makePolicy(21, '0.5.1')), [bootstrap, future]).action, 'publish');
});
test('retries only a recognized partial draft and retains every uploaded immutable file', () => {
  const s = read(makePolicy()),
    uploaded = assets(s.files);
  const draft = { tag_name: s.tag, draft: true, body: recordedMetadata(s), assets: [uploaded[0]] };
  assert.equal(planRelease(s, [bootstrap, draft]).draft, draft);
  const failed = { ...draft, assets: [{ ...uploaded[0], id: 99, state: 'starter', size: 0, digest: null }] };
  assert.deepEqual(planRelease(s, [bootstrap, failed]).emptyAssetSlots, [99]);
  assert.throws(() => planRelease(s, [bootstrap, { ...draft, body: 'other draft' }]));
  assert.throws(() => planRelease(s, [bootstrap, { ...draft, assets: [{ ...uploaded[0], size: 1 }] }]));
  assert.equal(planRelease(s, [bootstrap, { ...draft, draft: false, assets: uploaded }]).action, 'unchanged');
});

test('allows the public site catalogue only when both authoritative policies are absent', () => {
  const absent = { missing: true },
    partial = { offer: null },
    full = { offer: read(makePolicy()) };
  assert.equal(policyDecision([absent, absent]).source, 'catalog');
  for (const other of [partial, full]) assert.equal(policyDecision([absent, other]), null);
  assert.equal(policyDecision([partial, full]), null);
  assert.equal(policyDecision([full, full]), full.offer);
  assert.throws(() => policyDecision([full, { offer: read(makePolicy(16, '0.4.7')) }]));
});
test('manual publication checks both SHA receipts and only keeps its two website APKs when full policy follows', () => {
  const p = read(makePolicy());
  const manual = { ...p, source: 'manual', files: p.files.filter((f) => f.abi !== 'x86') };
  const published = { tag_name: p.tag, draft: false, body: recordedMetadata(manual), assets: assets(manual.files) };
  const request = { code: 15, arm64_sha256: manual.files[0].sha256 };
  assert.equal(manualNeeded(request, [bootstrap]), true);
  assert.equal(manualNeeded(request, [bootstrap, published]), false);
  assert.equal(planRelease(p, [bootstrap, published]).action, 'unchanged');
  assert.throws(() => manualNeeded({ ...request, arm64_sha256: 'x' }, [bootstrap, published]));
  assert.throws(() => manualNeeded(request, [bootstrap, { ...published, assets: published.assets.slice(0, 1) }]));
  assert.throws(() => manualNeeded({ ...request, code: 13 }, [bootstrap, published]));
  assert.throws(() =>
    planRelease({ ...p, files: p.files.map((f) => (f.abi === 'universal' ? { ...f, sha256: '0'.repeat(64) } : f)) }, [
      bootstrap,
      published,
    ]),
  );
});
test('both release paths publish the exact GitHub permalink and official installation page', () => {
  for (const source of ['manual', 'policy']) {
    const s = { ...read(makePolicy()), source };
    const notes = releaseNotes(s);
    assert.ok(notes.includes('(https://github.com/tbccvpn/TBCC-VPN-Downloads/releases/tag/v0.4.6)'));
    assert.ok(notes.includes('(https://vpn.tbcc.com/setup/tbcc)'));
    for (const abi of ['arm64-v8a', 'universal'])
      assert.ok(notes.includes('/releases/download/v0.4.6/TBCC-VPN-' + abi + '.apk)'));
    assert.ok(notes.includes('<!-- tbcc-stable-source: ' + source + ' -->'));
  }
});

test('release template fills the tagged links and displays provided changelog text in all three languages', () => {
  const translations = {
    'zh-Hans': '改进了连接。', en: 'Reconnects after a network change.', ru: 'Обновили выбор сети.',
  };
  const state = read({ ...makePolicy(), notes: translations });
  const body = releaseNotes(state);
  for (const line of Object.values(translations)) assert.ok(body.includes(line));
  assert.ok(body.includes('What’s new'));
  assert.ok(body.includes('version code **15**'));
  assert.ok(body.includes('/download/v0.4.6/SHA256SUMS.txt)'));
  assert.doesNotMatch(body, /\{\{(?:version|changes)/);
  const manual = releaseNotes({ ...state, source: 'manual', notes: undefined });
  assert.doesNotMatch(manual, /What’s new|\{\{/);
  assert.ok(manual.includes('https://vpn.tbcc.com/setup/tbcc'));
});
