import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';

export const repository = 'tbccvpn/TBCC-VPN-Downloads';
export const origin = 'https://updates.tbcc.com';
export const manifestUrl = origin + '/updates/android/v1/stable.json';
export const signer = '7a1d812882487be51df39d6027622ebe059877b4db336c75f2fde51d187c2f31';
const productionKey = createPublicKey({
  key: Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo+z+pu12rQu75kw99QjlCO5Oyw3YQWkEDx+Z1qE4HdbJ9YdWLi6ZtYhWFlsuesp/ou22cpcCYNX+4Yv1oHkWFg==',
    'base64',
  ),
  type: 'spki',
  format: 'der',
});
const abis = new Set(['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64', 'universal']);
const bootstrapTag = 'v0.4.5';
const codeMarker = /<!-- tbcc-stable-version-code: ([1-9][0-9]{0,9}) -->/;

export function readPolicy(envelope, now = Date.now(), publicKey = productionKey) {
  assert.deepEqual(Object.keys(envelope).sort(), ['keyId', 'payload', 'signature']);
  assert.equal(envelope.keyId, 'tbcc-updates-2026-1');
  const payload = Buffer.from(envelope.payload, 'base64');
  const signature = Buffer.from(envelope.signature, 'base64');
  assert.ok(payload.length > 0 && payload.length <= 32768 && signature.length === 64);
  const message = Buffer.concat([Buffer.from('TBCC-APP-UPDATE-v1\n'), payload]);
  assert.ok(
    verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature),
    'Invalid TBCC manifest signature',
  );
  const p = JSON.parse(payload.toString('utf8'));
  assert.equal(p.schema, 1);
  assert.equal(p.channel, 'stable');
  assert.equal(p.packageName, 'app.tbcc.vpn');
  assert.equal(p.certificateSha256, signer);
  assert.equal(p.minSdk, 28);
  assert.ok(Number.isSafeInteger(p.sequence) && p.sequence > 0);
  assert.ok(Number.isSafeInteger(p.issuedAt) && p.issuedAt > 0 && p.issuedAt <= now + 300000);
  assert.ok(
    Number.isSafeInteger(p.expiresAt) &&
      p.expiresAt > now &&
      p.expiresAt > p.issuedAt &&
      p.expiresAt - p.issuedAt <= 172800000,
  );
  assert.ok(Number.isSafeInteger(p.versionCode) && p.versionCode >= 1 && p.versionCode <= 2100000000);
  assert.match(p.versionName, /^[0-9]+\.[0-9]+\.[0-9]+$/);
  assert.equal(p.releaseId, 'stable-' + p.versionCode);
  assert.ok(['active', 'paused'].includes(p.status) && [5, 25, 100].includes(p.rolloutPercent));
  if (p.status !== 'active' || p.rolloutPercent !== 100) return null;
  assert.ok(Array.isArray(p.artifacts) && p.artifacts.length <= abis.size);
  const seen = new Set();
  const files = p.artifacts
    .map((a) => {
      assert.ok(abis.has(a.abi) && !seen.has(a.abi), 'Invalid or duplicate APK architecture');
      seen.add(a.abi);
      assert.ok(Number.isSafeInteger(a.bytes) && a.bytes > 0 && a.bytes <= 256 * 1024 * 1024);
      assert.match(a.sha256, /^[0-9a-f]{64}$/);
      const url = origin + '/downloads/android/stable/' + p.versionCode + '/' + a.abi + '.apk';
      assert.ok(Array.isArray(a.urls) && a.urls.includes(url), 'Missing official immutable URL');
      return { abi: a.abi, name: 'TBCC-VPN-' + a.abi + '.apk', url, size: a.bytes, sha256: a.sha256 };
    })
    .sort((a, b) => a.name.localeCompare(b.name, 'en'));
  assert.ok(seen.has('arm64-v8a') && seen.has('universal'), 'Both public download links must remain available');
  return { source: 'policy', tag: 'v' + p.versionName, version: p.versionName, code: p.versionCode, files };
}

export function sumsFor(files) {
  return files.map((a) => a.sha256 + '  ' + a.name + '\n').join('');
}

export function expectedAssets(files) {
  const sums = sumsFor(files);
  return [
    ...files,
    { name: 'SHA256SUMS.txt', size: Buffer.byteLength(sums), sha256: createHash('sha256').update(sums).digest('hex') },
  ];
}

function publishedVersion(release) {
  if (release.tag_name === bootstrapTag) return 14;
  const match = release.body?.match(codeMarker);
  assert.ok(match, 'Public release has no recognized version code: ' + release.tag_name);
  return Number(match[1]);
}

const originalFiles = [
  {
    name: 'TBCC-VPN-arm64-v8a.apk',
    size: 46029797,
    sha256: '13a5fa12f1cf3f8673e96eb1ec4397a46b81b2667a6c1a23eb88c0c16a6b6e5f',
  },
  {
    name: 'TBCC-VPN-universal.apk',
    size: 149086141,
    sha256: '2f66c4b6ba3f91d0808fb56c2f7d22d121c1482e34978c96a345e7758d93bed7',
  },
];
const manualNames = originalFiles.map((a) => a.name);

function recordedFiles(release) {
  if (release.tag_name === bootstrapTag) return originalFiles;
  const capture = release.body?.match(/<!-- tbcc-stable-files: ([^\n]+) -->/);
  assert.ok(capture, 'Missing public release checksums: ' + release.tag_name);
  const files = JSON.parse(capture[1]);
  assert.ok(Array.isArray(files) && files.length >= 2 && files.length <= 5);
  for (const f of files) {
    assert.ok([...abis].some((abi) => 'TBCC-VPN-' + abi + '.apk' === f.name));
    assert.match(f.sha256, /^[0-9a-f]{64}$/);
    assert.ok(Number.isSafeInteger(f.size) && f.size > 0 && f.size <= 256 * 1024 * 1024);
  }
  assert.ok(manualNames.every((name) => files.some((a) => a.name === name)));
  assert.equal(new Set(files.map((f) => f.name)).size, files.length);
  return files;
}
function manualPublication(release) {
  return release.tag_name === bootstrapTag || release.body?.includes('<!-- tbcc-stable-source: manual -->');
}
export function recordedMetadata(state) {
  const facts = state.files.map(({ name, size, sha256 }) => ({ name, size, sha256 }));
  return [
    '<!-- tbcc-stable-version-code: ' + state.code + ' -->',
    '<!-- tbcc-stable-source: ' + state.source + ' -->',
    '<!-- tbcc-stable-files: ' + JSON.stringify(facts) + ' -->',
  ].join('\n');
}

function validateAssets(release, files) {
  const pending = new Map(expectedAssets(files).map((f) => [f.name, f]));
  const emptyAssetSlots = [];
  for (const asset of release.assets) {
    const item = pending.get(asset.name);
    assert.ok(item, 'Unexpected asset name: ' + asset.name);
    if (
      release.draft &&
      asset.state === 'starter' &&
      asset.size === 0 &&
      !asset.digest &&
      Number.isSafeInteger(asset.id)
    ) {
      emptyAssetSlots.push(asset.id);
    } else {
      assert.ok(
        asset.state === 'uploaded' && asset.digest === 'sha256:' + item.sha256 && asset.size === item.size,
        'Mismatching release asset: ' + asset.name,
      );
    }
    pending.delete(asset.name);
  }
  if (!release.draft) assert.equal(pending.size, 0, 'Published release missing a verified asset');
  return emptyAssetSlots;
}

function published(releases) {
  const visible = releases.filter((r) => !r.draft && !r.prerelease);
  assert.ok(
    visible.some((r) => r.tag_name === bootstrapTag),
    'Missing public bootstrap release',
  );
  return visible;
}

export function manualNeeded(catalog, releases) {
  const visible = published(releases);
  const matched = visible.filter((r) => publishedVersion(r) === catalog.code);
  if (matched.length) {
    assert.equal(matched.length, 1, 'Ambiguous public versionCode');
    const files = recordedFiles(matched[0]);
    assert.equal(
      files.find((a) => a.name === manualNames[0]).sha256,
      catalog.arm64_sha256,
      'Official ARM64 checksum changed',
    );
    validateAssets(matched[0], files);
    return false;
  }
  assert.ok(catalog.code > Math.max(...visible.map(publishedVersion)), 'Refusing to publish an older manual release');
  return true;
}

export function planRelease(state, releases) {
  const visible = published(releases);
  const existing = releases.find((r) => r.tag_name === state.tag);
  let emptyAssetSlots = [];
  let files = state.files;
  if (existing) {
    assert.ok(!existing.prerelease && publishedVersion(existing) === state.code, 'Tag and versionCode disagree');
    if (existing.draft)
      assert.ok(existing.body.includes('<!-- tbcc-stable-version-code: ' + state.code + ' -->'), 'Unrecognized draft');
    files = manualPublication(existing) ? state.files.filter((f) => manualNames.includes(f.name)) : state.files;
    const facts = files.map(({ name, size, sha256 }) => ({ name, size, sha256 }));
    assert.deepEqual(recordedFiles(existing), facts, 'Existing tag/metadata differs from approved APKs');
    emptyAssetSlots = validateAssets(existing, files);
    if (!existing.draft) return { action: 'unchanged' };
  }
  assert.ok(
    state.code > Math.max(...visible.map(publishedVersion)),
    'Refusing to replace a published versionCode or republish an older release',
  );
  return { action: 'publish', draft: existing, emptyAssetSlots, files };
}

export function releaseNotes(state) {
  const url = 'https://github.com/' + repository + '/releases/';
  const asset = url + 'download/' + state.tag + '/';
  return (
    [
      'TBCC VPN for Android **' + state.version + '** · version code **' + state.code + '** · Android **9+**.',
      '[GitHub · This release / Этот выпуск / 此版本](' + url + 'tag/' + state.tag + ')',
      '[TBCC VPN · Installation / Установка / 安装](https://vpn.tbcc.com/setup/tbcc)',
      '[Android 64 位 · ARM64 · Для большинства телефонов](' + asset + 'TBCC-VPN-arm64-v8a.apk)',
      '[通用 APK · Universal APK · Универсальный APK](' + asset + 'TBCC-VPN-universal.apk)',
      '[SHA-256](' + asset + 'SHA256SUMS.txt)',
      recordedMetadata(state),
    ].join('\n\n') + '\n'
  );
}

export function policyDecision(heads) {
  assert.equal(heads.length, 2);
  if (heads.every((h) => h.missing)) return { source: 'catalog' };
  if (heads.some((h) => h.missing || !h.offer)) return null;
  assert.deepEqual(heads[0].offer, heads[1].offer, 'TBCC origins disagree about stable rollout');
  return heads[0].offer;
}
