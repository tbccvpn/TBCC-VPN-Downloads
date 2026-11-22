import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';

export const repository = 'tbccvpn/TBCC-VPN-Downloads';
export const channels = ['stable', 'development'];
export const origins = ['https://updates.tbcc.com', 'https://vpn.tbcc.com'];
const certificates = {
  stable: '7a1d812882487be51df39d6027622ebe059877b4db336c75f2fde51d187c2f31',
  development: '722bbff68ff080d922471919f80cb8a79ff71263692218a27ac3fd8beba4211a',
};
export const publicKey = createPublicKey({ format: 'der', type: 'spki', key: Buffer.from(
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo+z+pu12rQu75kw99QjlCO5Oyw3YQWkEDx+Z1qE4HdbJ9YdWLi6ZtYhWFlsuesp/ou22cpcCYNX+4Yv1oHkWFg==', 'base64') });
const hash = /^[a-f0-9]{64}$/;
const abis = new Set(['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64', 'universal']);
function base64(value, limit) {
  assert.ok(typeof value === 'string' && value.length <= limit * 2 && /^[A-Za-z0-9+/]*={0,2}$/.test(value));
  const bytes = Buffer.from(value, 'base64');
  assert.ok(bytes.length > 0 && bytes.length <= limit && bytes.toString('base64') === value);
  return bytes;
}
export function readEnvelope(raw, channel, { now = Date.now(), key = publicKey, allowExpired = false } = {}) {
  assert.ok(channels.includes(channel));
  assert.ok(Buffer.byteLength(raw) > 0 && Buffer.byteLength(raw) <= 65536);
  const e = JSON.parse(raw);
  assert.deepEqual(Object.keys(e).sort(), ['keyId', 'payload', 'signature']);
  assert.equal(e.keyId, 'tbcc-updates-2026-1');
  const payload = base64(e.payload, 32768), signature = base64(e.signature, 64);
  assert.equal(signature.length, 64);
  assert.ok(verify('sha256', Buffer.concat([Buffer.from('TBCC-APP-UPDATE-v1\n'), payload]),
    { key, dsaEncoding: 'ieee-p1363' }, signature), 'Invalid catalog signature');
  const p = JSON.parse(payload.toString('utf8'));
  assert.equal(p.schema, 1); assert.equal(p.channel, channel); assert.equal(p.packageName, 'app.tbcc.vpn');
  assert.equal(p.certificateSha256, certificates[channel]); assert.equal(p.minSdk, 28);
  assert.ok(Number.isSafeInteger(p.sequence) && p.sequence > 0);
  assert.ok(Number.isSafeInteger(p.issuedAt) && p.issuedAt > 0 && p.issuedAt <= now + 300000);
  assert.ok(Number.isSafeInteger(p.expiresAt) && p.expiresAt > p.issuedAt && p.expiresAt - p.issuedAt <= 172800000);
  assert.ok(allowExpired || p.expiresAt > now, 'Expired catalog');
  assert.ok(Number.isSafeInteger(p.versionCode) && p.versionCode >= 1 && p.versionCode <= 2100000000);
  assert.match(p.versionName, /^[a-zA-Z0-9._-]{1,50}$/); assert.equal(p.releaseId, channel + '-' + p.versionCode);
  assert.ok(['active', 'paused'].includes(p.status) && Number.isSafeInteger(p.rolloutPercent) && p.rolloutPercent >= 0 && p.rolloutPercent <= 100);
  assert.match(p.rolloutSalt, /^[a-zA-Z0-9_-]{8,80}$/);
  assert.ok(Array.isArray(p.artifacts) && p.artifacts.length >= 1 && p.artifacts.length <= 5);
  const seen = new Set();
  for (const a of p.artifacts) {
    assert.ok(abis.has(a.abi) && !seen.has(a.abi)); seen.add(a.abi);
    assert.ok(Number.isSafeInteger(a.bytes) && a.bytes > 0 && a.bytes <= 256 * 1024 * 1024); assert.match(a.sha256, hash);
    assert.ok(Array.isArray(a.urls) && a.urls.length >= 1 && a.urls.length <= 4 && new Set(a.urls).size === a.urls.length);
    for (const address of a.urls) {
      const u = new URL(address);
      assert.ok(origins.includes(u.origin) && address === u.origin + '/downloads/android/' + channel + '/' + p.versionCode + '/' + a.abi + '.apk');
    }
  }
  assert.ok(p.notes && typeof p.notes === 'object' && !Array.isArray(p.notes));
  assert.ok(Object.entries(p.notes).every(([k,v]) => ['ru','en','zh-Hans'].includes(k) && typeof v === 'string' && v.length <= 2000));
  return { payload: p, encoded: e.payload, raw: JSON.stringify(e) + '\n' };
}
export function newestEnvelope(values) {
  assert.ok(values.length > 0, 'No verified update catalog');
  const selected = values.reduce((a,b) => a.payload.sequence >= b.payload.sequence ? a : b);
  assert.ok(values.every(v => v.payload.sequence !== selected.payload.sequence || v.encoded === selected.encoded), 'Conflicting signed catalogs');
  return selected;
}
export function catalogChange(selected, previous, channel, options) {
  if (!previous) return selected.raw;
  const old = readEnvelope(previous, channel, { ...options, allowExpired: true });
  assert.ok(selected.payload.sequence >= old.payload.sequence, 'Refusing catalog sequence rollback');
  if (selected.payload.sequence === old.payload.sequence) {
    assert.equal(selected.encoded, old.encoded, 'Same catalog sequence changed');
    return null;
  }
  return selected.raw;
}
