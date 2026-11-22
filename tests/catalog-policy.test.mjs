import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { catalogChange, newestEnvelope, readEnvelope } from '../scripts/catalog-policy.mjs';
import { publishCatalogs, readCatalogs } from '../scripts/mirror-catalog.mjs';

const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const now = 1800000000000;
const options = { now, key: keys.publicKey };
function metadata(change = {}) {
  return { schema:1, packageName:'app.tbcc.vpn', channel:'stable', sequence:5, issuedAt:now-1000,
    expiresAt:now+3600000, status:'active', releaseId:'stable-30', versionName:'0.4.21', versionCode:30,
    minSdk:28, certificateSha256:'7a1d812882487be51df39d6027622ebe059877b4db336c75f2fde51d187c2f31',
    rolloutPercent:100, rolloutSalt:'fixture-salt', notes:{en:'Synthetic test release'},
    artifacts:[{abi:'arm64-v8a',bytes:100,sha256:'a'.repeat(64),urls:['https://updates.tbcc.com/downloads/android/stable/30/arm64-v8a.apk']}], ...change };
}
function signed(p) {
  const payload = Buffer.from(JSON.stringify(p));
  const signature = sign('sha256', Buffer.concat([Buffer.from('TBCC-APP-UPDATE-v1\n'), payload]), { key:keys.privateKey, dsaEncoding:'ieee-p1363' });
  return JSON.stringify({keyId:'tbcc-updates-2026-1',payload:payload.toString('base64'),signature:signature.toString('base64')});
}
const read = p => readEnvelope(signed(p),p.channel,options);

test('catalog preserves signed pause and partial rollout without making a new policy',()=>{
  for(const state of [{status:'paused'},{rolloutPercent:5},{rolloutPercent:25}]) {
    const p=metadata(state);assert.deepEqual(read(p).payload,p);
  }
});
test('tampering, wrong signer/channel, expiry and foreign or mutable URLs are rejected',()=>{
  const e=JSON.parse(signed(metadata()));e.payload=JSON.parse(signed(metadata({versionCode:31}))).payload;
  assert.throws(()=>readEnvelope(JSON.stringify(e),'stable',options));
  for(const p of [metadata({expiresAt:now}),metadata({certificateSha256:'b'.repeat(64)}),metadata({rolloutPercent:101}),
    metadata({artifacts:[{...metadata().artifacts[0],urls:['https://attacker.invalid/app.apk']}]})]) assert.throws(()=>read(p));
  assert.throws(()=>readEnvelope(signed(metadata()),'development',options));
  assert.throws(()=>readEnvelope(signed(metadata()),'stable',{now,key:generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey}));
});
test('newer pause wins; sequence rollback and equivocation never overwrite the mirror',()=>{
  const old=read(metadata()),paused=read(metadata({sequence:6,status:'paused'}));
  assert.equal(newestEnvelope([old,paused]).payload.status,'paused');
  assert.throws(()=>newestEnvelope([old,read(metadata({status:'paused'}))]));
  assert.throws(()=>catalogChange(old,paused.raw,'stable',options));
  assert.equal(catalogChange(old,old.raw,'stable',options),null);
  const expired=signed(metadata({sequence:4,expiresAt:now-1}));
  assert.equal(catalogChange(old,expired,'stable',options),old.raw);
});
test('one reachable origin works and unconfigured development is kept absent',async()=>{
  const value=read(metadata());
  const result=await readCatalogs(async(address,channel)=>{
    if(channel==='development')return null;
    if(address.startsWith('https://updates.'))throw Error('Synthetic outage');
    return value;
  });
  assert.deepEqual(Object.keys(result),['stable']);
  assert.equal(result.stable,value);
  await assert.rejects(()=>readCatalogs(async()=>{throw Error('Synthetic outage')}));
});
test('catalog publication changes only fixed data paths and never force-pushes',()=>{
  const calls=[];const value=read(metadata());
  const request=(method,path,body)=>{
    calls.push({method,path,body});
    if(path==='/git/ref/heads/updates-v1')return {object:{sha:'old'}};
    if(path==='/git/commits/old')return {tree:{sha:'base'}};
    if(path.startsWith('/contents/'))return null;
    if(path==='/git/trees')return {sha:'tree'};
    if(path==='/git/commits')return {sha:'new'};
    if(path==='/git/refs/heads/updates-v1')return {};
    throw Error('Unexpected API call');
  };
  assert.equal(publishCatalogs({stable:value},true,request,options).changed,true);
  const tree=calls.find(c=>c.path==='/git/trees').body;
  assert.equal(tree.base_tree,'base');assert.deepEqual(tree.tree.map(t=>t.path),['android/v1/stable.json']);
  assert.deepEqual(calls.at(-1).body,{sha:'new',force:false});
  const mutations=[];
  publishCatalogs({stable:value},false,(method,path,body)=>{if(method!=='GET')mutations.push(body);return request(method,path,body)},options);
  assert.deepEqual(mutations,[]);
});
