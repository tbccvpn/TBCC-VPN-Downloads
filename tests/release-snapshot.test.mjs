import test from 'node:test';
import assert from 'node:assert/strict';
import {releaseSnapshot, waitForDraft} from '../scripts/mirror-stable.mjs';
const old={tag_name:'v0.4.25',draft:false,prerelease:false,assets:[]};
const draft={tag_name:'v0.5.0',draft:true,prerelease:false,assets:[]};
function requestFor(rows, exact=draft) {
 return args=> {
  const url=args.at(-1);
  if(url.endsWith('?per_page=100'))return JSON.stringify([rows]);
  if(url.endsWith('/latest'))return JSON.stringify(old);
  if(exact instanceof Error)throw exact;
  return JSON.stringify(exact);
 };
}
test('exact tag sees a just-created draft missing from the paginated list',()=> {
 const snapshot=releaseSnapshot('v0.5.0',requestFor([old]));
 assert.equal(snapshot.latestTag,old.tag_name);
 assert.deepEqual(snapshot.releases,[old,draft]);
});
test('exact tag replaces stale asset metadata but retains other release fences',()=> {
 const newer={...old,tag_name:'v0.6.0'};
 const fresh={...draft,assets:[{name:'signed.apk',state:'uploaded'}]};
 const snapshot=releaseSnapshot('v0.5.0',requestFor([old,draft,newer],fresh));
 assert.deepEqual(snapshot.releases.find(r=>r.tag_name==='v0.5.0'),fresh);
 assert.ok(snapshot.releases.some(r=>r.tag_name===newer.tag_name));
});
test('missing tag is accepted before creation; other API errors stop publication',()=> {
 const missing=Object.assign(new Error('missing'),{stderr:'gh: Not Found (HTTP 404)'});
 assert.deepEqual(releaseSnapshot('v0.5.0',requestFor([old],missing)).releases,[old]);
 const denied=Object.assign(new Error('denied'),{stderr:'HTTP 403'});
 assert.throws(()=>releaseSnapshot('v0.5.0',requestFor([old],denied)),/denied/);
 assert.throws(()=>releaseSnapshot('v0.5.0',requestFor([old],{...draft,tag_name:'v0.6.0'})),/another tag/);
});
test('read-after-create waits for visibility with a strict bound',async()=> {
 let calls=0,waits=0;
 const result=await waitForDraft(()=>++calls<3?{action:'publish'}:{action:'publish',draft},'v0.5.0',async ms=>{assert.equal(ms,1000);waits++;});
 assert.equal(result.draft,draft);assert.equal(calls,3);assert.equal(waits,2);
 calls=0;
 await assert.rejects(waitForDraft(()=>{calls++;return {action:'publish'};},'v0.5.0',async()=>{}),/not visible/);
 assert.equal(calls,10);
});
test('policy/immutable metadata errors are never retried',async()=> {
 let calls=0;
 await assert.rejects(waitForDraft(()=>{calls++;throw Error('metadata differs');},'v0.5.0',async()=>assert.fail('retry')),/metadata differs/);
 assert.equal(calls,1);
});
