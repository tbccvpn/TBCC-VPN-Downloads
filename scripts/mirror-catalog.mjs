import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { catalogChange, channels, newestEnvelope, origins, readEnvelope, repository } from './catalog-policy.mjs';

const branch = 'updates-v1';
export async function catalogAt(address, channel) {
  const response = await fetch(address, { redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000) });
  if (response.status === 404) return null;
  assert.equal(response.status, 200, 'Catalog origin unavailable');
  const chunks = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length; assert.ok(size <= 65536, 'Catalog exceeds limit'); chunks.push(chunk);
  }
  return readEnvelope(Buffer.concat(chunks).toString('utf8'), channel);
}
export async function readCatalogs(read = catalogAt) {
  const selected = {};
  for (const channel of channels) {
    const replies = await Promise.allSettled(origins.map(origin => read(origin + '/updates/android/v1/' + channel + '.json', channel)));
    const valid = replies.filter(r => r.status === 'fulfilled' && r.value).map(r => r.value);
    if (valid.length) selected[channel] = newestEnvelope(valid);
    else if (channel === 'stable' || replies.some(r => r.status === 'rejected')) throw Error('No verified ' + channel + ' catalog');
    // A never-activated development channel legitimately has no public file.
  }
  return selected;
}
function api(method, endpoint, body) {
  try {
    return JSON.parse(execFileSync('gh', ['api', '--method', method, '/repos/' + repository + endpoint,
      ...(body ? ['--input', '-'] : [])], {
      ...(body ? { input: JSON.stringify(body) } : {}), encoding: 'utf8', maxBuffer: 2 * 1024 * 1024, timeout: 30000,
      stdio: ['pipe','pipe','pipe'],
    }));
  } catch(error) {
    if (method === 'GET' && String(error.stderr).includes('(HTTP 404)')) return null;
    throw Error('GitHub catalog operation failed: ' + method);
  }
}
export function publishCatalogs(selected, publish = false, request = api, options = {}) {
  const ref = request('GET', '/git/ref/heads/' + branch);
  const parent = ref?.object.sha ?? request('GET', '/git/ref/heads/main').object.sha;
  const base = ref ? request('GET', '/git/commits/' + parent).tree.sha : undefined;
  const tree = [];
  for (const [channel, value] of Object.entries(selected)) {
    const name = 'android/v1/' + channel + '.json';
    const file = ref ? request('GET', '/contents/' + name + '?ref=' + branch) : null;
    if (file) assert.ok(file.type === 'file' && file.encoding === 'base64' && file.size <= 65536);
    const previous = file ? Buffer.from(file.content, 'base64').toString('utf8') : null;
    const content = catalogChange(value, previous, channel, options);
    if (content) tree.push({ path: name, mode: '100644', type: 'blob', content });
  }
  if (!tree.length) return { changed: false, channels: Object.keys(selected) };
  if (!publish) return { changed: true, channels: Object.keys(selected) };
  const nextTree = request('POST', '/git/trees', { ...(base ? { base_tree: base } : {}), tree });
  const commit = request('POST', '/git/commits', { message: 'Refresh signed Android update catalog', tree: nextTree.sha, parents: [parent] });
  if (ref) request('PATCH', '/git/refs/heads/' + branch, { sha: commit.sha, force: false });
  else request('POST', '/git/refs', { ref: 'refs/heads/' + branch, sha: commit.sha });
  return { changed: true, channels: Object.keys(selected) };
}
async function main() {
  const publish = process.argv.includes('--publish');
  if (publish) assert.ok(process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_REPOSITORY === repository && process.env.GITHUB_REF === 'refs/heads/main', 'Publication requires the trusted main workflow');
  const selected = await readCatalogs();
  console.log(JSON.stringify(publishCatalogs(selected, publish)));
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(() => { console.error('Signed catalog mirror failed; previous catalog was retained.'); process.exitCode = 1; });
