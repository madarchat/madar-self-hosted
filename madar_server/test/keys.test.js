process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = process.env.KEYS_TEST_DATABASE_URL || 'postgresql://postgres:madar-local-change-me@localhost:5432/madar_keys_test';
process.env.STUN_ENABLED = 'false';
process.env.UPLOAD_DIR = '/tmp/madar-keys-test-uploads';
process.env.LOG_LEVEL = 'warn';

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';

const { startServer } = await import('../src/index.js');
const { db } = await import('../src/db/pool.js');
const { api, login } = await import('./helpers.js');

let server;
let client;
let alice;
let bob;
let carol;

function rawPublic(key) {
  return key.export({ type: 'spki', format: 'der' }).subarray(-32);
}

function freshBundle(opkCount = 2) {
  const signing = generateKeyPairSync('ed25519');
  const prekey = rawPublic(generateKeyPairSync('x25519').publicKey);
  const signature = sign(null, prekey, signing.privateKey);
  const oneTime = [];
  for (let i = 1; i <= opkCount; i += 1) {
    oneTime.push({ key_id: i, public_key: rawPublic(generateKeyPairSync('x25519').publicKey).toString('base64') });
  }
  return {
    identity_key: rawPublic(generateKeyPairSync('x25519').publicKey).toString('base64'),
    signing_key: rawPublic(signing.publicKey).toString('base64'),
    signed_prekey_id: 1,
    signed_prekey: prekey.toString('base64'),
    signed_prekey_sig: signature.toString('base64'),
    one_time_prekeys: oneTime,
    signing,
  };
}

before(async () => {
  server = await startServer({ port: 0, host: '127.0.0.1', stun: false });
  client = api(`http://127.0.0.1:${server.port}`, '/api/v1');
  await db.query('TRUNCATE users RESTART IDENTITY CASCADE');
  alice = await login(client, '+967773100001', 'Alice');
  bob = await login(client, '+967773100002', 'Bob');
  carol = await login(client, '+967773100003', 'Carol');
});

after(async () => {
  await server.close();
});

test('a bundle without a valid signature is rejected', async () => {
  const bundle = freshBundle();
  bundle.signed_prekey_sig = Buffer.alloc(64, 9).toString('base64');
  const rejected = await client.post('/keys/bundle', { token: alice.token, body: bundle });
  assert.equal(rejected.status, 400);
  assert.equal(rejected.json.error.code, 'invalid_key_signature');
});

test('the account owner can publish a signed bundle', async () => {
  const bundle = freshBundle();
  alice.bundle = bundle;
  const uploaded = await client.post('/keys/bundle', { token: alice.token, body: bundle });
  assert.equal(uploaded.status, 200);
  assert.equal(uploaded.json.identity_generation, 1);
  assert.equal(uploaded.json.one_time_remaining, 2);
});

test('another account cannot replace or read a stranger bundle', async () => {
  const bobBundle = freshBundle();
  bob.bundle = bobBundle;
  const uploaded = await client.post('/keys/bundle', { token: bob.token, body: bobBundle });
  assert.equal(uploaded.status, 200);

  const stranger = await client.get(`/keys/bundle/${alice.user.id}`, { token: carol.token });
  assert.equal(stranger.status, 403);
  assert.equal(stranger.json.error.code, 'key_bundle_unavailable');

  const own = await client.get('/keys/bundle/' + alice.user.id, { token: alice.token, });
  assert.equal(own.status, 200);
  assert.equal(own.json.bundle.identity_key, alice.bundle.identity_key);
  assert.equal(JSON.stringify(own.json).includes('identity_priv'), false);
  assert.equal(own.json.bundle.one_time_prekey, null);
});

test('replacing an identity requires an explicit confirmation', async () => {
  const next = freshBundle();
  const blocked = await client.post('/keys/bundle', { token: alice.token, body: next });
  assert.equal(blocked.status, 409);
  assert.equal(blocked.json.error.code, 'identity_pinned');

  const still = await client.get(`/keys/bundle/${alice.user.id}`, { token: alice.token });
  assert.equal(still.json.bundle.identity_key, alice.bundle.identity_key);
  assert.equal(still.json.bundle.identity_generation, 1);

  next.confirm_replace = true;
  const replaced = await client.post('/keys/bundle', { token: alice.token, body: next });
  assert.equal(replaced.status, 200);
  assert.equal(replaced.json.identity_generation, 2);
  alice.bundle = next;

  const published = await client.get(`/keys/bundle/${alice.user.id}`, { token: alice.token });
  assert.equal(published.json.bundle.identity_key, next.identity_key);
  assert.equal(published.json.bundle.identity_generation, 2);
});

test('a shared thread can read a bundle and consumes each one-time key once', async () => {
  const th = await db.one(`INSERT INTO threads (kind, title) VALUES ('direct', '') RETURNING id`);
  await db.query(
    `INSERT INTO thread_members (thread_id, user_id, role) VALUES ($1, $2, 'member'), ($1, $3, 'member')`,
    [th.id, alice.user.id, bob.user.id],
  );

  const quiet = await client.get(`/keys/bundle/${bob.user.id}?one_time=0`, { token: alice.token });
  assert.equal(quiet.status, 200);
  assert.equal(quiet.json.bundle.one_time_prekey, null);
  assert.equal(quiet.json.bundle.identity_key, bob.bundle.identity_key);

  const [first, second] = await Promise.all([
    client.get(`/keys/bundle/${bob.user.id}`, { token: alice.token }),
    client.get(`/keys/bundle/${bob.user.id}`, { token: alice.token }),
  ]);
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  const ids = [first.json.bundle.one_time_prekey.key_id, second.json.bundle.one_time_prekey.key_id].sort();
  assert.deepEqual(ids, [1, 2]);
  assert.notEqual(first.json.bundle.one_time_prekey.public_key, second.json.bundle.one_time_prekey.public_key);

  const empty = await client.get(`/keys/bundle/${bob.user.id}`, { token: alice.token });
  assert.equal(empty.json.bundle.one_time_prekey, null);
  const dumped = JSON.stringify(empty.json);
  assert.equal(dumped.includes('private'), false);
});
