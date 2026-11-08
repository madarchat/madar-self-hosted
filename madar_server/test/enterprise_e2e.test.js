process.env.NODE_ENV = 'test';
process.env.DEPLOYMENT_PROFILE = 'workspace';
process.env.DATABASE_URL =
  process.env.WORKSPACE_TEST_DATABASE_URL ||
  'postgresql://postgres:madar-local-change-me@localhost:5432/madar_workspace_test';
process.env.UPLOAD_DIR = '/tmp/madar-workspace-test-uploads';
process.env.LOG_LEVEL = 'silent';
process.env.STUN_ENABLED = 'false';

import test, { before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const { startServer } = await import('../src/index.js');
const { db } = await import('../src/db/pool.js');
const { hashPassword } = await import('../src/lib/password.js');
const { sha256 } = await import('../src/lib/tokens.js');
const { encryptField } = await import('../src/lib/fieldCrypto.js');

let server;
let base;

/** Minimal JSON client. */
async function call(method, path, { token, body } = {}) {
  const res = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

const ENROLL_TOKEN = 'TEST-ENR-0001';
const STAFF_PASSWORD = 'Workspace#Test2026';
const fixtures = {};

/**
 * Builds a small organization directly in the database: one workspace, one
 * department, two employees with credentials, a channel and an enrollment
 * token. This mirrors what `bin/seed-demo.js` produces, so the test exercises
 * the same shape an operator actually deploys.
 */
async function seedWorkspace() {
  for (const table of [
    'broadcast_receipts', 'broadcast_recipients', 'broadcast_versions', 'broadcasts',
    'channel_references', 'decisions', 'followups', 'hub_items', 'search_docs',
    'mentions', 'reactions', 'message_edits', 'channel_messages', 'channel_members', 'channels',
    'audit_log', 'legal_holds', 'break_glass', 'enrollment_tokens',
    'relay_wake_events', 'relay_push_handles',
    'refresh_tokens', 'devices', 'credentials', 'user_roles', 'mfa_factors', 'recovery_codes',
    'sessions', 'user_key_bundles', 'thread_members', 'messages', 'threads',
    'departments', 'users', 'workspace',
  ]) {
    await db.query(`DELETE FROM ${table}`);
  }

  const ws = await db.one(
    `INSERT INTO workspace (name, locale, timezone, deployment_profile, setup_completed)
     VALUES ('مساحة عمل الاختبار', 'ar', 'Asia/Riyadh', 'workspace', TRUE) RETURNING id`,
  );
  const dept = await db.one(
    `INSERT INTO departments (workspace_id, name, code) VALUES ($1, 'الهندسة', 'ENG') RETURNING id`,
    [ws.id],
  );

  const hash = hashPassword(STAFF_PASSWORD);
  const people = [
    { no: 'EMP-001', name: 'مدير النظام', role: 'SUPER_ADMIN' },
    { no: 'EMP-002', name: 'موظف الاختبار', role: 'MEMBER' },
  ];
  const ids = {};
  for (const p of people) {
    const u = await db.one(
      `INSERT INTO users (name, employee_no, workspace_id, department_id, profile_type, account_status)
       VALUES ($1, $2, $3, $4, 'workspace', 'active') RETURNING id`,
      [p.name, p.no, ws.id, dept.id],
    );
    ids[p.no] = u.id;
    await db.query('INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)', [u.id, hash]);
    await db.query('INSERT INTO user_roles (user_id, role) VALUES ($1, $2)', [u.id, p.role]);
  }

  const channel = await db.one(
    `INSERT INTO channels (workspace_id, kind, name, department_id, posting_mode, created_by)
     VALUES ($1, 'department', 'قناة الهندسة', $2, 'all', $3) RETURNING id`,
    [ws.id, dept.id, ids['EMP-001']],
  );

  const broadcast = await db.one(
    `INSERT INTO broadcasts (workspace_id, ref_no, sender_id, title, priority, ack_type,
                             published_at, created_by, status)
     VALUES ($1, 'BRD-T-001', $2, 'سياسة المرفقات', 'mandatory_ack', 'one_tap', NOW(), $2, 'published')
     RETURNING id`,
    [ws.id, ids['EMP-001']],
  );
  const sealed = encryptField('المرفقات تُتداول داخل مدار حصراً.');
  await db.query(
    `INSERT INTO broadcast_versions (broadcast_id, version_no, title, body_ciphertext, body_iv, key_id, created_by)
     VALUES ($1, 1, 'سياسة المرفقات', $2, $3, $4, $5)`,
    [broadcast.id, sealed.ciphertext, sealed.iv, sealed.keyId, ids['EMP-001']],
  );
  for (const uid of Object.values(ids)) {
    await db.query('INSERT INTO broadcast_recipients (broadcast_id, user_id) VALUES ($1, $2)', [
      broadcast.id, uid,
    ]);
  }

  await db.query(
    `INSERT INTO enrollment_tokens (workspace_id, token_hash, max_uses, expires_at, created_by)
     VALUES ($1, $2, 50, NOW() + INTERVAL '30 days', $3)`,
    [ws.id, sha256(ENROLL_TOKEN), ids['EMP-001']],
  );

  Object.assign(fixtures, { workspaceId: ws.id, deptId: dept.id, channelId: channel.id, userIds: ids });
}

function enrollBody(identifier) {
  return {
    enrollment_token: ENROLL_TOKEN,
    identifier,
    password: STAFF_PASSWORD,
    device_name: `test-${crypto.randomUUID().slice(0, 8)}`,
    platform: 'android',
    device_pub_key: crypto.randomBytes(32).toString('base64'),
  };
}

before(async () => {
  server = await startServer({ port: 0, stun: false });
  base = `http://127.0.0.1:${server.port}`;
  await seedWorkspace();
});

after(async () => {
  await server?.close();
});

describe('sovereign workspace — enrollment and governance', () => {
  let token;

  test('the public discovery document identifies the organization before sign-in', async () => {
    // The app reads this to confirm which organization a QR code points at,
    // so it must answer without credentials — and must not leak staff data.
    const res = await fetch(`${base}/.well-known/madar-workspace.json`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.workspace_id, fixtures.workspaceId);
    assert.equal(body.name, 'مساحة عمل الاختبار');
    assert.ok(!JSON.stringify(body).includes('EMP-001'), 'discovery must not expose employees');
  });

  test('an employee enrols with a token, employee number and password', async () => {
    const res = await call('POST', '/enroll', { body: enrollBody('EMP-002') });
    // 201: enrolling creates a device record, not just a session.
    assert.equal(res.status, 201, JSON.stringify(res.json).slice(0, 400));
    assert.ok(res.json.access_token);
    assert.ok(res.json.refresh_token);
    token = res.json.access_token;
  });

  test('the issued token carries the workspace and the role, not a personal session', async () => {
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    assert.equal(claims.wid, fixtures.workspaceId);
    assert.equal(claims.profile_type, 'workspace');
    assert.deepEqual(claims.roles, ['MEMBER']);
    assert.ok(claims.did, 'a workspace token is bound to a device');
  });

  test('a wrong password is refused even with a valid enrollment token', async () => {
    const res = await call('POST', '/enroll', {
      body: { ...enrollBody('EMP-002'), password: 'not-the-password' },
    });
    assert.notEqual(res.status, 200);
  });

  test('an unknown enrollment token is refused', async () => {
    const res = await call('POST', '/enroll', {
      body: { ...enrollBody('EMP-002'), enrollment_token: 'TEST-ENR-WRONG' },
    });
    assert.notEqual(res.status, 200);
  });

  test('an enrolled employee sees the organization channels', async () => {
    const res = await call('GET', '/channels', { token });
    assert.equal(res.status, 200);
    assert.ok(res.json.channels.some((c) => c.name === 'قناة الهندسة'));
  });

  test('the directory lists colleagues from the organization records', async () => {
    const res = await call('GET', '/directory', { token });
    assert.equal(res.status, 200);
    const names = (res.json.employees || []).map((e) => e.name ?? e.display_name);
    assert.ok(names.includes('مدير النظام'), JSON.stringify(names));
  });

  test('a mandatory broadcast is delivered with its body decrypted for the reader', async () => {
    const res = await call('GET', '/broadcasts', { token });
    assert.equal(res.status, 200);
    const item = res.json.broadcasts.find((b) => b.ref_no === 'BRD-T-001');
    assert.ok(item, 'the seeded broadcast is addressed to this employee');
    assert.equal(item.title, 'سياسة المرفقات');
    assert.match(item.body, /المرفقات تُتداول داخل مدار/);
  });

  test('requests without a token are rejected', async () => {
    for (const path of ['/channels', '/directory', '/broadcasts', '/hub']) {
      const res = await call('GET', path);
      assert.equal(res.status, 401, `${path} must require authentication`);
    }
  });
});

describe('product isolation — the personal social graph is absent', () => {
  // These are not "forbidden" here, they do not exist. A self-hosted server
  // has no moments, no waves, no phone-number discovery and no public invite
  // links, so an organization cannot accumulate that data even by accident.
  for (const path of ['/moments', '/people', '/pulse', '/invites', '/reports']) {
    test(`${path} is not served by a workspace deployment`, async () => {
      const res = await call('GET', path);
      assert.equal(res.status, 404, `${path} returned ${res.status}`);
    });
  }

  test('the personal social tables are not even present in the schema', async () => {
    const rows = await db.many(
      `SELECT tablename FROM pg_tables
       WHERE schemaname = 'public'
         AND tablename IN ('waves','moments','moment_views','invite_links',
                           'phone_lookup_audit','invite_open_audit','user_phone_hashes')`,
    );
    assert.deepEqual(rows, [], `unexpected personal tables: ${rows.map((r) => r.tablename).join(', ')}`);
  });
});
