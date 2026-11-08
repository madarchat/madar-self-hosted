import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL =
  process.env.TEST_DATABASE_URL ||
  'postgresql://postgres:madar-local-change-me@localhost:5432/madar_test';
process.env.STUN_PORT = '3495';
process.env.CALL_RING_TIMEOUT_MS = '1500';
process.env.UPLOAD_DIR = '/tmp/madar-workspace-test-uploads';
process.env.LOG_LEVEL = 'warn';

const { startServer } = await import('../src/index.js');
const { db } = await import('../src/db/pool.js');
const { verifyEd25519Jws } = await import('../src/lib/jws.js');
const { generateTotpCode } = await import('../src/lib/totp.js');
const { decryptField } = await import('../src/lib/fieldCrypto.js');
const { sanitizeCsvCell } = await import('../src/routes/admin.js');
const { runMadarCtl } = await import('../bin/madarctl.js');
const { createAdminConsoleServer } = await import('../../madar_admin_console/src/server.js');

let server;
let base;
let adminBff;
let adminBffBase;

async function callApi(method, path, { token, body, headers = {} } = {}) {
  const reqHeaders = { ...headers };
  if (token) reqHeaders.authorization = `Bearer ${token}`;
  let payload;
  if (body !== undefined) {
    reqHeaders['content-type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: reqHeaders,
    body: payload,
  });
  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json')
    ? await res.json().catch(() => ({}))
    : await res.text();
  return { status: res.status, json: data, headers: res.headers };
}

function generateEd25519DeviceKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const pubKeyB64Url = spki.subarray(-32).toString('base64url');
  return {
    pubKeyB64Url,
    sign(message) {
      return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('base64url');
    },
  };
}

before(async () => {
  server = await startServer({ port: 0, host: '127.0.0.1' });
  base = `http://127.0.0.1:${server.port}`;

  // Clean workspace & user tables for deterministic test execution
  await db.query('SET session_replication_role = replica');
  await db.query(`
    TRUNCATE
      audit_log,
      broadcast_receipts,
      broadcast_recipients,
      broadcast_versions,
      broadcasts,
      broadcast_templates,
      channel_references,
      followups,
      decisions,
      reactions,
      message_edits,
      channel_messages,
      channel_members,
      channels,
      hub_items,
      search_docs,
      legal_holds,
      break_glass,
      policy_versions,
      policy_entries,
      policy_group_members,
      policy_groups,
      policy_signing_keys,
      enrollment_tokens,
      refresh_tokens,
      relay_wake_events,
      relay_push_handles,
      auth_providers,
      devices,
      mfa_factors,
      recovery_codes,
      credentials,
      user_roles,
      departments,
      users,
      workspace
    RESTART IDENTITY CASCADE
  `);
  await db.query('SET session_replication_role = DEFAULT');
});

after(async () => {
  if (adminBff) await adminBff.close();
  if (server) await server.close();
});

describe('Madar Workspace v1.0 & Isolated Control Plane End-to-End Suite', () => {
  let workspaceId;
  let signingPubKey;
  let superAdminToken;
  let superAdminUser;
  let itAdminToken;
  let complianceToken;
  let complianceUserId;
  let engDeptId;
  let opsDeptId;
  let deptHeadUserId;
  let deptHeadToken;
  let employeeUser;
  let employeeToken;
  let employeeDeviceId;
  let employeeDeviceKeys;

  test('1. Control-Plane Isolation: /admin is NOT embedded in madar_server & controlPlaneGuard enforces secrets and toggles', async () => {
    // 1a. Embedded /admin must return 404 on madar_server
    const embeddedRes = await fetch(`${base}/admin`);
    assert.equal(embeddedRes.status, 404, 'madar_server must not serve an embedded /admin web app');

    // 1b. When ADMIN_API_ENABLED=false, /api/v1/admin/* returns 404 on edge nodes
    process.env.ADMIN_API_ENABLED = 'false';
    const disabledRes = await callApi('POST', '/admin/setup', {
      body: { workspace_name: 'Blocked Edge' },
    });
    assert.equal(disabledRes.status, 404);
    process.env.ADMIN_API_ENABLED = 'true';

    // 1c. When ADMIN_PLANE_SECRET is configured, requests without X-Madar-Control-Plane-Key are rejected with 403
    process.env.ADMIN_PLANE_SECRET = 'top-secret-control-plane-key-2026';
    const missingKeyRes = await callApi('POST', '/admin/setup', {
      body: { workspace_name: 'Missing Key' },
    });
    assert.equal(missingKeyRes.status, 403);
    assert.equal(missingKeyRes.json.error.code, 'untrusted_control_plane');
  });

  test('2. First-Boot Setup Wizard (ADM-01) & Discovery (ENR-01)', async () => {
    const setupRes = await callApi('POST', '/admin/setup', {
      headers: { 'X-Madar-Control-Plane-Key': process.env.ADMIN_PLANE_SECRET },
      body: {
        workspace_name: 'هيئة الفضاء السيادية — مدار',
        primary_color: '#0F766E',
        locale: 'ar',
        timezone: 'Asia/Riyadh',
        deployment_profile: 'workspace',
        policy_preset: 'regulated',
        admin_user: {
          employee_no: 'ADM-001',
          name: 'م. طارق المنصور',
          email: 'tarek@madar.gov.sa',
          title: 'المدير التنفيذي لتقنية المعلومات',
          password: 'Sovereign#2026!Admin',
        },
        departments: [
          { name: 'إدارة هندسة المنصات', code: 'ENG' },
          { name: 'إدارة العمليات السيبرانية', code: 'SECOPS' },
        ],
      },
    });

    assert.equal(setupRes.status, 201, JSON.stringify(setupRes.json));
    assert.equal(setupRes.json.success, true);
    workspaceId = setupRes.json.workspace.id;
    signingPubKey = setupRes.json.policy_signing_pub_key;
    assert.ok(workspaceId);
    assert.ok(signingPubKey);
    assert.equal(setupRes.json.departments.length, 2);
    engDeptId = setupRes.json.departments[0].id;
    opsDeptId = setupRes.json.departments[1].id;

    // Verify Discovery endpoint (/.well-known/madar-workspace.json & /api/v1/server/info)
    const infoRes = await callApi('GET', '/server/info');
    assert.equal(infoRes.status, 200);
    assert.equal(infoRes.json.workspace_id, workspaceId);
    assert.equal(infoRes.json.policy_signing_pub_key, signingPubKey);
    assert.equal(infoRes.json.setup_completed, true);
  });

  test('3. Isolated Admin Console BFF (madar_admin_console): HttpOnly session cookie, zero localStorage JWT, and CSRF enforcement', async () => {
    adminBff = await createAdminConsoleServer({
      port: 0,
      host: '127.0.0.1',
      coreApiUrl: base,
      controlPlaneSecret: process.env.ADMIN_PLANE_SECRET,
      sessionSecret: 'bff-test-session-secret-key-32bytes!',
    });
    adminBffBase = `http://127.0.0.1:${adminBff.port}`;

    // 3a. Health check confirms zero direct DB access
    const healthRes = await fetch(`${adminBffBase}/admin-api/health`).then((r) => r.json());
    assert.equal(healthRes.status, 'ok');
    assert.equal(healthRes.isolated, true);
    assert.equal(healthRes.zero_db_access, true);

    // 3b. Login through BFF sets HttpOnly cookie and returns CSRF token (never raw access_token)
    const loginRes = await fetch(`${adminBffBase}/admin-api/session/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        identifier: 'ADM-001',
        password: 'Sovereign#2026!Admin',
      }),
    });
    assert.equal(loginRes.status, 200);
    const setCookie = loginRes.headers.get('set-cookie') || '';
    assert.match(setCookie, /madar_admin_sid=/);
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /SameSite=Strict/i);

    const cookieHeader = setCookie.split(';')[0];
    const loginBody = await loginRes.json();
    assert.equal(loginBody.authenticated, true);
    assert.ok(loginBody.csrf_token);
    assert.equal(loginBody.access_token, undefined, 'BFF must not leak raw JWT to browser JS');

    // 3c. Proxy GET /admin-api/proxy/overview works with HttpOnly cookie
    const overviewRes = await fetch(`${adminBffBase}/admin-api/proxy/overview`, {
      headers: { cookie: cookieHeader },
    }).then((r) => r.json());
    assert.equal(overviewRes.success, true);
    assert.equal(overviewRes.kpis.departments, 2);

    // 3d. Mutating request through BFF without X-Madar-CSRF is rejected with 403
    const noCsrfRes = await fetch(`${adminBffBase}/admin-api/proxy/departments`, {
      method: 'POST',
      headers: {
        cookie: cookieHeader,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ name: 'قسم الاختبار', code: 'TST' }),
    });
    assert.equal(noCsrfRes.status, 403);
    const noCsrfJson = await noCsrfRes.json();
    assert.equal(noCsrfJson.error.code, 'csrf_validation_failed');

    // 3e. Mutating request with valid X-Madar-CSRF succeeds via isolated BFF
    const withCsrfRes = await fetch(`${adminBffBase}/admin-api/proxy/departments`, {
      method: 'POST',
      headers: {
        cookie: cookieHeader,
        'x-madar-csrf': loginBody.csrf_token,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ name: 'إدارة الحوكمة والمخاطر', code: 'GRC' }),
    });
    assert.equal(withCsrfRes.status, 201);
  });

  test('4. Enterprise Authentication, Role Provisioning, & TOTP Replay Protection (AUT-01..06)', async () => {
    // Clear ADMIN_PLANE_SECRET restriction or pass header in helper for remaining tests
    const cpHeaders = { 'X-Madar-Control-Plane-Key': process.env.ADMIN_PLANE_SECRET };

    // Login as SUPER_ADMIN directly to get token for API test assertions
    const loginRes = await callApi('POST', '/auth/login', {
      body: {
        identifier: 'ADM-001',
        password: 'Sovereign#2026!Admin',
        device_name: 'Admin Workstation',
        platform: 'web',
        device_pub_key: generateEd25519DeviceKeyPair().pubKeyB64Url,
      },
    });
    assert.equal(loginRes.status, 200);
    superAdminToken = loginRes.json.access_token;
    superAdminUser = loginRes.json.user;

    // Verify signed policy bundle returned on login (Ed25519 JWS)
    const verifiedBundle = verifyEd25519Jws(loginRes.json.policy_bundle.jws, signingPubKey);
    assert.equal(verifiedBundle.payload.workspace_id, workspaceId);

    // Provision IT_ADMIN, COMPLIANCE_OFFICER, and DEPT_HEAD
    const itRes = await callApi('POST', '/admin/users', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        employee_no: 'IT-002',
        name: 'فهد القحطاني',
        email: 'fahad@madar.gov.sa',
        title: 'مسؤول تقنية المعلومات',
        department_id: engDeptId,
        roles: ['IT_ADMIN'],
        password: 'ItAdmin#2026!Pass',
      },
    });
    assert.equal(itRes.status, 201);

    const compRes = await callApi('POST', '/admin/users', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        employee_no: 'CMP-003',
        name: 'نورة السبيعي',
        email: 'noura@madar.gov.sa',
        title: 'مسؤولة الامتثال والحوكمة',
        department_id: opsDeptId,
        roles: ['COMPLIANCE_OFFICER'],
        password: 'Compliance#2026!Pass',
      },
    });
    assert.equal(compRes.status, 201);
    complianceUserId = compRes.json.user.id;

    const headRes = await callApi('POST', '/admin/users', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        employee_no: 'ENG-HEAD-01',
        name: 'د. سلمان العتيبي',
        email: 'salman@madar.gov.sa',
        title: 'مدير هندسة المنصات',
        department_id: engDeptId,
        roles: ['DEPT_HEAD', 'BROADCASTER'],
        password: 'DeptHead#2026!Pass',
      },
    });
    assert.equal(headRes.status, 201);
    deptHeadUserId = headRes.json.user.id;

    // Assign head_user_id on ENG department
    await db.query('UPDATE departments SET head_user_id = $2 WHERE id = $1', [engDeptId, deptHeadUserId]);

    // Login as IT_ADMIN, COMPLIANCE_OFFICER, and DEPT_HEAD
    itAdminToken = (
      await callApi('POST', '/auth/login', {
        body: {
          identifier: 'IT-002',
          password: 'ItAdmin#2026!Pass',
          device_name: 'IT Laptop',
          platform: 'web',
          device_pub_key: generateEd25519DeviceKeyPair().pubKeyB64Url,
        },
      })
    ).json.access_token;

    complianceToken = (
      await callApi('POST', '/auth/login', {
        body: {
          identifier: 'CMP-003',
          password: 'Compliance#2026!Pass',
          device_name: 'Compliance Laptop',
          platform: 'web',
          device_pub_key: generateEd25519DeviceKeyPair().pubKeyB64Url,
        },
      })
    ).json.access_token;

    deptHeadToken = (
      await callApi('POST', '/auth/login', {
        body: {
          identifier: 'ENG-HEAD-01',
          password: 'DeptHead#2026!Pass',
          device_name: 'DeptHead Tablet',
          platform: 'ios',
          device_pub_key: generateEd25519DeviceKeyPair().pubKeyB64Url,
        },
      })
    ).json.access_token;

    // Test TOTP enrollment & RFC 6238 Replay Protection
    const totpSetup = await callApi('POST', '/auth/totp/setup', {
      token: itAdminToken,
      body: {},
    });
    if (totpSetup.status === 200) {
      const secret = totpSetup.json.secret;
      const code = generateTotpCode(secret);
      const verify1 = await callApi('POST', '/auth/totp/verify', {
        token: itAdminToken,
        body: { code },
      });
      assert.equal(verify1.status, 200);

      // Replaying the exact same TOTP code in the same 30-second window must be rejected
      const verifyReplay = await callApi('POST', '/auth/totp/verify', {
        token: itAdminToken,
        body: { code },
      });
      assert.equal(verifyReplay.status, 400, 'Replaying a TOTP code in the same time-step must fail');
    }
  });

  test('5. Signed JWS Enrollment Token & Device Binding (ENR-02..04)', async () => {
    const cpHeaders = { 'X-Madar-Control-Plane-Key': process.env.ADMIN_PLANE_SECRET };

    // Provision invited employee
    const empCreate = await callApi('POST', '/admin/users', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        employee_no: 'EMP-100',
        name: 'خالد الدوسري',
        email: 'khaled@madar.gov.sa',
        title: 'مهندس نظم أول',
        department_id: engDeptId,
        roles: ['MEMBER'],
      },
    });
    assert.equal(empCreate.status, 201);
    employeeUser = empCreate.json.user;

    // Issue single-use signed enrollment token for employeeUser
    const tokenRes = await callApi('POST', '/admin/enrollment-tokens', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        target_user_id: employeeUser.id,
        max_uses: 1,
        expires_in_hours: 24,
      },
    });
    assert.equal(tokenRes.status, 201);
    assert.match(tokenRes.json.qr_uri, /^madar:\/\/enroll\?/);
    assert.match(tokenRes.json.qr_uri, /[?&]workspace=/);
    assert.match(tokenRes.json.qr_uri, /[?&]name=/);

    // Enroll employee device with Ed25519 key pair
    employeeDeviceKeys = generateEd25519DeviceKeyPair();
    const enrollRes = await callApi('POST', '/enroll', {
      body: {
        enrollment_token: tokenRes.json.enrollment_token,
        device_name: 'Khaled Android Pixel',
        platform: 'android',
        os_version: 'Android 15',
        app_version: '2.0.0',
        device_pub_key: employeeDeviceKeys.pubKeyB64Url,
        password: 'Employee#2026!Pass',
      },
    });
    assert.equal(enrollRes.status, 201, JSON.stringify(enrollRes.json));
    employeeToken = enrollRes.json.access_token;
    employeeDeviceId = enrollRes.json.device.id;

    // Reusing exhausted single-use enrollment token must fail
    const reuseRes = await callApi('POST', '/enroll', {
      body: {
        enrollment_token: tokenRes.json.enrollment_token,
        device_name: 'Second Device',
        platform: 'android',
        device_pub_key: generateEd25519DeviceKeyPair().pubKeyB64Url,
      },
    });
    assert.equal(reuseRes.status, 400);
    assert.equal(reuseRes.json.error.code, 'enrollment_token_exhausted');

    // Multi-use organization QR token must NOT allow overwriting an existing user's password without verifying it
    const orgTokenRes = await callApi('POST', '/admin/enrollment-tokens', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        max_uses: 5,
        expires_in_hours: 24,
      },
    });
    assert.equal(orgTokenRes.status, 201);

    const hijackAttempt = await callApi('POST', '/enroll/exchange', {
      body: {
        enrollment_token: orgTokenRes.json.enrollment_token,
        identifier: 'EMP-100',
        password: 'WrongPassword#123',
        device_id: 'dev-flutter-hijack',
        platform: 'flutter',
      },
    });
    assert.equal(hijackAttempt.status, 401, 'Multi-use QR token must reject wrong password on existing account');

    const validFlutterEnroll = await callApi('POST', '/enroll/exchange', {
      body: {
        enrollment_token: orgTokenRes.json.enrollment_token,
        identifier: 'EMP-100',
        password: 'Employee#2026!Pass',
        device_pub_key: employeeDeviceKeys.pubKeyB64Url,
        platform: 'flutter',
      },
    });
    assert.equal(validFlutterEnroll.status, 201, JSON.stringify(validFlutterEnroll.json));
    employeeToken = validFlutterEnroll.json.access_token;
  });

  test('6. Hierarchical Policy Engine, Separation of Duties, Locked Inheritance, Preview & Rollback (POL-01..09, ADM-04)', async () => {
    const cpHeaders = { 'X-Madar-Control-Plane-Key': process.env.ADMIN_PLANE_SECRET };

    // 6a. Separation of Duties (ADM-04): IT_ADMIN cannot modify retention.* policies
    const itRetentionAttempt = await callApi('PUT', '/admin/policies', {
      token: itAdminToken,
      headers: cpHeaders,
      body: {
        scope_type: 'workspace',
        reason: 'محاولة تعديل الاحتفاظ من مسؤول تقنية المعلومات',
        changes: [{ key: 'retention.message_days', value: 90, locked: false }],
      },
    });
    assert.equal(itRetentionAttempt.status, 403);

    // 6b. COMPLIANCE_OFFICER can modify retention.* policies
    const compRetentionUpdate = await callApi('PUT', '/admin/policies', {
      token: complianceToken,
      headers: cpHeaders,
      body: {
        scope_type: 'workspace',
        reason: 'اعتماد فترة الاحتفاظ الرقابية',
        changes: [{ key: 'retention.message_days', value: 730, locked: true }],
      },
    });
    assert.equal(compRetentionUpdate.status, 200);

    // 6c. Policy Impact Preview (POL-05)
    const previewRes = await callApi('POST', '/admin/policies/preview', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        scope_type: 'workspace',
        changes: [{ key: 'dlp.prevent_screenshots', value: true, locked: true }],
      },
    });
    assert.equal(previewRes.status, 200);
    assert.ok(previewRes.json.preview.affected_users_count >= 1);

    // 6d. Locked Inheritance: Lock dlp.allow_copy_paste = false at workspace scope, try overriding at user scope
    const lockWsRes = await callApi('PUT', '/admin/policies', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        scope_type: 'workspace',
        reason: 'قفل النسخ واللصق على مستوى المؤسسة',
        changes: [{ key: 'dlp.allow_copy_paste', value: false, locked: true }],
      },
    });
    assert.equal(lockWsRes.status, 200);
    const lockedVersion = lockWsRes.json.version;

    // Set user-level override to true (should be ignored because workspace scope is locked=true)
    await callApi('PUT', '/admin/policies', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        scope_type: 'user',
        scope_id: String(employeeUser.id),
        reason: 'استثناء خاص للموظف',
        changes: [{ key: 'dlp.allow_copy_paste', value: true, locked: false }],
      },
    });

    const empPolicyRes = await callApi('GET', '/policy/me', { token: employeeToken });
    assert.equal(empPolicyRes.status, 200);
    assert.equal(
      empPolicyRes.json.effective_policy['dlp.allow_copy_paste'],
      false,
      'Locked workspace policy must not be overridden by lower scopes',
    );

    // 6e. Rollback policy version (POL-06)
    const rollbackRes = await callApi('POST', '/admin/policies/rollback', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        target_version: lockedVersion,
        reason: 'إلغاء الاستثناء التجريبي',
      },
    });
    assert.equal(rollbackRes.status, 200);
  });

  test('7. Channels, Institutional Memory (Decisions, Superseding, Followups, References), Action Hub & Digest (CHN-01..06, MEM-01..06, HUB-01..02)', async () => {
    // Create a project channel with deptHead and employee
    const chRes = await callApi('POST', '/channels', {
      token: deptHeadToken,
      body: {
        kind: 'project',
        name: 'مشروع القمر الصناعي مدار-1',
        description: 'قناة التنسيق الهندسي لإطلاق مدار-1',
        department_id: engDeptId,
        member_ids: [employeeUser.id],
      },
    });
    assert.equal(chRes.status, 201);
    const channelId = chRes.json.channel.id;

    // Post a message in the channel
    const msgRes = await callApi('POST', `/channels/${channelId}/messages`, {
      token: deptHeadToken,
      body: {
        body: 'نحتاج إلى اعتماد معيار التشفير الفضائي وجدولة اختبار المحطة الأرضية.',
      },
    });
    assert.equal(msgRes.status, 201);
    const msgId = msgRes.json.message.id;

    // Record a Decision from the message (MEM-01)
    const decRes = await callApi('POST', `/channels/${channelId}/decisions`, {
      token: deptHeadToken,
      body: {
        title: 'اعتماد معيار التشفير AES-256-GCM لوصلة القياس عن بعد',
        rationale: 'التوافق مع المتطلبات السيادية للهيئة',
        source_msg_id: msgId,
      },
    });
    assert.equal(decRes.status, 201);
    const decisionId = decRes.json.decision.id;

    // Supersede the decision with an updated one without deleting history (MEM-06)
    const supRes = await callApi('POST', `/decisions/${decisionId}/supersede`, {
      token: deptHeadToken,
      body: {
        title: 'اعتماد التشفير المزدوج AES-256-GCM مع توقيع Ed25519 لوصلة القياس',
        rationale: 'تعزيز التحقق من سلامة الأوامر الفضائية',
      },
    });
    assert.equal(supRes.status, 201);
    assert.equal(supRes.json.superseded_decision.status, 'superseded');
    assert.equal(supRes.json.decision.status, 'active');

    // Create a Follow-up assigned to employeeUser (MEM-02)
    const dueTomorrow = new Date(Date.now() + 86_400_000).toISOString();
    const fuRes = await callApi('POST', `/channels/${channelId}/followups`, {
      token: deptHeadToken,
      body: {
        title: 'إعداد تقرير جاهزية المحطة الأرضية في الرياض',
        owner_id: employeeUser.id,
        due_at: dueTomorrow,
        source_msg_id: msgId,
      },
    });
    assert.equal(fuRes.status, 201);
    const followupId = fuRes.json.followup.id;

    // Pin a Reference in the channel (MEM-03)
    const refRes = await callApi('POST', `/channels/${channelId}/references`, {
      token: deptHeadToken,
      body: {
        title: 'وثيقة مواصفات وصلة الترددات الفضائية v2',
        ref_type: 'link',
        target_url: 'https://intranet.madar.gov.sa/specs/rf-link-v2.pdf',
      },
    });
    assert.equal(refRes.status, 201);

    // Verify Employee's Action Hub contains the assigned Follow-up and Decision announcement (HUB-01)
    const hubRes = await callApi('GET', '/hub', { token: employeeToken });
    assert.equal(hubRes.status, 200);
    assert.ok(
      hubRes.json.sections.followups.some((item) => item.source_id === followupId),
      'Employee Action Hub must include assigned follow-up',
    );

    // Verify Weekly Channel Digest (MEM-04)
    const digestRes = await callApi('GET', `/channels/${channelId}/digest`, {
      token: employeeToken,
    });
    assert.equal(digestRes.status, 200);
    assert.equal(digestRes.json.digest.summary_counts.open_followups, 1);
    assert.equal(digestRes.json.digest.summary_counts.pinned_references, 1);
  });

  test('8. Verified Broadcasts: Comprehension Quiz, Material Revision Reset & Arabic Search (BRD-01..07, SRCH-01..03)', async () => {
    // Publish a mandatory_ack broadcast with quiz_ack (BRD-01, BRD-03)
    const brdRes = await callApi('POST', '/broadcasts', {
      token: deptHeadToken,
      body: {
        title: 'تعميم تحديث بروتوكول الاستجابة للحوادث السيبرانية للإدارة الهندسية',
        body: 'يجب الإبلاغ عن أي حادثة أمنية خلال 15 دقيقة كحد أقصى عبر قناة الطوارئ.',
        priority: 'mandatory_ack',
        ack_type: 'quiz_ack',
        quiz_json: {
          question: 'ما هي المهلة القصوى للإبلاغ عن الحوادث الأمنية؟',
          options: ['ساعة واحدة', '15 دقيقة', '24 ساعة'],
          correct_index: 1,
        },
        target_spec: {
          scope: 'custom',
          department_ids: [engDeptId],
        },
      },
    });
    assert.equal(brdRes.status, 201, JSON.stringify(brdRes.json));
    const broadcastId = brdRes.json.broadcast.id;
    assert.match(brdRes.json.broadcast.ref_no, /^BRD-\d{4}-\d{4}$/);

    // Wrong quiz answer must be rejected (400 quiz_answer_incorrect)
    const wrongAck = await callApi('POST', `/broadcasts/${broadcastId}/ack`, {
      token: employeeToken,
      body: {
        ack_type: 'quiz_ack',
        quiz_answer_index: 0,
      },
    });
    assert.equal(wrongAck.status, 400);
    assert.equal(wrongAck.json.error.code, 'quiz_answer_incorrect');

    // Correct quiz answer succeeds and resolves the Hub item
    const rightAck = await callApi('POST', `/broadcasts/${broadcastId}/ack`, {
      token: employeeToken,
      body: {
        ack_type: 'quiz_ack',
        quiz_answer_index: 1,
      },
    });
    assert.equal(rightAck.status, 200);
    assert.equal(rightAck.json.acknowledged, true);

    // Material revision (v2) resets acknowledgment requirement (BRD-05)
    const revRes = await callApi('PATCH', `/broadcasts/${broadcastId}`, {
      token: deptHeadToken,
      body: {
        title: 'تعميم محدث: بروتوكول الاستجابة للحوادث السيبرانية (نسخة 2)',
        body: 'تم تقليص مهلة الإبلاغ الفوري إلى 10 دقائق مع إرفاق السجل الجنائي.',
        change_note: 'تعديل جوهري في مهلة الإبلاغ',
        material_change: true,
      },
    });
    assert.equal(revRes.status, 200);
    assert.equal(revRes.json.broadcast.current_version, 2);

    const statsAfterRev = await callApi('GET', `/broadcasts/${broadcastId}/stats`, {
      token: deptHeadToken,
    });
    assert.equal(statsAfterRev.status, 200);
    assert.equal(
      statsAfterRev.json.acknowledged_count,
      0,
      'Material revision v2 must require fresh acknowledgments',
    );

    // Unified Arabic-aware Search across messages, decisions, followups, and broadcasts (SRCH-01..03)
    // Query with different Hamza/Ta-Marbuta forms ("الاستجابه" vs "الاستجابة", "تقرير جاهزيه")
    const searchRes = await callApi('GET', `/search?q=${encodeURIComponent('الاستجابه للحوادث')}`, {
      token: employeeToken,
    });
    assert.equal(searchRes.status, 200);
    assert.ok(searchRes.json.results.length >= 1, 'Arabic normalized search must match broadcast');
  });

  test('9. Legal Hold, Dual-Control Break-Glass, Atomic Offboarding, Selective Wipe & Tamper-Evident Audit Chain (ADM-05..10, WIPE-01..04)', async () => {
    const cpHeaders = { 'X-Madar-Control-Plane-Key': process.env.ADMIN_PLANE_SECRET };

    // 9a. Place Legal Hold on employeeUser (ADM-06)
    const holdRes = await callApi('POST', '/admin/legal-holds', {
      token: complianceToken,
      headers: cpHeaders,
      body: {
        scope_type: 'user',
        scope_id: String(employeeUser.id),
        matter_ref: 'LGL-2026-099',
        reason: 'تحقيق امتثال داخلي روتيني',
      },
    });
    assert.equal(holdRes.status, 201);

    // 9b. Dual-Control Break-Glass (ADM-07): Initiator cannot self-approve
    const bgInit = await callApi('POST', '/admin/break-glass', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        reason: 'فحص طارئ لسجلات قناة المشروع',
        scope: 'channel:project-madar-1',
        duration_minutes: 30,
      },
    });
    assert.equal(bgInit.status, 201);
    const bgId = bgInit.json.break_glass.id;

    const selfApprove = await callApi('POST', `/admin/break-glass/${bgId}/approve`, {
      token: superAdminToken,
      headers: cpHeaders,
    });
    assert.equal(selfApprove.status, 403);
    assert.equal(selfApprove.json.error.code, 'dual_control_violation');

    // Independent second actor (COMPLIANCE_OFFICER) approves Break-Glass
    const secondApprove = await callApi('POST', `/admin/break-glass/${bgId}/approve`, {
      token: complianceToken,
      headers: cpHeaders,
    });
    assert.equal(secondApprove.status, 200);
    assert.equal(secondApprove.json.break_glass.status, 'active');

    // 9c. Atomic Offboarding (ADM-08): revokes tokens, marks device wipe_pending, transfers open followups to department head
    const offboardRes = await callApi('POST', `/admin/users/${employeeUser.id}/offboard`, {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        reason: 'انتهاء فترة التكليف ونقل المهام لرئيس القسم',
      },
    });
    assert.equal(offboardRes.status, 200);
    assert.equal(offboardRes.json.devices_marked_wipe_pending.length, 1);
    assert.equal(offboardRes.json.transferred_followups_count, 1);
    assert.equal(offboardRes.json.transferred_to_user_id, deptHeadUserId);

    // Offboarded employee's token must now be rejected (401/403)
    const postOffboardCall = await callApi('GET', '/hub', { token: employeeToken });
    assert.ok([401, 403].includes(postOffboardCall.status));

    // 9d. Cryptographic Selective Wipe Acknowledgment (WIPE-03) signed with device Ed25519 private key
    const wipePayload = `wipe:${employeeDeviceId}:${workspaceId}`;
    const wipeSig = employeeDeviceKeys.sign(wipePayload);
    const wipeAckRes = await callApi('POST', `/devices/${employeeDeviceId}/wipe-ack`, {
      body: {
        payload: wipePayload,
        signature: wipeSig,
      },
    });
    assert.equal(wipeAckRes.status, 200, JSON.stringify(wipeAckRes.json));
    assert.equal(wipeAckRes.json.device.status, 'wiped');

    // 9e. Verify SHA-256 Tamper-Evident Audit Chain (ADM-05)
    const verifyRes = await callApi('GET', '/admin/audit-log/verify', {
      token: complianceToken,
      headers: cpHeaders,
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.json.verification.valid, true);
    assert.ok(verifyRes.json.verification.checkedCount >= 10);

    // 9f. Verify CSV Formula Injection Protection (Section 13.6)
    assert.equal(sanitizeCsvCell('=cmd|\'/C calc\'!A0'), '"\'=cmd|\'/C calc\'!A0"');
    assert.equal(sanitizeCsvCell('+SUM(A1:A2)'), '"\'+SUM(A1:A2)"');
    assert.equal(sanitizeCsvCell('@IMPORTXML()'), '"\'@IMPORTXML()"');

    const csvExportRes = await callApi('GET', '/admin/audit-log/export?format=csv', {
      token: complianceToken,
      headers: cpHeaders,
    });
    assert.equal(csvExportRes.status, 200);
    assert.match(String(csvExportRes.json), /^id,created_at,action,/);

    // 9g. Verify madarctl CLI commands programmatically (ADM-10)
    const doctorOut = await runMadarCtl(['doctor']);
    assert.equal(doctorOut.ok, true);
    assert.equal(doctorOut.audit_chain_valid, true);

    const rotateOut = await runMadarCtl(['rotate-keys']);
    assert.ok(rotateOut.kid);
    assert.ok(rotateOut.publicKeyEd25519);
  });

  test('10. Argon2id Password Hashing (NFR-09), Separation of Duties Role Conflict (Section 5.3), & First-Frame WebSocket Auth (Section 9.2)', async () => {
    const cpHeaders = { 'X-Madar-Control-Plane-Key': process.env.ADMIN_PLANE_SECRET };

    // 10a. Verify stored password hashes use Argon2id ($argon2id$v=19$...)
    const credRow = await db.query(
      'SELECT password_hash FROM credentials WHERE user_id = $1',
      [superAdminUser.id],
    );
    assert.match(
      credRow.rows[0].password_hash,
      /^\$argon2id\$v=19\$m=/,
      'Credentials must be hashed with Argon2id (NFR-09)',
    );

    // 10b. Separation of Duties: assigning both IT_ADMIN and COMPLIANCE_OFFICER to the same user must fail with 400 sod_role_conflict
    const sodConflictRes = await callApi('POST', '/admin/users', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        employee_no: 'SOD-999',
        name: 'مستخدم متعارض الصلاحيات',
        email: 'sod@madar.gov.sa',
        department_id: engDeptId,
        roles: ['IT_ADMIN', 'COMPLIANCE_OFFICER'],
      },
    });
    assert.equal(sodConflictRes.status, 400);
    assert.equal(sodConflictRes.json.error.code, 'sod_role_conflict');

    // 10c. WebSocket First-Frame Authentication without ?token= in URL query string (Section 9.2)
    const { WebSocket } = await import('ws');
    const wsUrl = base.replace(/^http/, 'ws') + '/ws';
    const authAck = await new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      const timer = setTimeout(() => {
        ws.close();
        reject(new Error('WebSocket first-frame auth timed out'));
      }, 4000);
      ws.on('open', () => {
        ws.send(JSON.stringify({ t: 'auth', token: superAdminToken }));
      });
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.t === 'hello' || msg.t === 'auth.ok') {
          clearTimeout(timer);
          ws.close();
          resolve(msg);
        }
      });
      ws.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
    assert.equal(authAck.authenticated, true);
    assert.equal(authAck.user_id, superAdminUser.id);
  });

  test('11. Cloud Services Config (ADM-02), Official Domain Verification (ENR-06), & Blind Push/SMS Relay (Section 4.5)', async () => {
    const cpHeaders = { 'X-Madar-Control-Plane-Key': process.env.ADMIN_PLANE_SECRET };
    const tenantToken = 'madar-tenant-relay-token-2026-secret';

    // 11a. Configure Cloud Services & Official Domain
    const cfgRes = await callApi('PUT', '/admin/cloud-services', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        official_domain: 'madar.gov.sa',
        push_relay_enabled: true,
        relay_url: base,
        tenant_token: tenantToken,
        sms_provider: 'madar_relay',
      },
    });
    assert.equal(cfgRes.status, 200, JSON.stringify(cfgRes.json));
    assert.equal(cfgRes.json.cloud_services.official_domain, 'madar.gov.sa');
    assert.match(cfgRes.json.cloud_services.dns_txt_expected, /^madar-domain-verify=/);

    // 11b. Verify domain with DNS TXT token proof (ENR-06)
    const verifyDomRes = await callApi('POST', '/admin/cloud-services/verify-domain', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        simulated_txt_record: cfgRes.json.cloud_services.dns_txt_expected,
      },
    });
    assert.equal(verifyDomRes.status, 200, JSON.stringify(verifyDomRes.json));
    assert.equal(verifyDomRes.json.domain_verified, true);

    const discoveryRes = await callApi('GET', '/server/info');
    assert.equal(discoveryRes.json.official_domain, 'madar.gov.sa');
    assert.equal(discoveryRes.json.domain_verified, true);
    assert.equal(discoveryRes.json.cloud_relay_enabled, true);

    // 11c. Register an opaque 128-bit Push Handle on the Blind Relay (POST /v1/handles)
    const handleRes = await fetch(`${base}/v1/handles`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        platform: 'android',
        native_token: 'fcm-device-secret-token-xyz-987654',
      }),
    }).then(async (r) => ({ status: r.status, json: await r.json() }));

    assert.equal(handleRes.status, 201, JSON.stringify(handleRes.json));
    assert.match(handleRes.json.push_handle, /^rel_[0-9a-f]{32}$/);
    const pushHandle = handleRes.json.push_handle;

    // 11d. Blind Relay MUST reject any wake request containing message content or PII (Section 4.5.2)
    const piiLeakWake = await fetch(`${base}/v1/wake`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${tenantToken}`,
      },
      body: JSON.stringify({
        push_handle: pushHandle,
        wake_signal: {
          vault_id: workspaceId,
          body: 'سري للغاية: تفاصيل الاجتماع',
        },
      }),
    }).then(async (r) => ({ status: r.status, json: await r.json() }));

    assert.equal(piiLeakWake.status, 400);
    assert.equal(piiLeakWake.json.error.code, 'relay_content_violation');

    // 11e. Valid zero-payload wake signal succeeds
    const validWake = await fetch(`${base}/v1/wake`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${tenantToken}`,
      },
      body: JSON.stringify({
        push_handle: pushHandle,
        wake_signal: {
          vault_id: workspaceId,
          sync_hint: 'urgent',
          priority: 'high',
        },
      }),
    }).then(async (r) => ({ status: r.status, json: await r.json() }));

    assert.equal(validWake.status, 200, JSON.stringify(validWake.json));
    assert.equal(validWake.json.success, true);
    assert.equal(validWake.json.blind_envelope.t, 'wake');
  });

  test('12. Enterprise SSO (OIDC/SAML/LDAP), 15-Min Directory Sync Offboarding (AUTH-01, AUTH-06), Confidential E2EE Channels (MSG-05), & Break-Glass Inspection (AUD-02)', async () => {
    const cpHeaders = { 'X-Madar-Control-Plane-Key': process.env.ADMIN_PLANE_SECRET };

    // 12a. Create an Active Directory (LDAP) Auth Provider with directory snapshot for sync
    const ldapProviderRes = await callApi('POST', '/admin/auth-providers', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        kind: 'ldap',
        name: 'Active Directory — الهيئة السيادية',
        enabled: true,
        sync_interval_minutes: 15,
        config: {
          ldap_url: 'ldaps://ad.madar.gov.sa:636',
          base_dn: 'DC=madar,DC=gov,DC=sa',
          directory_entries: [
            {
              external_id: 'ad-user-501',
              employee_no: 'AD-501',
              username: 'reem.zahrani',
              password: 'AdBind#2026!Password',
              name: 'م. ريم الزهراني',
              email: 'reem@madar.gov.sa',
              title: 'مهندسة أمن معلومات',
              department_code: 'SECOPS',
              active: true,
            },
          ],
        },
      },
    });
    assert.equal(ldapProviderRes.status, 201, JSON.stringify(ldapProviderRes.json));
    const ldapProviderId = ldapProviderRes.json.provider.id;

    // 12b. Run Directory Sync: provisions AD-501 automatically
    const sync1Res = await callApi('POST', `/admin/auth-providers/${ldapProviderId}/sync`, {
      token: superAdminToken,
      headers: cpHeaders,
    });
    assert.equal(sync1Res.status, 200, JSON.stringify(sync1Res.json));
    assert.equal(sync1Res.json.sync.provisioned_count, 1);

    // 12c. SSO Login as AD-501 via LDAP bind and enroll a device
    const ssoLoginRes = await callApi('POST', '/auth/sso/login', {
      body: {
        provider_id: ldapProviderId,
        ldap_username: 'reem.zahrani',
        ldap_password: 'AdBind#2026!Password',
        device_name: 'Reem Corp Workstation',
        platform: 'desktop',
        device_pub_key: generateEd25519DeviceKeyPair().pubKeyB64Url,
      },
    });
    assert.equal(ssoLoginRes.status, 200, JSON.stringify(ssoLoginRes.json));
    const reemToken = ssoLoginRes.json.access_token;
    const reemUserId = ssoLoginRes.json.user.id;

    // 12d. Create a Confidential E2EE Channel (MSG-05, Section 10.2)
    const e2eeChRes = await callApi('POST', '/channels', {
      token: deptHeadToken,
      body: {
        kind: 'private_group',
        name: 'غرفة العمليات السيادية المشفرة طرفياً',
        privacy_mode: 'confidential_e2ee',
        member_ids: [reemUserId],
      },
    });
    assert.equal(e2eeChRes.status, 201, JSON.stringify(e2eeChRes.json));
    assert.equal(e2eeChRes.json.channel.privacy_mode, 'confidential_e2ee');
    const e2eeChannelId = e2eeChRes.json.channel.id;

    // Post an E2EE envelope message in the confidential channel
    const e2eeMsgRes = await callApi('POST', `/channels/${e2eeChannelId}/messages`, {
      token: deptHeadToken,
      body: {
        e2ee_envelope: {
          alg: 'X25519-AES256GCM',
          epoch: 1,
          ciphertext: 'bWFkYXItZTJlZS1jaXBoZXJ0ZXh0LXBheWxvYWQ=',
          iv: 'MTIzNDU2Nzg5MDEy',
        },
      },
    });
    assert.equal(e2eeMsgRes.status, 201, JSON.stringify(e2eeMsgRes.json));
    assert.equal(e2eeMsgRes.json.message.body, '');
    assert.equal(e2eeMsgRes.json.message.e2ee_envelope.alg, 'X25519-AES256GCM');

    // 12e. Dual-Control Break-Glass Inspection (AUD-02): inspects governed user messages while keeping confidential_e2ee opaque
    const bgDeptHead = await callApi('POST', '/admin/break-glass', {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        reason: 'فحص الامتثال لسجلات الرسائل الحساسة',
        scope: `user:${deptHeadUserId}`,
        duration_minutes: 30,
      },
    });
    assert.equal(bgDeptHead.status, 201);
    const bgId2 = bgDeptHead.json.break_glass.id;

    await callApi('POST', `/admin/break-glass/${bgId2}/approve`, {
      token: complianceToken,
      headers: cpHeaders,
    });

    const inspectRes = await callApi('GET', `/admin/break-glass/${bgId2}/inspect`, {
      token: complianceToken,
      headers: cpHeaders,
    });
    assert.equal(inspectRes.status, 200, JSON.stringify(inspectRes.json));
    assert.ok(inspectRes.json.records.messages.length >= 2);
    const e2eeInspected = inspectRes.json.records.messages.find((m) => m.channel_id === e2eeChannelId);
    assert.ok(e2eeInspected);
    assert.equal(e2eeInspected.e2ee_protected, true);
    assert.equal(
      e2eeInspected.body,
      null,
      'Break-Glass must never expose plaintext of confidential_e2ee channels',
    );

    // 12f. Simulate disabling AD-501 in Active Directory and running Directory Sync (AUTH-06)
    const sync2Res = await callApi('POST', `/admin/auth-providers/${ldapProviderId}/sync`, {
      token: superAdminToken,
      headers: cpHeaders,
      body: {
        directory_entries: [
          {
            external_id: 'ad-user-501',
            employee_no: 'AD-501',
            username: 'reem.zahrani',
            name: 'م. ريم الزهراني',
            email: 'reem@madar.gov.sa',
            department_code: 'SECOPS',
            active: false,
          },
        ],
      },
    });
    assert.equal(sync2Res.status, 200, JSON.stringify(sync2Res.json));
    assert.equal(sync2Res.json.sync.disabled_count, 1);
    assert.equal(sync2Res.json.sync.wiped_devices.length, 1);

    // Reem's session is immediately revoked and device marked wipe_pending
    const reemCheck = await callApi('GET', '/hub', { token: reemToken });
    assert.ok([401, 403].includes(reemCheck.status));

    // Reset ADMIN_PLANE_SECRET so any other tests in the process aren't affected
    delete process.env.ADMIN_PLANE_SECRET;
  });
});
