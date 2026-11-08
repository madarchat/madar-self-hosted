#!/usr/bin/env node
/**
 * Seeds a demonstration workspace into a fresh Madar Enterprise deployment.
 *
 *   node bin/seed-demo.js
 *   node bin/seed-demo.js --org "مجموعة آفاق" --domain afaq.example
 *
 * Intended for evaluation, demos and local development. A real deployment is
 * initialised through the admin console's `/setup` wizard, which also
 * generates the Ed25519 policy signing key and locks itself afterwards.
 *
 * Refuses to run against a database that already has a workspace, so it can
 * never overwrite a live tenant.
 */
import crypto from 'node:crypto';
import process from 'node:process';
import { db, closePool } from '../madar_server/src/db/pool.js';
import { runMigrations } from '../madar_server/src/db/migrate.js';
import { hashPassword } from '../madar_server/src/lib/password.js';
import { sha256 } from '../madar_server/src/lib/tokens.js';
import { encryptField } from '../madar_server/src/lib/fieldCrypto.js';
import { env } from '../madar_server/src/config/env.js';

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const ORG = arg('org', 'مجموعة آفاق المستقبل القابضة');
const ADMIN_PASSWORD = arg('admin-password', 'Madar#Admin2026');
const STAFF_PASSWORD = arg('staff-password', 'Madar#Staff2026');
const ENROLLMENT_TOKEN = arg('token', 'MADAR-ENR-DEMO-0001');

const DEPARTMENTS = [
  { name: 'الإدارة التنفيذية', code: 'EXEC' },
  { name: 'إدارة تطوير الأنظمة والمنتجات', code: 'ENG' },
  { name: 'الموارد البشرية', code: 'HR' },
  { name: 'الشؤون المالية', code: 'FIN' },
];

const STAFF = [
  { employee_no: 'EMP-100', name: 'أ. نورة السبيعي', title: 'الرئيس التنفيذي', dept: 'EXEC', role: 'SUPER_ADMIN' },
  { employee_no: 'EMP-201', name: 'م. سلطان الدوسري', title: 'مدير تطوير الأنظمة والمنصات', dept: 'ENG', role: 'DEPT_HEAD' },
  { employee_no: 'EMP-202', name: 'أ. ريم القحطاني', title: 'مهندسة جودة أولى', dept: 'ENG', role: 'MEMBER' },
  { employee_no: 'EMP-301', name: 'أ. هند الزهراني', title: 'مديرة الموارد البشرية', dept: 'HR', role: 'DEPT_HEAD' },
];

async function main() {
  await runMigrations();

  const existing = await db.one('SELECT id, name FROM workspace LIMIT 1');
  if (existing && process.argv.includes('--force') === false && existing.name !== 'docker') {
    console.error(
      `Refusing to seed: workspace "${existing.name}" already exists.\n` +
        'Pass --force only against a database you are willing to overwrite.',
    );
    process.exitCode = 1;
    return;
  }

  const summary = await db.tx(async (c) => {
    // One workspace per deployment: this is a single-tenant sovereign server.
    // Remove users first — `workspace` does not cascade to them, and leaving
    // stale rows behind would carry their enrolled devices into the new seed
    // and immediately exhaust the device-per-user policy.
    // Order matters: message and governance rows reference users with
    // RESTRICT, which is correct for a system of record — you cannot delete
    // an author out from under an audit trail. Reseeding clears the content
    // first, deliberately and in dependency order.
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
      await c.query(`DELETE FROM ${table}`);
    }
    const ws = (
      await c.query(
        `INSERT INTO workspace (name, primary_color, locale, timezone, deployment_profile, setup_completed)
         VALUES ($1, '#0F766E', 'ar', 'Asia/Riyadh', 'workspace', TRUE)
         RETURNING id`,
        [ORG],
      )
    ).rows[0];

    const deptIds = {};
    for (const [i, d] of DEPARTMENTS.entries()) {
      const row = (
        await c.query(
          `INSERT INTO departments (workspace_id, name, code, sort_order)
           VALUES ($1, $2, $3, $4) RETURNING id`,
          [ws.id, d.name, d.code, i],
        )
      ).rows[0];
      deptIds[d.code] = row.id;
    }

    const adminHash = hashPassword(ADMIN_PASSWORD);
    const staffHash = hashPassword(STAFF_PASSWORD);

    const userIds = {};
    for (const person of STAFF) {
      const user = (
        await c.query(
          `INSERT INTO users (name, employee_no, title, email, workspace_id, department_id,
                              profile_type, account_status, accent)
           VALUES ($1, $2, $3, $4, $5, $6, 'workspace', 'active', 'teal')
           RETURNING id`,
          [
            person.name,
            person.employee_no,
            person.title,
            `${person.employee_no.toLowerCase()}@${arg('domain', 'example.local')}`,
            ws.id,
            deptIds[person.dept],
          ],
        )
      ).rows[0];
      userIds[person.employee_no] = user.id;

      await c.query(
        'INSERT INTO credentials (user_id, password_hash, must_change_password) VALUES ($1, $2, FALSE)',
        [user.id, person.role === 'SUPER_ADMIN' ? adminHash : staffHash],
      );
      await c.query('INSERT INTO user_roles (user_id, role) VALUES ($1, $2)', [user.id, person.role]);
    }

    // Each department gets its official channel, plus one organization-wide.
    const ownerId = userIds['EMP-100'];
    await c.query(
      `INSERT INTO channels (workspace_id, kind, name, purpose, posting_mode, created_by)
       VALUES ($1, 'announcement', 'التعاميم الرسمية', 'قناة التعاميم الرسمية لمساحة العمل — النشر للإدارة فقط', 'moderators_only', $2)`,
      [ws.id, ownerId],
    );
    for (const d of DEPARTMENTS) {
      await c.query(
        `INSERT INTO channels (workspace_id, kind, name, purpose, department_id, posting_mode, created_by)
         VALUES ($1, 'department', $2, $3, $4, 'all', $5)`,
        [ws.id, d.name, `قناة ${d.name}`, deptIds[d.code], ownerId],
      );
    }

    // Governance content, so a freshly seeded workspace demonstrates what the
    // product is actually for rather than opening on empty tabs.
    const orgChannel = (
      await c.query(`SELECT id FROM channels WHERE workspace_id = $1 AND kind = 'announcement' LIMIT 1`, [ws.id])
    ).rows[0];
    const engChannel = (
      await c.query(`SELECT id FROM channels WHERE workspace_id = $1 AND department_id = $2 LIMIT 1`, [
        ws.id,
        deptIds.ENG,
      ])
    ).rows[0];

    const broadcasts = [
      {
        ref: 'BRD-2026-001',
        title: 'سياسة التعامل مع المرفقات والبريد الإلكتروني',
        priority: 'mandatory_ack',
        ack: 'scroll_ack',
        body: 'يُمنع إرسال مرفقات العمل عبر البريد الإلكتروني الشخصي. جميع الملفات تُتداول داخل مدار حصراً.',
      },
      {
        ref: 'BRD-2026-002',
        title: 'تحديث إجراءات الوصول عن بُعد',
        priority: 'important',
        ack: 'one_tap',
        body: 'تم تفعيل التحقق بخطوتين على جميع حسابات الوصول عن بُعد اعتباراً من بداية الشهر.',
      },
    ];
    for (const b of broadcasts) {
      const row = (
        await c.query(
          `INSERT INTO broadcasts (workspace_id, ref_no, sender_id, title, priority, ack_type,
                                   ack_deadline, published_at, created_by, status)
           VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '7 days', NOW(), $3, 'published')
           RETURNING id`,
          [ws.id, b.ref, ownerId, b.title, b.priority, b.ack],
        )
      ).rows[0];
      // Encrypted with the server's own field key, exactly as a real
      // broadcast is, so the API can decrypt and render it.
      const sealed = encryptField(b.body);
      await c.query(
        `INSERT INTO broadcast_versions (broadcast_id, version_no, title, body_ciphertext, body_iv, key_id, created_by)
         VALUES ($1, 1, $2, $3, $4, $5, $6)`,
        [row.id, b.title, sealed.ciphertext, sealed.iv, sealed.keyId, ownerId],
      );
      for (const uid of Object.values(userIds)) {
        await c.query(
          'INSERT INTO broadcast_recipients (broadcast_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [row.id, uid],
        );
      }
    }

    await c.query(
      `INSERT INTO decisions (workspace_id, channel_id, title, rationale, owner_user_id, status, created_by)
       VALUES ($1, $2, $3, $4, $5, 'active', $5)`,
      [
        ws.id,
        engChannel?.id || orgChannel.id,
        'اعتماد مدار كقناة التواصل الرسمية بدلاً من البريد',
        'تقليل مخاطر تسريب المرفقات عبر البريد الإلكتروني وتوحيد سجل القرارات.',
        ownerId,
      ],
    );

    await c.query(
      `INSERT INTO followups (workspace_id, channel_id, title, assignee_user_id, due_at, status, created_by)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '14 days', 'open', $5)`,
      [
        ws.id,
        engChannel?.id || orgChannel.id,
        'ترحيل قوائم التوزيع البريدية إلى قنوات مدار',
        userIds['EMP-201'],
        ownerId,
      ],
    );

    // Everyone belongs to the organization-wide channel; each employee to
    // their department's. The engineering channel opens with a short real
    // exchange and a pinned reference, so a fresh workspace shows the
    // institutional memory the product is about.
    const allChannels = await c.query(
      'SELECT id, kind, department_id FROM channels WHERE workspace_id = $1',
      [ws.id],
    );
    for (const person of STAFF) {
      const uid = userIds[person.employee_no];
      for (const ch of allChannels.rows) {
        if (ch.kind === 'announcement' || ch.department_id === deptIds[person.dept]) {
          await c.query(
            `INSERT INTO channel_members (channel_id, user_id, role) VALUES ($1, $2, 'member')
             ON CONFLICT (channel_id, user_id) DO NOTHING`,
            [ch.id, uid],
          );
        }
      }
    }

    if (engChannel) {
      const say = async (employeeNo, text) => {
        const seq = (await c.query('UPDATE channels SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq', [engChannel.id])).rows[0].last_seq;
        const enc = encryptField(text);
        await c.query(
          `INSERT INTO channel_messages (channel_id, seq, sender_id, msg_type, body_ciphertext, body_iv, key_id)
           VALUES ($1, $2, $3, 'text', $4, $5, $6)`,
          [engChannel.id, seq, userIds[employeeNo], enc.ciphertext, enc.iv, enc.keyId],
        );
      };
      await say('EMP-201', 'صباح الخير فريق التطوير. نبدأ اليوم ترحيل قوائم البريد إلى قنوات مدار.');
      await say('EMP-202', 'تمام. جهّزت قائمة المرفقات المتداولة بالبريد خلال الربع الماضي للمراجعة.');
      await c.query(
        `INSERT INTO channel_references (channel_id, workspace_id, title, kind, url, description, created_by, added_by)
         VALUES ($1, $2, $3, 'link', $4, $5, $6, $6)`,
        [
          engChannel.id,
          ws.id,
          'دليل الانتقال من البريد إلى مدار',
          'https://docs.protosoftdev.online/ar/channels-and-privacy',
          'المرجع المعتمد لتصنيف القنوات وسياسة المرفقات',
          userIds['EMP-201'],
        ],
      );
    }

    // A multi-use enrollment token so the app can be demonstrated repeatedly.
    await c.query(
      `INSERT INTO enrollment_tokens (workspace_id, token_hash, max_uses, expires_at, created_by)
       VALUES ($1, $2, 99, NOW() + INTERVAL '365 days', $3)`,
      [ws.id, sha256(ENROLLMENT_TOKEN), ownerId],
    );

    return { workspaceId: ws.id, users: Object.keys(userIds).length };
  });

  const serverUrl = env.PUBLIC_URL || `http://localhost:${env.PORT}`;
  const enrollUri =
    `madar://enroll?server=${encodeURIComponent(serverUrl)}` +
    `&token=${encodeURIComponent(ENROLLMENT_TOKEN)}` +
    `&workspace=${encodeURIComponent(summary.workspaceId)}` +
    `&name=${encodeURIComponent(ORG)}`;

  console.log(`
  Workspace seeded
  ----------------
  Organization   ${ORG}
  Workspace id   ${summary.workspaceId}
  Departments    ${DEPARTMENTS.length}
  Employees      ${summary.users}
  Server         ${serverUrl}

  Sign in
    Admin   EMP-100 / ${ADMIN_PASSWORD}
    Staff   EMP-201, EMP-202, EMP-301 / ${STAFF_PASSWORD}

  Enrollment link (scan or paste into the app)
    ${enrollUri}

  These are demonstration credentials. Rotate them before exposing this
  server to anyone outside your machine.
`);
}

main()
  .then(closePool)
  .catch(async (err) => {
    console.error(err);
    await closePool();
    process.exit(1);
  });
