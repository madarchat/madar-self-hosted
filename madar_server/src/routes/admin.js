import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { Router } from 'express';
import { env } from '../config/env.js';
import { db } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import {
  attachPolicyContext,
  requireRoles,
  assertPolicyEditPermission,
} from '../middleware/policyGuard.js';
import { validate, z } from '../lib/validate.js';
import { badRequest, forbidden, notFound } from '../lib/errors.js';
import { hashPassword, validatePasswordComplexity } from '../lib/password.js';
import { encryptField, decryptField } from '../lib/fieldCrypto.js';
import { sha256 } from '../lib/tokens.js';
import { signEd25519Jws, ensureWorkspaceSigningKey, rotateWorkspaceSigningKey } from '../lib/jws.js';
import {
  getPolicyCatalog,
  validatePolicyEntryValue,
  ensureDefaultWorkspace,
  previewPolicyImpact,
  publishPolicyVersion,
  buildSignedPolicyBundle,
} from '../services/policyEngine.js';
import { appendAuditLog, verifyAuditChain } from '../lib/audit.js';
import { sendToUser, sendToUsers, disconnectUser } from '../realtime/ws.js';

export const adminRouter = Router();

/**
 * POST /api/v1/admin/setup — 6-Step First-Boot Setup Wizard (ADM-01).
 * Accessible unauthenticated ONLY when workspace.setup_completed === false; otherwise requires SUPER_ADMIN.
 */
adminRouter.post(
  '/setup',
  validate({
    body: z.object({
      workspace_name: z.string().trim().min(2).max(160),
      logo_url: z.string().trim().max(500).optional(),
      primary_color: z.string().trim().regex(/^#[0-9A-Fa-f]{6}$/).default('#0F766E'),
      locale: z.string().trim().max(10).default('ar'),
      timezone: z.string().trim().max(64).default('Asia/Riyadh'),
      deployment_profile: z.enum(['workspace', 'hybrid', 'personal']).default('workspace'),
      policy_preset: z.enum(['standard', 'regulated', 'defense']).default('standard'),
      admin_user: z
        .object({
          employee_no: z.string().trim().min(1).max(64).default('ADMIN-001'),
          name: z.string().trim().min(2).max(120),
          email: z.string().email(),
          work_phone: z.string().trim().max(32).optional(),
          title: z.string().trim().max(120).default('مدير النظام السيادي'),
          password: z.string().min(10).max(255),
        })
        .optional(),
      departments: z
        .array(
          z.object({
            name: z.string().trim().min(1).max(120),
            code: z.string().trim().min(1).max(40),
          }),
        )
        .max(50)
        .default([]),
      server_url: z.string().trim().max(500).optional(),
    }),
  }),
  async (req, res, next) => {
    try {
      const ws = await ensureDefaultWorkspace();
      if (ws.setup_completed) {
        // Require SUPER_ADMIN if setup was already completed
        await new Promise((resolve, reject) => {
          requireAuth(req, res, (err) => (err ? reject(err) : resolve()));
        });
        if (!(req.auth.roles || []).includes('SUPER_ADMIN')) {
          throw forbidden('super_admin_required', 'تم إكمال الإعداد الأولي مسبقاً، يتطلب التعديل صلاحية SUPER_ADMIN');
        }
      }

      const {
        workspace_name,
        logo_url,
        primary_color,
        locale,
        timezone,
        deployment_profile,
        policy_preset,
        admin_user,
        departments,
        server_url,
      } = req.body;

      if (admin_user) {
        const pwCheck = validatePasswordComplexity(admin_user.password, 10);
        if (!pwCheck.valid) throw badRequest('weak_password', pwCheck.reason);
      }

      const result = await db.tx(async (client) => {
        const { rows: wsRows } = await client.query(
          `UPDATE workspace
           SET name = $2,
               logo_url = COALESCE($3, logo_url),
               primary_color = $4,
               locale = $5,
               timezone = $6,
               deployment_profile = $7,
               setup_completed = TRUE
           WHERE id = $1
           RETURNING *`,
          [
            ws.id,
            workspace_name,
            logo_url || null,
            primary_color,
            locale,
            timezone,
            deployment_profile,
          ],
        );
        const updatedWs = wsRows[0];

        let createdAdmin = null;
        if (admin_user) {
          const existingAdmin = await client.query(
            `SELECT * FROM users
             WHERE workspace_id = $1 AND (employee_no = $2 OR LOWER(email) = LOWER($3))
             LIMIT 1`,
            [ws.id, admin_user.employee_no, admin_user.email],
          );

          if (existingAdmin.rows[0]) {
            const { rows: uRows } = await client.query(
              `UPDATE users
               SET name = $2, email = $3, title = $4, account_status = 'active', profile_type = 'workspace'
               WHERE id = $1
               RETURNING *`,
              [existingAdmin.rows[0].id, admin_user.name, admin_user.email, admin_user.title],
            );
            createdAdmin = uRows[0];
          } else {
            const { rows: uRows } = await client.query(
              `INSERT INTO users (
                 workspace_id, employee_no, email, work_phone, name, title,
                 account_status, profile_type, last_seen_at
               ) VALUES ($1, $2, $3, $4, $5, $6, 'active', 'workspace', NOW())
               RETURNING *`,
              [
                ws.id,
                admin_user.employee_no,
                admin_user.email,
                admin_user.work_phone || null,
                admin_user.name,
                admin_user.title,
              ],
            );
            createdAdmin = uRows[0];
          }

          await client.query(
            `INSERT INTO credentials (user_id, password_hash, must_change_password, password_changed_at)
             VALUES ($1, $2, FALSE, NOW())
             ON CONFLICT (user_id) DO UPDATE
             SET password_hash = EXCLUDED.password_hash, must_change_password = FALSE`,
            [createdAdmin.id, hashPassword(admin_user.password)],
          );

          await client.query(
            "INSERT INTO user_roles (user_id, role) VALUES ($1, 'SUPER_ADMIN') ON CONFLICT DO NOTHING",
            [createdAdmin.id],
          );
        }

        const createdDepts = [];
        for (let i = 0; i < departments.length; i += 1) {
          const d = departments[i];
          const { rows: dRows } = await client.query(
            `INSERT INTO departments (workspace_id, name, code, sort_order)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (workspace_id, code) DO UPDATE SET name = EXCLUDED.name
             RETURNING *`,
            [ws.id, d.name, d.code, i + 1],
          );
          const dept = dRows[0];

          const { rows: chRows } = await client.query(
            `INSERT INTO channels (workspace_id, kind, name, description, department_id, created_by)
             VALUES ($1, 'department', $2, $3, $4, $5)
             RETURNING *`,
            [
              ws.id,
              `قناة ${dept.name}`,
              `القناة الرسمية لقسم ${dept.name}`,
              dept.id,
              createdAdmin?.id || null,
            ],
          );
          await client.query('UPDATE departments SET channel_id = $2 WHERE id = $1', [
            dept.id,
            chRows[0].id,
          ]);
          createdDepts.push({ ...dept, channel_id: chRows[0].id });
        }

        if (createdAdmin && createdDepts.length > 0 && !createdAdmin.department_id) {
          await client.query('UPDATE users SET department_id = $2 WHERE id = $1', [
            createdAdmin.id,
            createdDepts[0].id,
          ]);
          createdAdmin.department_id = createdDepts[0].id;
        }

        // Provision default organization-wide public channels on initial setup
        const { rows: existingPub } = await client.query(
          "SELECT id FROM channels WHERE workspace_id = $1 AND kind IN ('public_channel', 'broadcast_feed') LIMIT 1",
          [ws.id],
        );
        if (existingPub.length === 0) {
          await client.query(
            `INSERT INTO channels (workspace_id, kind, name, description, posting_mode, created_by)
             VALUES
               ($1, 'public_channel', 'عام — الساحة العامة', 'القناة العامة لتواصل جميع فرق وإدارات مساحة العمل', 'all', $2),
               ($1, 'broadcast_feed', 'الإعلانات والقرارات الرسمية', 'القناة الرسمية للقرارات المعتمدة والتعاميم التنظيمية', 'moderators_only', $2)`,
            [ws.id, createdAdmin?.id || null],
          );
        }

        if (createdAdmin) {
          const { rows: allWsChannels } = await client.query(
            'SELECT id FROM channels WHERE workspace_id = $1',
            [ws.id],
          );
          for (const ch of allWsChannels) {
            await client.query(
              `INSERT INTO channel_members (channel_id, user_id, role)
               VALUES ($1, $2, 'moderator') ON CONFLICT DO NOTHING`,
              [ch.id, createdAdmin.id],
            );
          }
        }

        // Apply policy preset overrides if regulated or defense
        if (policy_preset === 'regulated' || policy_preset === 'defense') {
          const presetEntries = [
            ['auth.mfa_required', 'all', true],
            ['dlp.allow_copy_paste', false, true],
            ['dlp.allow_external_share', false, true],
            ['dlp.allow_screenshot', false, true],
            ['dlp.watermark_enabled', true, true],
            ['dlp.require_biometric_unlock', true, true],
            ['chat.allow_external_guests', false, true],
          ];
          if (policy_preset === 'defense') {
            presetEntries.push(
              ['device.require_attestation', true, true],
              ['device.max_per_user', 1, true],
              ['chat.allow_message_delete', 'none', true],
              ['chat.allow_voice_notes', false, true],
            );
          }

          for (const [k, v, locked] of presetEntries) {
            await client.query(
              `INSERT INTO policy_entries (
                 workspace_id, scope_type, scope_id, key, value_json, locked, updated_by
               ) VALUES ($1, 'workspace', $2, $3, $4::jsonb, $5, $6)
               ON CONFLICT (workspace_id, scope_type, scope_id, key) DO UPDATE
               SET value_json = EXCLUDED.value_json, locked = EXCLUDED.locked, updated_at = NOW()`,
              [ws.id, ws.id, k, JSON.stringify(v), locked, createdAdmin?.id || null],
            );
          }
        }

        return { workspace: updatedWs, admin: createdAdmin, departments: createdDepts };
      });

      const signingKey = await ensureWorkspaceSigningKey(ws.id);

      // Issue an initial organization-wide multi-use enrollment token so admins can onboard employees right away
      const rawToken = `MADAR-ENR-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
      const tokenHash = sha256(rawToken);
      const expiresAt = new Date(Date.now() + 168 * 3_600_000); // 7 days
      const jwsCompact = signEd25519Jws(
        {
          typ: 'madar.enrollment.v1',
          workspace_id: ws.id,
          token_hash: tokenHash,
          target_user_id: null,
          default_group_id: null,
          max_uses: 100,
          exp: Math.floor(expiresAt.getTime() / 1000),
        },
        signingKey.privateKeyPem,
        signingKey.kid,
      );
      const initialEnrollmentRow = await db.one(
        `INSERT INTO enrollment_tokens (
           workspace_id, token_hash, jws_compact, target_user_id, default_group_id,
           max_uses, expires_at, created_by
         ) VALUES ($1, $2, $3, NULL, NULL, 100, $4, $5)
         RETURNING *`,
        [ws.id, tokenHash, jwsCompact, expiresAt, result.admin?.id || null],
      );
      const proto = req.protocol || 'http';
      const host = req.get('host') || `localhost:${env.PORT}`;
      const resolvedServerUrl = (server_url || env.PUBLIC_URL || `${proto}://${host}`).replace(/\/+$/, '');
      const wsName = result.workspace?.name || workspace_name || ws.name;
      let initialQrUri = `madar://enroll?server=${encodeURIComponent(resolvedServerUrl)}&token=${encodeURIComponent(rawToken)}&workspace=${encodeURIComponent(ws.id)}&name=${encodeURIComponent(wsName)}`;
      if (result.admin?.employee_no) {
        initialQrUri += `&emp=${encodeURIComponent(result.admin.employee_no)}`;
      }
      if (result.admin?.title) {
        initialQrUri += `&title=${encodeURIComponent(result.admin.title)}`;
      }

      await appendAuditLog({
        workspaceId: ws.id,
        actorUserId: result.admin?.id || null,
        action: 'workspace.setup.completed',
        targetType: 'workspace',
        targetId: ws.id,
        metadata: {
          workspace_name,
          policy_preset,
          departments_count: result.departments.length,
        },
      });

      res.status(201).json({
        success: true,
        workspace: result.workspace,
        admin_user: result.admin
          ? {
              id: result.admin.id,
              employee_no: result.admin.employee_no,
              name: result.admin.name,
              email: result.admin.email,
            }
          : null,
        departments: result.departments,
        policy_signing_pub_key: signingKey.publicKeyEd25519,
        initial_enrollment: {
          enrollment_token: rawToken,
          qr_uri: initialQrUri,
          server_url: resolvedServerUrl,
          record: initialEnrollmentRow,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

// All remaining /api/v1/admin/* endpoints require authentication and policy context
adminRouter.use(requireAuth, attachPolicyContext);

/**
 * GET /api/v1/admin/overview — Dashboard KPI summary for the Web Admin Console.
 */
adminRouter.get(
  '/overview',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER', 'DEPT_HEAD', 'BROADCASTER'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const [usersCnt, devicesCnt, deptsCnt, channelsCnt, broadcastsCnt, decisionsCnt, holdsCnt] =
      await Promise.all([
        db.one("SELECT COUNT(*)::int AS c FROM users WHERE (workspace_id = $1 OR workspace_id IS NULL) AND account_status = 'active'", [ws.id]),
        db.one("SELECT COUNT(*)::int AS c FROM devices WHERE workspace_id = $1 AND status = 'active'", [ws.id]),
        db.one('SELECT COUNT(*)::int AS c FROM departments WHERE workspace_id = $1', [ws.id]),
        db.one('SELECT COUNT(*)::int AS c FROM channels WHERE workspace_id = $1 AND is_archived = FALSE', [ws.id]),
        db.one('SELECT COUNT(*)::int AS c FROM broadcasts WHERE workspace_id = $1', [ws.id]),
        db.one("SELECT COUNT(*)::int AS c FROM decisions WHERE workspace_id = $1 AND status = 'active'", [ws.id]),
        db.one('SELECT COUNT(*)::int AS c FROM legal_holds WHERE workspace_id = $1 AND released_at IS NULL', [ws.id]),
      ]);

    const chainCheck = await verifyAuditChain(ws.id);

    res.json({
      success: true,
      workspace: ws,
      kpis: {
        active_users: usersCnt?.c || 0,
        active_devices: devicesCnt?.c || 0,
        departments: deptsCnt?.c || 0,
        active_channels: channelsCnt?.c || 0,
        broadcasts: broadcastsCnt?.c || 0,
        active_decisions: decisionsCnt?.c || 0,
        active_legal_holds: holdsCnt?.c || 0,
        audit_chain_valid: chainCheck.valid,
        audit_entries_checked: chainCheck.checkedCount,
      },
    });
  },
);

/**
 * GET /api/v1/admin/departments — List departments.
 */
adminRouter.get(
  '/departments',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER', 'DEPT_HEAD', 'BROADCASTER'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rows = await db.many(
      `SELECT d.*, u.name AS head_user_name,
              (SELECT COUNT(*)::int FROM users m WHERE m.department_id = d.id AND m.account_status = 'active') AS member_count
       FROM departments d
       LEFT JOIN users u ON u.id = d.head_user_id
       WHERE d.workspace_id = $1
       ORDER BY d.sort_order ASC, d.name ASC`,
      [ws.id],
    );
    res.json({ success: true, departments: rows });
  },
);

/**
 * POST /api/v1/admin/departments — Create department + automatic department channel (DIR-02).
 */
adminRouter.post(
  '/departments',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(120),
      code: z.string().trim().min(1).max(40),
      parent_id: z.string().uuid().nullable().optional(),
      head_user_id: z.number().int().positive().nullable().optional(),
      sort_order: z.number().int().default(0),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { name, code, parent_id, head_user_id, sort_order } = req.body;

    // Enforce max 4 hierarchy levels (DIR-01)
    if (parent_id) {
      let depth = 1;
      let cursorId = parent_id;
      while (cursorId) {
        depth += 1;
        if (depth > 4) {
          throw badRequest('max_department_depth', 'الهيكل التنظيمي يدعم حتى 4 مستويات كحد أقصى (DIR-01)');
        }
        const parentRow = await db.one('SELECT parent_id FROM departments WHERE id = $1', [cursorId]);
        cursorId = parentRow?.parent_id || null;
      }
    }

    const dept = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO departments (workspace_id, parent_id, name, code, head_user_id, sort_order)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [ws.id, parent_id || null, name, code, head_user_id || null, sort_order],
      );
      const created = rows[0];

      const { rows: chRows } = await client.query(
        `INSERT INTO channels (workspace_id, kind, name, description, department_id, created_by)
         VALUES ($1, 'department', $2, $3, $4, $5)
         RETURNING *`,
        [ws.id, `قناة ${name}`, `القناة الرسمية لقسم ${name}`, created.id, req.auth.userId],
      );

      await client.query('UPDATE departments SET channel_id = $2 WHERE id = $1', [
        created.id,
        chRows[0].id,
      ]);

      if (head_user_id) {
        await client.query(
          `INSERT INTO channel_members (channel_id, user_id, role)
           VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING`,
          [chRows[0].id, head_user_id],
        );
        await client.query(
          "INSERT INTO user_roles (user_id, role, scope_dept_id) VALUES ($1, 'DEPT_HEAD', $2) ON CONFLICT DO NOTHING",
          [head_user_id, created.id],
        );
      }

      return { ...created, channel_id: chRows[0].id };
    });

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'department.created',
      targetType: 'department',
      targetId: dept.id,
      metadata: { name, code, channel_id: dept.channel_id },
    });

    res.status(201).json({ success: true, department: dept });
  },
);

/**
 * PATCH /api/v1/admin/departments/:id — Update department name, code, or head_user_id.
 */
adminRouter.patch(
  '/departments/:id',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(120).optional(),
      code: z.string().trim().min(1).max(40).optional(),
      head_user_id: z.number().int().positive().nullable().optional(),
      sort_order: z.number().int().optional(),
    }),
  }),
  async (req, res) => {
    const dept = await db.one('SELECT * FROM departments WHERE id = $1', [req.params.id]);
    if (!dept) throw notFound('department_not_found', 'القسم غير موجود');

    const nextName = req.body.name ?? dept.name;
    const nextCode = req.body.code ? req.body.code.toUpperCase() : dept.code;
    const nextHeadId = req.body.head_user_id === undefined ? dept.head_user_id : req.body.head_user_id;
    const nextSort = req.body.sort_order ?? dept.sort_order ?? 0;

    const updated = await db.tx(async (client) => {
      const { rows } = await client.query(
        `UPDATE departments
         SET name = $2, code = $3, head_user_id = $4, sort_order = $5
         WHERE id = $1
         RETURNING *`,
        [dept.id, nextName, nextCode, nextHeadId, nextSort],
      );
      if (dept.channel_id && req.body.name) {
        await client.query(
          'UPDATE channels SET name = $2, description = $3 WHERE id = $1',
          [dept.channel_id, `قناة ${nextName}`, `القناة الرسمية لقسم ${nextName}`],
        );
      }
      if (nextHeadId && dept.channel_id) {
        await client.query(
          `INSERT INTO channel_members (channel_id, user_id, role)
           VALUES ($1, $2, 'owner')
           ON CONFLICT (channel_id, user_id) DO UPDATE SET role = 'owner'`,
          [dept.channel_id, nextHeadId],
        );
      }
      return rows[0];
    });

    await appendAuditLog({
      workspaceId: dept.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'department.updated',
      targetType: 'department',
      targetId: dept.id,
      metadata: { name: nextName, code: nextCode, head_user_id: nextHeadId },
    });

    res.json({ success: true, department: updated });
  },
);

/**
 * DELETE /api/v1/admin/departments/:id — Delete a department and archive its channel.
 */
adminRouter.delete(
  '/departments/:id',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  async (req, res) => {
    const dept = await db.one('SELECT * FROM departments WHERE id = $1', [req.params.id]);
    if (!dept) throw notFound('department_not_found', 'القسم غير موجود');

    await db.tx(async (client) => {
      await client.query('UPDATE users SET department_id = NULL WHERE department_id = $1', [dept.id]);
      await client.query('UPDATE departments SET parent_id = NULL WHERE parent_id = $1', [dept.id]);
      if (dept.channel_id) {
        await client.query(
          'UPDATE channels SET is_archived = TRUE, department_id = NULL WHERE id = $1',
          [dept.channel_id],
        );
      }
      await client.query('DELETE FROM departments WHERE id = $1', [dept.id]);
    });

    await appendAuditLog({
      workspaceId: dept.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'department.deleted',
      targetType: 'department',
      targetId: dept.id,
      metadata: { name: dept.name, code: dept.code },
    });

    res.json({ success: true, deleted_id: dept.id });
  },
);

/**
 * GET /api/v1/admin/channels — List all workspace channels with member, decision, and message counts.
 */
adminRouter.get(
  '/channels',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER', 'DEPT_HEAD', 'BROADCASTER'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rows = await db.many(
      `SELECT c.*, d.name AS department_name, d.code AS department_code,
              (SELECT COUNT(*)::int FROM channel_members cm WHERE cm.channel_id = c.id) AS member_count,
              (SELECT COUNT(*)::int FROM decisions dc WHERE dc.channel_id = c.id AND dc.status = 'active') AS decision_count,
              (SELECT COUNT(*)::int FROM followups fu WHERE fu.channel_id = c.id AND fu.status = 'open') AS open_followup_count,
              (SELECT COUNT(*)::int FROM channel_messages msg WHERE msg.channel_id = c.id) AS message_count
       FROM channels c
       LEFT JOIN departments d ON d.id = c.department_id
       WHERE c.workspace_id = $1
       ORDER BY c.is_archived ASC, c.created_at ASC`,
      [ws.id],
    );
    res.json({ success: true, channels: rows });
  },
);

/**
 * POST /api/v1/admin/channels — Create an organizational channel and assign members.
 */
adminRouter.post(
  '/channels',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'DEPT_HEAD'),
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(160),
      description: z.string().trim().max(500).optional(),
      kind: z
        .enum(['department', 'project', 'cross_dept', 'public_channel', 'announcement', 'broadcast_feed'])
        .default('project'),
      department_id: z.string().uuid().nullable().optional(),
      auto_join_all: z.boolean().default(true),
      member_ids: z.array(z.number().int().positive()).default([]),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { name, description, kind: rawKind, department_id, auto_join_all, member_ids } = req.body;
    const kind = rawKind === 'cross_dept' ? 'public_channel' : rawKind;

    const channel = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO channels (workspace_id, kind, name, description, department_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [ws.id, kind, name, description || '', department_id || null, req.auth.userId],
      );
      const ch = rows[0];

      const targetIds = new Set([req.auth.userId, ...member_ids]);
      if (auto_join_all) {
        const allUsers = await client.query(
          "SELECT id FROM users WHERE (workspace_id = $1 OR workspace_id IS NULL) AND account_status = 'active'",
          [ws.id],
        );
        for (const r of allUsers.rows) targetIds.add(r.id);
      } else if (department_id) {
        const deptUsers = await client.query(
          "SELECT id FROM users WHERE department_id = $1 AND account_status = 'active'",
          [department_id],
        );
        for (const r of deptUsers.rows) targetIds.add(r.id);
      }

      for (const uid of targetIds) {
        const role = Number(uid) === Number(req.auth.userId) ? 'owner' : 'member';
        await client.query(
          `INSERT INTO channel_members (channel_id, user_id, role)
           VALUES ($1, $2, $3)
           ON CONFLICT (channel_id, user_id) DO NOTHING`,
          [ch.id, uid, role],
        );
      }

      return ch;
    });

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'channel.created',
      targetType: 'channel',
      targetId: channel.id,
      metadata: { name, kind, department_id },
    });

    res.status(201).json({ success: true, channel });
  },
);

/**
 * PATCH /api/v1/admin/channels/:id — Update channel name, description, archive status, or members.
 */
adminRouter.patch(
  '/channels/:id',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'DEPT_HEAD'),
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(160).optional(),
      description: z.string().trim().max(500).optional(),
      is_archived: z.boolean().optional(),
      member_ids: z.array(z.number().int().positive()).optional(),
    }),
  }),
  async (req, res) => {
    const ch = await db.one('SELECT * FROM channels WHERE id = $1', [req.params.id]);
    if (!ch) throw notFound('channel_not_found', 'القناة غير موجودة');

    const nextName = req.body.name ?? ch.name;
    const nextDesc = req.body.description ?? ch.description ?? '';
    const nextArchived = req.body.is_archived ?? ch.is_archived;

    const updated = await db.tx(async (client) => {
      const { rows } = await client.query(
        `UPDATE channels
         SET name = $2, description = $3, is_archived = $4
         WHERE id = $1
         RETURNING *`,
        [ch.id, nextName, nextDesc, nextArchived],
      );
      if (Array.isArray(req.body.member_ids)) {
        for (const uid of req.body.member_ids) {
          await client.query(
            `INSERT INTO channel_members (channel_id, user_id, role)
             VALUES ($1, $2, 'member')
             ON CONFLICT (channel_id, user_id) DO NOTHING`,
            [ch.id, uid],
          );
        }
      }
      return rows[0];
    });

    await appendAuditLog({
      workspaceId: ch.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'channel.updated',
      targetType: 'channel',
      targetId: ch.id,
      metadata: { name: nextName, is_archived: nextArchived },
    });

    res.json({ success: true, channel: updated });
  },
);

/**
 * DELETE /api/v1/admin/channels/:id — Archive or delete a channel if not under legal hold.
 */
adminRouter.delete(
  '/channels/:id',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  async (req, res) => {
    const ch = await db.one('SELECT * FROM channels WHERE id = $1', [req.params.id]);
    if (!ch) throw notFound('channel_not_found', 'القناة غير موجودة');
    if (ch.legal_hold) {
      throw forbidden('legal_hold_active', 'لا يمكن حذف أو أرشفة قناة خاضعة لأمر تحفظ قانوني');
    }

    const updated = await db.one(
      'UPDATE channels SET is_archived = TRUE WHERE id = $1 RETURNING *',
      [ch.id],
    );

    await appendAuditLog({
      workspaceId: ch.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'channel.archived',
      targetType: 'channel',
      targetId: ch.id,
      metadata: { name: ch.name },
    });

    res.json({ success: true, channel: updated });
  },
);


/**
 * GET /api/v1/admin/users — List workspace users with roles and device counts.
 */
adminRouter.get(
  '/users',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER', 'DEPT_HEAD'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rows = await db.many(
      `SELECT u.id, u.workspace_id, u.employee_no, u.name, u.title, u.email, u.work_phone, u.phone,
              u.department_id, d.name AS department_name, u.account_status, u.presence_status,
              u.last_seen_at, u.created_at, u.offboarded_at,
              COALESCE(
                (SELECT json_agg(ur.role) FROM user_roles ur WHERE ur.user_id = u.id),
                '[]'::json
              ) AS roles,
              (SELECT COUNT(*)::int FROM devices dv WHERE dv.user_id = u.id AND dv.status = 'active') AS active_devices_count
       FROM users u
       LEFT JOIN departments d ON d.id = u.department_id
       WHERE u.workspace_id = $1 OR u.workspace_id IS NULL
       ORDER BY u.id ASC`,
      [ws.id],
    );
    res.json({ success: true, users: rows });
  },
);

function assertSeparationOfDuties(roles = []) {
  if (roles.includes('IT_ADMIN') && roles.includes('COMPLIANCE_OFFICER')) {
    throw badRequest(
      'sod_role_conflict',
      'يُمنع منح صلاحيتي IT_ADMIN و COMPLIANCE_OFFICER لنفس المستخدم التزاماً بمبدأ فصل الصلاحيات (Section 5.3)',
    );
  }
}

/**
 * POST /api/v1/admin/users — Provision an enterprise employee account (DIR-01).
 */
adminRouter.post(
  '/users',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      employee_no: z.string().trim().min(1).max(64),
      name: z.string().trim().min(1).max(120),
      email: z.string().email().optional(),
      work_phone: z.string().trim().max(32).optional(),
      title: z.string().trim().max(120).optional(),
      department_id: z.string().uuid().nullable().optional(),
      roles: z
        .array(
          z.enum([
            'SUPER_ADMIN',
            'EXEC_MANAGER',
            'IT_ADMIN',
            'COMPLIANCE_OFFICER',
            'DEPT_HEAD',
            'BROADCASTER',
            'MODERATOR',
            'MEMBER',
            'GUEST',
          ]),
        )
        .default(['MEMBER']),
      password: z.string().min(6).max(255).optional(),
      must_change_password: z.boolean().default(false),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const {
      employee_no,
      name,
      email,
      work_phone,
      title,
      department_id,
      roles,
      password,
      must_change_password,
    } = req.body;

    assertSeparationOfDuties(roles);

    if (password) {
      const minLen = Number(req.effectivePolicy?.policies?.['auth.password_min_length'] ?? 10);
      const pwCheck = validatePasswordComplexity(password, minLen);
      if (!pwCheck.valid) throw badRequest('weak_password', pwCheck.reason);
    }

    const user = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO users (
           workspace_id, employee_no, name, email, work_phone, title,
           department_id, account_status, profile_type, last_seen_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', 'workspace', NOW())
         RETURNING *`,
        [
          ws.id,
          employee_no,
          name,
          email || null,
          work_phone || null,
          title || '',
          department_id || null,
        ],
      );
      const u = rows[0];

      for (const r of roles) {
        await client.query(
          'INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [u.id, r],
        );
      }

      if (password) {
        await client.query(
          `INSERT INTO credentials (user_id, password_hash, must_change_password, password_changed_at)
           VALUES ($1, $2, $3, NOW())`,
          [u.id, hashPassword(password), must_change_password],
        );
      }

      // Auto-join department channel if department_id is set
      if (department_id) {
        const dept = await client.query('SELECT channel_id FROM departments WHERE id = $1', [
          department_id,
        ]);
        if (dept.rows[0]?.channel_id) {
          await client.query(
            `INSERT INTO channel_members (channel_id, user_id, role)
             VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING`,
            [dept.rows[0].channel_id, u.id],
          );
        }
      }

      return u;
    });

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'user.created',
      targetType: 'user',
      targetId: user.id,
      metadata: { employee_no, name, roles, department_id },
    });

    res.status(201).json({
      success: true,
      user: {
        ...user,
        roles,
      },
    });
  },
);

/**
 * POST /api/v1/admin/users/import-csv — Bulk import employees from CSV or array (DIR-01).
 */
adminRouter.post(
  '/users/import-csv',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      csv_text: z.string().optional(),
      users: z
        .array(
          z.object({
            employee_no: z.string().trim().min(1),
            name: z.string().trim().min(1),
            email: z.string().email().optional(),
            work_phone: z.string().optional(),
            title: z.string().optional(),
            department_code: z.string().optional(),
            role: z.string().default('MEMBER'),
            password: z.string().optional(),
          }),
        )
        .optional(),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    let entries = req.body.users || [];

    if (req.body.csv_text) {
      const lines = req.body.csv_text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      if (lines.length > 1) {
        const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
        entries = lines.slice(1).map((line) => {
          const cols = line.split(',').map((c) => c.trim());
          const obj = {};
          headers.forEach((h, i) => {
            obj[h] = cols[i] || '';
          });
          return obj;
        });
      }
    }

    const depts = await db.many('SELECT id, code, channel_id FROM departments WHERE workspace_id = $1', [
      ws.id,
    ]);
    const deptByCode = new Map(depts.map((d) => [d.code.toLowerCase(), d]));

    const imported = [];
    for (const item of entries) {
      if (!item.employee_no || !item.name) continue;
      const dept = item.department_code
        ? deptByCode.get(String(item.department_code).toLowerCase())
        : null;

      const u = await db.one(
        `INSERT INTO users (
           workspace_id, employee_no, name, email, work_phone, title,
           department_id, account_status, profile_type, last_seen_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', 'workspace', NOW())
         ON CONFLICT (workspace_id, employee_no) DO UPDATE
         SET name = EXCLUDED.name,
             email = COALESCE(EXCLUDED.email, users.email),
             title = COALESCE(EXCLUDED.title, users.title),
             department_id = COALESCE(EXCLUDED.department_id, users.department_id)
         RETURNING id, employee_no, name, email, title, department_id`,
        [
          ws.id,
          item.employee_no,
          item.name,
          item.email || null,
          item.work_phone || null,
          item.title || '',
          dept?.id || null,
        ],
      );

      const role = item.role || 'MEMBER';
      await db.query(
        'INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [u.id, role],
      );

      if (item.password) {
        await db.query(
          `INSERT INTO credentials (user_id, password_hash, must_change_password)
           VALUES ($1, $2, TRUE)
           ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
          [u.id, hashPassword(item.password)],
        );
      }

      if (dept?.channel_id) {
        await db.query(
          `INSERT INTO channel_members (channel_id, user_id, role)
           VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING`,
          [dept.channel_id, u.id],
        );
      }

      imported.push(u);
    }

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'users.bulk_imported',
      targetType: 'workspace',
      targetId: ws.id,
      metadata: { imported_count: imported.length },
    });

    res.status(201).json({
      success: true,
      imported_count: imported.length,
      users: imported,
    });
  },
);

/**
 * POST /api/v1/admin/users/:id/offboard — Atomic employee offboarding (ADM-08, TC-ADM).
 * Revokes tokens, marks all devices wipe_pending, and transfers open followups to department head or target user.
 */
adminRouter.post(
  '/users/:id/offboard',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      reason: z.string().trim().min(2).max(500).default('إنهاء خدمة الموظف وإخلاء الطرف الرقمي'),
      transfer_to_user_id: z.number().int().positive().optional(),
    }),
  }),
  async (req, res) => {
    const targetUserId = Number(req.params.id);
    const user = await db.one('SELECT * FROM users WHERE id = $1', [targetUserId]);
    if (!user) throw notFound('user_not_found', 'الموظف غير موجود');

    const wsId = user.workspace_id || req.auth.workspaceId || (await ensureDefaultWorkspace()).id;

    // Resolve followup assignee: explicit transfer_to_user_id OR department head_user_id OR actor
    let newOwnerId = req.body.transfer_to_user_id || null;
    if (!newOwnerId && user.department_id) {
      const dept = await db.one('SELECT head_user_id FROM departments WHERE id = $1', [
        user.department_id,
      ]);
      if (dept?.head_user_id && dept.head_user_id !== targetUserId) {
        newOwnerId = dept.head_user_id;
      }
    }
    if (!newOwnerId) {
      newOwnerId = req.auth.userId;
    }

    const summary = await db.tx(async (client) => {
      await client.query(
        `UPDATE users
         SET account_status = 'offboarded', offboarded_at = NOW(), updated_at = NOW()
         WHERE id = $1`,
        [targetUserId],
      );

      const revokedRefresh = await client.query(
        'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL RETURNING id',
        [targetUserId],
      );

      const revokedSessions = await client.query(
        'UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL RETURNING id',
        [targetUserId],
      );

      const wipeCmdId = crypto.randomUUID();
      const wipedDevices = await client.query(
        `UPDATE devices
         SET status = 'wipe_pending', wipe_command_id = $2
         WHERE user_id = $1 AND status IN ('active', 'suspended')
         RETURNING id, device_name`,
        [targetUserId, wipeCmdId],
      );

      const transferredFollowups = await client.query(
        `UPDATE followups
         SET owner_id = $2
         WHERE owner_id = $1 AND status = 'open'
         RETURNING id, title, channel_id`,
        [targetUserId, newOwnerId],
      );

      // Update hub_items for transferred followups to point to newOwnerId
      if (transferredFollowups.rowCount > 0) {
        const fuIds = transferredFollowups.rows.map((r) => r.id);
        await client.query(
          `UPDATE hub_items
           SET user_id = $2
           WHERE source_type = 'followup' AND source_id = ANY($1::uuid[]) AND resolved_at IS NULL`,
          [fuIds, newOwnerId],
        );
      }

      return {
        wipe_command_id: wipeCmdId,
        revoked_refresh_tokens: revokedRefresh.rowCount,
        revoked_sessions: revokedSessions.rowCount,
        devices_marked_wipe_pending: wipedDevices.rows,
        transferred_followups_count: transferredFollowups.rowCount,
        transferred_to_user_id: newOwnerId,
      };
    });

    await appendAuditLog({
      workspaceId: wsId,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'user.offboarded',
      targetType: 'user',
      targetId: targetUserId,
      metadata: {
        reason: req.body.reason,
        ...summary,
      },
    });

    // Notify connected sockets for this user with device.wipe + session.revoked, then close sockets
    for (const dev of summary.devices_marked_wipe_pending) {
      sendToUser(targetUserId, 'device.wipe', {
        device_id: dev.id,
        wipe_command_id: summary.wipe_command_id,
        reason: req.body.reason,
        issued_at: new Date().toISOString(),
      });
    }
    sendToUser(targetUserId, 'session.revoked', {
      user_id: targetUserId,
      reason: 'offboarded',
    });
    disconnectUser(targetUserId);

    res.json({
      success: true,
      offboarded_user_id: targetUserId,
      ...summary,
    });
  },
);

/**
 * PATCH /api/v1/admin/users/:id — Update employee profile, department, roles, or account_status (active / suspended).
 */
adminRouter.patch(
  '/users/:id',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(120).optional(),
      email: z.string().email().nullable().optional(),
      work_phone: z.string().trim().max(32).nullable().optional(),
      title: z.string().trim().max(120).optional(),
      department_id: z.string().uuid().nullable().optional(),
      account_status: z.enum(['active', 'suspended']).optional(),
      roles: z
        .array(
          z.enum([
            'SUPER_ADMIN',
            'EXEC_MANAGER',
            'IT_ADMIN',
            'COMPLIANCE_OFFICER',
            'DEPT_HEAD',
            'BROADCASTER',
            'MODERATOR',
            'MEMBER',
            'GUEST',
          ]),
        )
        .optional(),
    }),
  }),
  async (req, res) => {
    const targetUserId = Number(req.params.id);
    if (Array.isArray(req.body.roles)) {
      assertSeparationOfDuties(req.body.roles);
    }
    const user = await db.one('SELECT * FROM users WHERE id = $1', [targetUserId]);
    if (!user) throw notFound('user_not_found', 'الموظف غير موجود');

    const wsId = user.workspace_id || req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
    const nextName = req.body.name ?? user.name;
    const nextEmail = req.body.email === undefined ? user.email : req.body.email;
    const nextPhone = req.body.work_phone === undefined ? user.work_phone : req.body.work_phone;
    const nextTitle = req.body.title ?? user.title ?? '';
    const nextDeptId = req.body.department_id === undefined ? user.department_id : req.body.department_id;
    const nextStatus = req.body.account_status ?? user.account_status;

    const updated = await db.tx(async (client) => {
      const { rows } = await client.query(
        `UPDATE users
         SET name = $2,
             email = $3,
             work_phone = $4,
             title = $5,
             department_id = $6,
             account_status = $7,
             offboarded_at = CASE WHEN $7 = 'active' THEN NULL ELSE offboarded_at END,
             updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [targetUserId, nextName, nextEmail, nextPhone, nextTitle, nextDeptId, nextStatus],
      );

      if (Array.isArray(req.body.roles) && req.body.roles.length > 0) {
        await client.query('DELETE FROM user_roles WHERE user_id = $1', [targetUserId]);
        for (const r of req.body.roles) {
          await client.query(
            'INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [targetUserId, r],
          );
        }
      }

      if (nextDeptId) {
        const dept = await client.query('SELECT channel_id FROM departments WHERE id = $1', [
          nextDeptId,
        ]);
        if (dept.rows[0]?.channel_id) {
          await client.query(
            `INSERT INTO channel_members (channel_id, user_id, role)
             VALUES ($1, $2, 'member')
             ON CONFLICT (channel_id, user_id) DO NOTHING`,
            [dept.rows[0].channel_id, targetUserId],
          );
        }
      }

      if (nextStatus === 'suspended') {
        await client.query(
          'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL',
          [targetUserId],
        );
        await client.query(
          'UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL',
          [targetUserId],
        );
      }

      return rows[0];
    });

    if (nextStatus === 'suspended') {
      sendToUser(targetUserId, 'session.revoked', {
        user_id: targetUserId,
        reason: 'account_suspended',
      });
      disconnectUser(targetUserId);
    }

    await appendAuditLog({
      workspaceId: wsId,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'user.updated',
      targetType: 'user',
      targetId: targetUserId,
      metadata: {
        name: nextName,
        title: nextTitle,
        department_id: nextDeptId,
        account_status: nextStatus,
        roles: req.body.roles,
      },
    });

    res.json({ success: true, user: updated });
  },
);

/**
 * POST /api/v1/admin/users/:id/reset-password — Administrative password reset for an employee.
 */
adminRouter.post(
  '/users/:id/reset-password',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      new_password: z.string().min(6).max(255),
      must_change_password: z.boolean().default(false),
    }),
  }),
  async (req, res) => {
    const targetUserId = Number(req.params.id);
    const user = await db.one('SELECT * FROM users WHERE id = $1', [targetUserId]);
    if (!user) throw notFound('user_not_found', 'الموظف غير موجود');

    const minLen = Number(req.effectivePolicy?.policies?.['auth.password_min_length'] ?? 10);
    const pwCheck = validatePasswordComplexity(req.body.new_password, minLen);
    if (!pwCheck.valid) throw badRequest('weak_password', pwCheck.reason);

    const wsId = user.workspace_id || req.auth.workspaceId || (await ensureDefaultWorkspace()).id;

    await db.tx(async (client) => {
      await client.query(
        `INSERT INTO credentials (user_id, password_hash, must_change_password, password_changed_at, failed_attempts, locked_until)
         VALUES ($1, $2, $3, NOW(), 0, NULL)
         ON CONFLICT (user_id) DO UPDATE
         SET password_hash = EXCLUDED.password_hash,
             must_change_password = EXCLUDED.must_change_password,
             password_changed_at = NOW(),
             failed_attempts = 0,
             locked_until = NULL`,
        [targetUserId, hashPassword(req.body.new_password), req.body.must_change_password],
      );
      await client.query(
        'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL',
        [targetUserId],
      );
    });

    await appendAuditLog({
      workspaceId: wsId,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'user.password_reset',
      targetType: 'user',
      targetId: targetUserId,
      metadata: { must_change_password: req.body.must_change_password },
    });

    res.json({ success: true, user_id: targetUserId });
  },
);


/**
 * GET /api/v1/admin/enrollment-tokens — List enrollment tokens.
 */
adminRouter.get(
  '/enrollment-tokens',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rows = await db.many(
      `SELECT et.*, u.name AS target_user_name, g.name AS group_name
       FROM enrollment_tokens et
       LEFT JOIN users u ON u.id = et.target_user_id
       LEFT JOIN policy_groups g ON g.id = et.default_group_id
       WHERE et.workspace_id = $1
       ORDER BY et.created_at DESC
       LIMIT 100`,
      [ws.id],
    );
    res.json({ success: true, enrollment_tokens: rows });
  },
);

/**
 * POST /api/v1/admin/enrollment-tokens — Issue signed JWS enrollment token & QR payload (ENR-02).
 */
adminRouter.post(
  '/enrollment-tokens',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      target_user_id: z.number().int().positive().nullable().optional(),
      default_group_id: z.string().uuid().nullable().optional(),
      max_uses: z.number().int().min(1).max(500).default(1),
      expires_in_hours: z.number().int().min(1).max(720).default(72),
      server_url: z.string().trim().max(500).optional(),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const signingKey = await ensureWorkspaceSigningKey(ws.id);
    const { target_user_id, default_group_id, max_uses, expires_in_hours, server_url } = req.body;

    const rawToken = `MADAR-ENR-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
    const tokenHash = sha256(rawToken);
    const expiresAt = new Date(Date.now() + expires_in_hours * 3_600_000);

    const jwsCompact = signEd25519Jws(
      {
        typ: 'madar.enrollment.v1',
        workspace_id: ws.id,
        token_hash: tokenHash,
        target_user_id: target_user_id || null,
        default_group_id: default_group_id || null,
        max_uses,
        exp: Math.floor(expiresAt.getTime() / 1000),
      },
      signingKey.privateKeyPem,
      signingKey.kid,
    );

    const row = await db.one(
      `INSERT INTO enrollment_tokens (
         workspace_id, token_hash, jws_compact, target_user_id, default_group_id,
         max_uses, expires_at, created_by
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        ws.id,
        tokenHash,
        jwsCompact,
        target_user_id || null,
        default_group_id || null,
        max_uses,
        expiresAt,
        req.auth.userId,
      ],
    );

    const proto = req.protocol || 'http';
    const host = req.get('host') || `localhost:${env.PORT}`;
    const serverUrl = (server_url || env.PUBLIC_URL || `${proto}://${host}`).replace(/\/+$/, '');
    let qrUri = `madar://enroll?server=${encodeURIComponent(serverUrl)}&token=${encodeURIComponent(rawToken)}&workspace=${encodeURIComponent(ws.id)}&name=${encodeURIComponent(ws.name)}`;

    if (target_user_id) {
      const targetUser = await db.one(
        `SELECT u.employee_no, u.name, u.title, d.name AS department_name
         FROM users u
         LEFT JOIN departments d ON d.id = u.department_id
         WHERE u.id = $1`,
        [target_user_id],
      );
      if (targetUser) {
        if (targetUser.employee_no) {
          qrUri += `&emp=${encodeURIComponent(targetUser.employee_no)}`;
        }
        if (targetUser.department_name) {
          qrUri += `&dept=${encodeURIComponent(targetUser.department_name)}`;
        }
        if (targetUser.title) {
          qrUri += `&title=${encodeURIComponent(targetUser.title)}`;
        }
      }
    }

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'enrollment_token.created',
      targetType: 'enrollment_token',
      targetId: row.id,
      metadata: { target_user_id, max_uses, expires_at: expiresAt.toISOString() },
    });

    res.status(201).json({
      success: true,
      enrollment_token: rawToken,
      jws_compact: jwsCompact,
      qr_uri: qrUri,
      record: row,
    });
  },
);

/**
 * GET /api/v1/admin/devices — List all enrolled workspace devices (ADM-02).
 */
adminRouter.get(
  '/devices',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rows = await db.many(
      `SELECT dv.id, dv.workspace_id, dv.user_id, u.name AS user_name, u.employee_no,
              dv.device_name, dv.platform, dv.os_version, dv.app_version, dv.fingerprint,
              dv.attestation_state, dv.status, dv.wipe_command_id, dv.wiped_at,
              dv.last_seen_at, dv.created_at
       FROM devices dv
       LEFT JOIN users u ON u.id = dv.user_id
       WHERE dv.workspace_id = $1
       ORDER BY dv.last_seen_at DESC`,
      [ws.id],
    );
    res.json({ success: true, devices: rows });
  },
);

/**
 * POST /api/v1/admin/devices/:id/revoke — Revoke a specific device and its refresh tokens (ADM-02, DEV-03).
 */
adminRouter.post(
  '/devices/:id/revoke',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      reason: z.string().trim().min(2).max(500).default('إلغاء اعتماد الجهاز إدارياً'),
    }),
  }),
  async (req, res) => {
    const dev = await db.one('SELECT * FROM devices WHERE id = $1', [req.params.id]);
    if (!dev) throw notFound('device_not_found', 'الجهاز غير موجود');

    const updated = await db.tx(async (client) => {
      const { rows } = await client.query(
        "UPDATE devices SET status = 'revoked' WHERE id = $1 RETURNING *",
        [dev.id],
      );
      await client.query(
        'UPDATE refresh_tokens SET revoked_at = NOW() WHERE device_id = $1 AND revoked_at IS NULL',
        [dev.id],
      );
      return rows[0];
    });

    await appendAuditLog({
      workspaceId: dev.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'device.revoked',
      targetType: 'device',
      targetId: dev.id,
      metadata: { target_user_id: dev.user_id, reason: req.body.reason },
    });

    sendToUser(dev.user_id, 'session.revoked', {
      device_id: dev.id,
      reason: req.body.reason,
    });

    res.json({ success: true, device: updated });
  },
);

/**
 * POST /api/v1/admin/devices/:id/wipe — Issue remote selective wipe command for a device (ADM-02, DEV-04, TC-WIPE).
 */
adminRouter.post(
  '/devices/:id/wipe',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      reason: z.string().trim().min(2).max(500).default('مسح انتقائي عن بعد لقبو العمل'),
    }),
  }),
  async (req, res) => {
    const dev = await db.one('SELECT * FROM devices WHERE id = $1', [req.params.id]);
    if (!dev) throw notFound('device_not_found', 'الجهاز غير موجود');

    const wipeCommandId = crypto.randomUUID();
    const updated = await db.tx(async (client) => {
      const { rows } = await client.query(
        `UPDATE devices
         SET status = 'wipe_pending', wipe_command_id = $2
         WHERE id = $1
         RETURNING *`,
        [dev.id, wipeCommandId],
      );
      await client.query(
        'UPDATE refresh_tokens SET revoked_at = NOW() WHERE device_id = $1 AND revoked_at IS NULL',
        [dev.id],
      );
      return rows[0];
    });

    await appendAuditLog({
      workspaceId: dev.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'device.wipe.issued',
      targetType: 'device',
      targetId: dev.id,
      metadata: {
        target_user_id: dev.user_id,
        wipe_command_id: wipeCommandId,
        reason: req.body.reason,
      },
    });

    // Push live device.wipe event over WebSocket
    sendToUser(dev.user_id, 'device.wipe', {
      device_id: dev.id,
      wipe_command_id: wipeCommandId,
      reason: req.body.reason,
      issued_at: new Date().toISOString(),
    });

    res.json({
      success: true,
      wipe_command_id: wipeCommandId,
      device: updated,
    });
  },
);

/* ============================================================================
 * POLICY ENGINE MANAGEMENT (POL-01..06, ADM-03..04, TC-POL-21..25)
 * ========================================================================== */

/**
 * GET /api/v1/admin/policies — Get catalog, entries, groups, and version history.
 */
adminRouter.get(
  '/policies',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const [entries, groups, versions] = await Promise.all([
      db.many(
        'SELECT * FROM policy_entries WHERE workspace_id = $1 ORDER BY scope_type ASC, key ASC',
        [ws.id],
      ),
      db.many(
        `SELECT pg.*,
                (SELECT COUNT(*)::int FROM policy_group_members pgm WHERE pgm.group_id = pg.id) AS member_count
         FROM policy_groups pg
         WHERE pg.workspace_id = $1
         ORDER BY pg.priority DESC, pg.name ASC`,
        [ws.id],
      ),
      db.many(
        `SELECT pv.*, u.name AS published_by_name
         FROM policy_versions pv
         LEFT JOIN users u ON u.id = pv.published_by
         WHERE pv.workspace_id = $1
         ORDER BY pv.version DESC
         LIMIT 50`,
        [ws.id],
      ),
    ]);

    res.json({
      success: true,
      catalog: getPolicyCatalog(),
      entries,
      groups,
      versions,
    });
  },
);

/**
 * POST /api/v1/admin/policies/groups — Create a policy group and assign members.
 */
adminRouter.post(
  '/policies/groups',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(120),
      priority: z.number().int().min(1).max(10_000).default(100),
      member_ids: z.array(z.number().int().positive()).default([]),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { name, priority, member_ids } = req.body;

    const group = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO policy_groups (workspace_id, name, priority)
         VALUES ($1, $2, $3)
         RETURNING *`,
        [ws.id, name, priority],
      );
      const g = rows[0];
      for (const uid of member_ids) {
        await client.query(
          `INSERT INTO policy_group_members (group_id, user_id)
           VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [g.id, uid],
        );
      }
      return g;
    });

    res.status(201).json({ success: true, group });
  },
);

/**
 * POST /api/v1/admin/policies/preview — Dry-run impact preview before publishing (POL-05, TC-POL-25).
 */
adminRouter.post(
  '/policies/preview',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER'),
  validate({
    body: z.object({
      scope_type: z.enum(['workspace', 'department', 'group', 'user']).default('workspace'),
      scope_id: z.string().optional(),
      changes: z
        .array(
          z.object({
            key: z.string().trim().min(1),
            value: z.any(),
            locked: z.boolean().optional(),
          }),
        )
        .min(1),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { scope_type, scope_id, changes } = req.body;
    const effectiveScopeId = scope_type === 'workspace' ? ws.id : String(scope_id || ws.id);

    for (const ch of changes) {
      assertPolicyEditPermission(req.auth.roles, ch.key);
      const check = validatePolicyEntryValue(ch.key, ch.value);
      if (!check.valid) throw badRequest('invalid_policy_value', check.error);
    }

    const impact = await previewPolicyImpact(ws.id, scope_type, effectiveScopeId, changes);
    res.json({
      success: true,
      preview: impact,
    });
  },
);

/**
 * PUT /api/v1/admin/policies — Publish policy changes, sign new bundle & push policy.updated over WS (POL-01..04, ADM-04).
 */
adminRouter.put(
  '/policies',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER'),
  validate({
    body: z.object({
      scope_type: z.enum(['workspace', 'department', 'group', 'user']).default('workspace'),
      scope_id: z.string().optional(),
      reason: z.string().trim().min(2).max(500).default('تحديث سياسات مساحة العمل'),
      changes: z
        .array(
          z.object({
            key: z.string().trim().min(1),
            value: z.any(),
            locked: z.boolean().default(false),
          }),
        )
        .min(1),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { scope_type, scope_id, reason, changes } = req.body;
    const effectiveScopeId = scope_type === 'workspace' ? ws.id : String(scope_id || ws.id);

    // Validate all keys and enforce Separation of Duties (ADM-04)
    for (const ch of changes) {
      assertPolicyEditPermission(req.auth.roles, ch.key);
      const check = validatePolicyEntryValue(ch.key, ch.value);
      if (!check.valid) throw badRequest('invalid_policy_value', check.error);
    }

    const diffRecord = [];
    await db.tx(async (client) => {
      for (const ch of changes) {
        const prev = await client.query(
          `SELECT * FROM policy_entries
           WHERE workspace_id = $1 AND scope_type = $2 AND scope_id = $3 AND key = $4`,
          [ws.id, scope_type, effectiveScopeId, ch.key],
        );
        await client.query(
          `INSERT INTO policy_entries (
             workspace_id, scope_type, scope_id, key, value_json, locked, updated_by, updated_at
           ) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, NOW())
           ON CONFLICT (workspace_id, scope_type, scope_id, key) DO UPDATE
           SET value_json = EXCLUDED.value_json,
               locked = EXCLUDED.locked,
               updated_by = EXCLUDED.updated_by,
               updated_at = NOW()`,
          [
            ws.id,
            scope_type,
            effectiveScopeId,
            ch.key,
            JSON.stringify(ch.value),
            Boolean(ch.locked),
            req.auth.userId,
          ],
        );
        diffRecord.push({
          scope_type,
          scope_id: effectiveScopeId,
          key: ch.key,
          previous_value: prev.rows[0]?.value_json ?? null,
          previous_locked: prev.rows[0]?.locked ?? false,
          new_value: ch.value,
          new_locked: Boolean(ch.locked),
        });
      }
    });

    const newVersion = await publishPolicyVersion({
      workspaceId: ws.id,
      publishedBy: req.auth.userId,
      reason,
      diffJson: { changes: diffRecord },
    });

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'policy.published',
      targetType: 'policy_version',
      targetId: newVersion,
      metadata: { version: newVersion, reason, changes: diffRecord },
    });

    // Push live policy.updated to active workspace users over WebSocket (POL-03)
    const activeUsers = await db.many(
      "SELECT id, profile_type FROM users WHERE (workspace_id = $1 OR workspace_id IS NULL) AND account_status = 'active'",
      [ws.id],
    );
    for (const u of activeUsers) {
      const bundle = await buildSignedPolicyBundle(ws.id, u.id, u.profile_type || 'workspace');
      sendToUser(u.id, 'policy.updated', {
        version: newVersion,
        reason,
        policy_bundle: bundle,
      });
    }

    res.json({
      success: true,
      version: newVersion,
      changes: diffRecord,
    });
  },
);

/**
 * POST /api/v1/admin/policies/rollback — Rollback to a prior policy version (POL-06).
 */
adminRouter.post(
  '/policies/rollback',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER'),
  validate({
    body: z.object({
      target_version: z.number().int().positive(),
      reason: z.string().trim().min(2).max(500).default('استعادة نسخة سابقة من السياسات'),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { target_version, reason } = req.body;

    const targetRow = await db.one(
      'SELECT * FROM policy_versions WHERE workspace_id = $1 AND version = $2',
      [ws.id, target_version],
    );
    if (!targetRow) throw notFound('policy_version_not_found', 'نسخة السياسة المطلوبة غير موجودة');

    // Revert changes applied in versions > target_version in reverse chronological order
    const subsequent = await db.many(
      'SELECT * FROM policy_versions WHERE workspace_id = $1 AND version > $2 ORDER BY version DESC',
      [ws.id, target_version],
    );

    await db.tx(async (client) => {
      for (const ver of subsequent) {
        const changes = ver.diff_json?.changes || [];
        for (const ch of changes) {
          if (ch.previous_value === null || ch.previous_value === undefined) {
            await client.query(
              `DELETE FROM policy_entries
               WHERE workspace_id = $1 AND scope_type = $2 AND scope_id = $3 AND key = $4`,
              [ws.id, ch.scope_type || 'workspace', ch.scope_id || ws.id, ch.key],
            );
          } else {
            await client.query(
              `UPDATE policy_entries
               SET value_json = $5::jsonb, locked = $6, updated_at = NOW()
               WHERE workspace_id = $1 AND scope_type = $2 AND scope_id = $3 AND key = $4`,
              [
                ws.id,
                ch.scope_type || 'workspace',
                ch.scope_id || ws.id,
                ch.key,
                JSON.stringify(ch.previous_value),
                Boolean(ch.previous_locked),
              ],
            );
          }
        }
      }
    });

    const newVersion = await publishPolicyVersion({
      workspaceId: ws.id,
      publishedBy: req.auth.userId,
      reason: `Rollback to v${target_version}: ${reason}`,
      diffJson: { rollback_to: target_version },
    });

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'policy.rollback',
      targetType: 'policy_version',
      targetId: newVersion,
      metadata: { target_version, new_version: newVersion, reason },
    });

    res.json({
      success: true,
      rolled_back_to: target_version,
      new_version: newVersion,
    });
  },
);

/* ============================================================================
 * AUDIT LOG, TAMPER-EVIDENT VERIFICATION, LEGAL HOLD, BREAK-GLASS & RETENTION
 * ========================================================================== */

/**
 * GET /api/v1/admin/audit-log — Paginated query of tamper-evident audit log (ADM-05).
 */
adminRouter.get(
  '/audit-log',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER', 'IT_ADMIN'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
    const action = req.query.action ? String(req.query.action) : null;

    const params = [ws.id];
    let filterSql = '';
    if (action) {
      params.push(action);
      filterSql = `AND al.action = $${params.length}`;
    }
    params.push(limit);

    const rows = await db.many(
      `SELECT al.id, al.workspace_id, al.actor_user_id, u.name AS actor_name,
              al.actor_device_id, al.action, al.target_type, al.target_id,
              COALESCE(al.metadata_json, al.metadata) AS metadata,
              al.metadata_json, al.ip_hash, al.created_at,
              al.prev_hash AS prev_hash_hex,
              al.row_hash AS row_hash_hex
       FROM audit_log al
       LEFT JOIN users u ON u.id = al.actor_user_id
       WHERE al.workspace_id = $1 ${filterSql}
       ORDER BY al.id DESC
       LIMIT $${params.length}`,
      params,
    );

    res.json({ success: true, entries: rows });
  },
);

/**
 * GET /api/v1/admin/audit-log/verify — Cryptographically verify the SHA-256 hash chain (ADM-05, TC-ADM).
 */
adminRouter.get(
  '/audit-log/verify',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER', 'IT_ADMIN'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const verification = await verifyAuditChain(ws.id);
    res.json({
      success: true,
      verification,
    });
  },
);

/**
 * GET /api/v1/admin/legal-holds — List active and historical legal holds (ADM-06).
 */
adminRouter.get(
  '/legal-holds',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rows = await db.many(
      `SELECT lh.*, u.name AS placed_by_name
       FROM legal_holds lh
       LEFT JOIN users u ON u.id = lh.placed_by
       WHERE lh.workspace_id = $1
       ORDER BY lh.created_at DESC`,
      [ws.id],
    );
    res.json({ success: true, legal_holds: rows });
  },
);

/**
 * POST /api/v1/admin/legal-holds — Place a legal hold on a channel or user (ADM-06).
 */
adminRouter.post(
  '/legal-holds',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER'),
  validate({
    body: z.object({
      scope_type: z.enum(['user', 'channel']),
      scope_id: z.string().trim().min(1),
      matter_ref: z.string().trim().min(2).max(160),
      reason: z.string().trim().min(3).max(1000),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { scope_type, scope_id, matter_ref, reason } = req.body;

    const hold = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO legal_holds (workspace_id, scope_type, scope_id, matter_ref, reason, placed_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [ws.id, scope_type, scope_id, matter_ref, reason, req.auth.userId],
      );
      if (scope_type === 'channel') {
        await client.query('UPDATE channels SET legal_hold = TRUE WHERE id = $1::uuid', [scope_id]);
      }
      return rows[0];
    });

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'legal_hold.placed',
      targetType: scope_type,
      targetId: scope_id,
      metadata: { hold_id: hold.id, matter_ref, reason },
    });

    res.status(201).json({ success: true, legal_hold: hold });
  },
);

/**
 * POST /api/v1/admin/legal-holds/:id/release — Release an active legal hold (ADM-06).
 */
adminRouter.post(
  '/legal-holds/:id/release',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER'),
  async (req, res) => {
    const hold = await db.one('SELECT * FROM legal_holds WHERE id = $1', [req.params.id]);
    if (!hold) throw notFound('legal_hold_not_found', 'أمر التجميد القانوني غير موجود');

    const updated = await db.tx(async (client) => {
      const { rows } = await client.query(
        'UPDATE legal_holds SET released_at = NOW() WHERE id = $1 RETURNING *',
        [hold.id],
      );
      if (hold.scope_type === 'channel') {
        const otherActive = await client.query(
          `SELECT 1 FROM legal_holds
           WHERE scope_type = 'channel' AND scope_id = $1 AND released_at IS NULL AND id <> $2`,
          [hold.scope_id, hold.id],
        );
        if (otherActive.rowCount === 0) {
          await client.query('UPDATE channels SET legal_hold = FALSE WHERE id = $1::uuid', [
            hold.scope_id,
          ]);
        }
      }
      return rows[0];
    });

    await appendAuditLog({
      workspaceId: hold.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'legal_hold.released',
      targetType: hold.scope_type,
      targetId: hold.scope_id,
      metadata: { hold_id: hold.id, matter_ref: hold.matter_ref },
    });

    res.json({ success: true, legal_hold: updated });
  },
);

/**
 * GET /api/v1/admin/break-glass — List emergency break-glass requests (ADM-07).
 */
adminRouter.get(
  '/break-glass',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER', 'EXEC_MANAGER', 'IT_ADMIN'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rows = await db.many(
      `SELECT bg.*, u1.name AS initiated_by_name, u2.name AS approved_by_name
       FROM break_glass bg
       LEFT JOIN users u1 ON u1.id = bg.initiated_by
       LEFT JOIN users u2 ON u2.id = bg.approved_by
       WHERE bg.workspace_id = $1
       ORDER BY bg.created_at DESC`,
      [ws.id],
    );
    res.json({ success: true, requests: rows });
  },
);

/**
 * POST /api/v1/admin/break-glass — Initiate a dual-control emergency break-glass request (ADM-07, AUD-02, TC-ADM).
 */
adminRouter.post(
  '/break-glass',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER', 'EXEC_MANAGER', 'IT_ADMIN'),
  validate({
    body: z.object({
      reason: z.string().trim().min(5).max(1000),
      scope: z.string().trim().min(2).max(200),
      duration_minutes: z.number().int().min(5).max(1440).default(60),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { reason, scope, duration_minutes } = req.body;
    const expiresAt = new Date(Date.now() + duration_minutes * 60_000);

    const row = await db.one(
      `INSERT INTO break_glass (
         workspace_id, initiated_by, reason, scope, expires_at, status
       ) VALUES ($1, $2, $3, $4, $5, 'pending_second_approval')
       RETURNING *`,
      [ws.id, req.auth.userId, reason, scope, expiresAt],
    );

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'break_glass.initiated',
      targetType: 'break_glass',
      targetId: row.id,
      metadata: { reason, scope, expires_at: expiresAt.toISOString() },
    });

    res.status(201).json({ success: true, break_glass: row });
  },
);

/**
 * POST /api/v1/admin/break-glass/:id/approve — Second-actor approval for break-glass (initiated_by != approved_by) (ADM-07, AUD-02).
 */
adminRouter.post(
  '/break-glass/:id/approve',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER', 'EXEC_MANAGER'),
  async (req, res) => {
    const bg = await db.one('SELECT * FROM break_glass WHERE id = $1', [req.params.id]);
    if (!bg) throw notFound('break_glass_not_found', 'طلب كسر الزجاج غير موجود');
    if (bg.status !== 'pending_second_approval') {
      throw badRequest('invalid_break_glass_state', 'الطلب ليس في حالة انتظار الموافقة الثانية');
    }
    if (Number(bg.initiated_by) === Number(req.auth.userId)) {
      throw forbidden(
        'dual_control_violation',
        'يتطلب إجراء كسر الزجاج موافقة مسؤول ثانٍ مستقل؛ لا يمكن لمقدم الطلب الموافقة على طلبه ذاته (ADM-07)',
      );
    }

    const updated = await db.one(
      `UPDATE break_glass
       SET approved_by = $2, status = 'active'
       WHERE id = $1
       RETURNING *`,
      [bg.id, req.auth.userId],
    );

    await appendAuditLog({
      workspaceId: bg.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'break_glass.approved',
      targetType: 'break_glass',
      targetId: bg.id,
      metadata: {
        initiated_by: bg.initiated_by,
        approved_by: req.auth.userId,
        scope: bg.scope,
      },
    });

    res.json({ success: true, break_glass: updated });
  },
);

/**
 * GET /api/v1/admin/break-glass/:id/inspect — Execute governed inspection using an active Dual-Control Break-Glass token (AUD-02, UC-06).
 * Only COMPLIANCE_OFFICER, EXEC_MANAGER, or SUPER_ADMIN can inspect; IT_ADMIN is strictly forbidden.
 * Confidential E2EE rooms (privacy_mode = 'confidential_e2ee' / 'enhanced_privacy') never expose plaintext on server.
 */
adminRouter.get(
  '/break-glass/:id/inspect',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER', 'EXEC_MANAGER'),
  async (req, res) => {
    const bg = await db.one('SELECT * FROM break_glass WHERE id = $1', [req.params.id]);
    if (!bg) throw notFound('break_glass_not_found', 'تصريح كسر الزجاج غير موجود');
    if (bg.status !== 'active') {
      throw forbidden('break_glass_not_active', 'تصريح كسر الزجاج غير مفعل؛ يتطلب موافقة ثنائية مسبقة (AUD-02)');
    }
    if (bg.expires_at && new Date(bg.expires_at).getTime() < Date.now()) {
      await db.query("UPDATE break_glass SET status = 'expired' WHERE id = $1", [bg.id]);
      throw forbidden('break_glass_expired', 'انتهت المهلة الزمنية لتصريح كسر الزجاج');
    }

    const scopeStr = String(bg.scope || '');
    let messages = [];
    let decisions = [];

    if (scopeStr.startsWith('channel:')) {
      const target = scopeStr.slice('channel:'.length).trim();
      const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(target);
      const ch = isUuid
        ? await db.one('SELECT * FROM channels WHERE id = $1 AND workspace_id = $2', [target, bg.workspace_id])
        : await db.one(
            'SELECT * FROM channels WHERE workspace_id = $1 AND (name ILIKE $2 OR description ILIKE $2) ORDER BY created_at DESC LIMIT 1',
            [bg.workspace_id, `%${target}%`],
          );

      if (ch) {
        const rawMsgs = await db.many(
          `SELECT cm.id, cm.channel_id, cm.seq, cm.sender_id, u.name AS sender_name,
                  cm.kind, cm.body_ciphertext, cm.body_iv, cm.key_id, cm.e2ee_envelope, cm.created_at
           FROM channel_messages cm
           LEFT JOIN users u ON u.id = cm.sender_id
           WHERE cm.channel_id = $1
           ORDER BY cm.seq ASC
           LIMIT 500`,
          [ch.id],
        );
        messages = rawMsgs.map((m) => {
          let body = null;
          if (ch.privacy_mode === 'standard_governed' && m.body_ciphertext && m.body_iv) {
            try {
              body = decryptField(m.body_ciphertext, m.body_iv, m.key_id);
            } catch {
              body = '[encrypted]';
            }
          }
          return {
            id: m.id,
            channel_id: m.channel_id,
            seq: Number(m.seq),
            sender_id: m.sender_id,
            sender_name: m.sender_name,
            kind: m.kind,
            privacy_mode: ch.privacy_mode || 'standard_governed',
            body: ch.privacy_mode === 'standard_governed' ? body : null,
            e2ee_protected: ch.privacy_mode !== 'standard_governed',
            created_at: m.created_at,
          };
        });
        decisions = await db.many(
          'SELECT id, title, rationale, status, decided_at FROM decisions WHERE channel_id = $1 ORDER BY decided_at DESC',
          [ch.id],
        );
      }
    } else if (scopeStr.startsWith('user:')) {
      const targetUserId = Number(scopeStr.slice('user:'.length).trim());
      if (Number.isFinite(targetUserId)) {
        const rawMsgs = await db.many(
          `SELECT cm.id, cm.channel_id, c.name AS channel_name, c.privacy_mode, cm.seq, cm.sender_id,
                  cm.kind, cm.body_ciphertext, cm.body_iv, cm.key_id, cm.created_at
           FROM channel_messages cm
           JOIN channels c ON c.id = cm.channel_id
           WHERE c.workspace_id = $1 AND cm.sender_id = $2
           ORDER BY cm.created_at DESC
           LIMIT 500`,
          [bg.workspace_id, targetUserId],
        );
        messages = rawMsgs.map((m) => ({
          id: m.id,
          channel_id: m.channel_id,
          channel_name: m.channel_name,
          seq: Number(m.seq),
          sender_id: m.sender_id,
          privacy_mode: m.privacy_mode || 'standard_governed',
          body:
            (m.privacy_mode || 'standard_governed') === 'standard_governed' && m.body_ciphertext && m.body_iv
              ? decryptField(m.body_ciphertext, m.body_iv, m.key_id)
              : null,
          e2ee_protected: (m.privacy_mode || 'standard_governed') !== 'standard_governed',
          created_at: m.created_at,
        }));
      }
    }

    await appendAuditLog({
      workspaceId: bg.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'break_glass.inspected',
      targetType: 'break_glass',
      targetId: bg.id,
      metadata: {
        scope: bg.scope,
        inspected_messages_count: messages.length,
        inspected_decisions_count: decisions.length,
      },
    });

    res.json({
      success: true,
      break_glass: {
        id: bg.id,
        scope: bg.scope,
        reason: bg.reason,
        initiated_by: bg.initiated_by,
        approved_by: bg.approved_by,
        expires_at: bg.expires_at,
      },
      records: {
        messages,
        decisions,
      },
    });
  },
);

/**
 * POST /api/v1/admin/retention/purge — Execute retention purge respecting legal_hold (TC-POL-18).
 */
adminRouter.post(
  '/retention/purge',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const policies = req.effectivePolicy?.policies || {};
    const messageDays = Number(policies['retention.message_days'] ?? 365);

    if (messageDays <= 0) {
      res.json({
        success: true,
        purged_messages: 0,
        note: 'retention.message_days = 0 (الاحتفاظ الدائم مفعل)',
      });
      return;
    }

    const cutoff = new Date(Date.now() - messageDays * 86_400_000);

    const purged = await db.many(
      `DELETE FROM channel_messages cm
       USING channels c
       WHERE cm.channel_id = c.id
         AND c.workspace_id = $1
         AND cm.created_at < $2
         AND c.legal_hold = FALSE
         AND NOT EXISTS (
           SELECT 1 FROM legal_holds lh
           WHERE lh.workspace_id = $1
             AND lh.released_at IS NULL
             AND (
               (lh.scope_type = 'channel' AND lh.scope_id = c.id::text)
               OR (lh.scope_type = 'user' AND lh.scope_id = cm.sender_id::text)
             )
         )
       RETURNING cm.id`,
      [ws.id, cutoff],
    );

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'retention.purge.executed',
      targetType: 'workspace',
      targetId: ws.id,
      metadata: {
        retention_message_days: messageDays,
        cutoff: cutoff.toISOString(),
        purged_count: purged.length,
      },
    });

    res.json({
      success: true,
      retention_message_days: messageDays,
      cutoff: cutoff.toISOString(),
      purged_messages: purged.length,
    });
  },
);

/**
 * Sanitizes CSV cell values against Formula Injection (Section 13.6).
 * Any cell starting with =, +, -, @, \t, or \r is prefixed with a single quote (')
 * and double quotes are escaped per RFC 4180.
 */
export function sanitizeCsvCell(value) {
  if (value === null || value === undefined) return '""';
  let str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * GET /api/v1/admin/audit-log/export — Export tamper-evident audit log in CSV or JSON with CSV Formula Injection sanitization (ADM-05, 13.6).
 */
adminRouter.get(
  '/audit-log/export',
  requireRoles('SUPER_ADMIN', 'COMPLIANCE_OFFICER'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const format = String(req.query.format || 'csv').toLowerCase();
    const limit = Math.min(Math.max(Number(req.query.limit) || 1000, 1), 10000);

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'audit.exported',
      targetType: 'workspace',
      targetId: ws.id,
      metadata: { format, limit },
    });

    const rows = await db.many(
      `SELECT al.id, al.workspace_id, al.actor_user_id, u.name AS actor_name,
              al.actor_device_id, al.action, al.target_type, al.target_id,
              COALESCE(al.metadata_json, al.metadata) AS metadata,
              al.created_at,
              al.prev_hash AS prev_hash_hex,
              al.row_hash AS row_hash_hex
       FROM audit_log al
       LEFT JOIN users u ON u.id = al.actor_user_id
       WHERE al.workspace_id = $1
       ORDER BY al.id ASC
       LIMIT $2`,
      [ws.id, limit],
    );

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.json({
        success: true,
        workspace_id: ws.id,
        exported_at: new Date().toISOString(),
        count: rows.length,
        entries: rows,
      });
      return;
    }

    const headers = [
      'id',
      'created_at',
      'action',
      'actor_user_id',
      'actor_name',
      'actor_device_id',
      'target_type',
      'target_id',
      'prev_hash_hex',
      'row_hash_hex',
      'metadata',
    ];
    const csvLines = [headers.join(',')];
    for (const r of rows) {
      csvLines.push(
        [
          sanitizeCsvCell(r.id),
          sanitizeCsvCell(r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at),
          sanitizeCsvCell(r.action),
          sanitizeCsvCell(r.actor_user_id),
          sanitizeCsvCell(r.actor_name),
          sanitizeCsvCell(r.actor_device_id),
          sanitizeCsvCell(r.target_type),
          sanitizeCsvCell(r.target_id),
          sanitizeCsvCell(r.prev_hash_hex),
          sanitizeCsvCell(r.row_hash_hex),
          sanitizeCsvCell(r.metadata),
        ].join(','),
      );
    }

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="madar-audit-${ws.id}.csv"`);
    res.send(csvLines.join('\n'));
  },
);

/**
 * POST /api/v1/admin/signing-keys/rotate — Rotate Ed25519 policy signing key (Section 13.7).
 */
adminRouter.post(
  '/signing-keys/rotate',
  requireRoles('SUPER_ADMIN'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rotated = await rotateWorkspaceSigningKey(ws.id);

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'signing_key.rotated',
      targetType: 'workspace',
      targetId: ws.id,
      metadata: { kid: rotated.kid, public_key_ed25519: rotated.publicKeyEd25519 },
    });

    res.json({
      success: true,
      kid: rotated.kid,
      public_key_ed25519: rotated.publicKeyEd25519,
    });
  },
);

/**
 * GET /api/v1/admin/cloud-services — Retrieve Cloud Relay (Push & SMS) & Official Domain verification state (ADM-02, ENR-06).
 */
adminRouter.get(
  '/cloud-services',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    let verifyToken = ws.domain_verify_token;
    if (!verifyToken) {
      verifyToken = `mdr_${crypto.randomBytes(12).toString('hex')}`;
      await db.query('UPDATE workspace SET domain_verify_token = $2 WHERE id = $1', [ws.id, verifyToken]);
    }
    const cfg = ws.cloud_services_config || {};
    const domain = ws.official_domain || 'workspace.local';

    res.json({
      success: true,
      cloud_services: {
        official_domain: ws.official_domain || '',
        domain_verified: Boolean(ws.domain_verified),
        domain_verified_at: ws.domain_verified_at || null,
        dns_txt_host: `_madar-verify.${domain}`,
        dns_txt_expected: `madar-domain-verify=${verifyToken}`,
        push_relay_enabled: Boolean(cfg.push_relay_enabled),
        relay_url: cfg.relay_url || process.env.MADAR_RELAY_URL || 'https://relay.madar.sa',
        tenant_token_configured: Boolean(cfg.tenant_token || process.env.TENANT_TOKEN),
        sms_provider: cfg.sms_provider || process.env.SMS_PROVIDER || 'console',
        sms_webhook_url: cfg.sms_webhook_url || process.env.SMS_WEBHOOK_URL || '',
      },
    });
  },
);

/**
 * PUT /api/v1/admin/cloud-services — Update Cloud Relay (TENANT_TOKEN, Push Relay, SMS Gateway) & Official Domain (ADM-02, ENR-06).
 */
adminRouter.put(
  '/cloud-services',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      official_domain: z.string().trim().max(255).optional(),
      push_relay_enabled: z.boolean().optional(),
      relay_url: z.string().trim().max(500).optional(),
      tenant_token: z.string().trim().max(500).optional(),
      sms_provider: z.enum(['madar_relay', 'webhook', 'console', 'none']).optional(),
      sms_webhook_url: z.string().trim().max(500).optional(),
      sms_webhook_secret: z.string().trim().max(255).optional(),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const prevCfg = ws.cloud_services_config || {};
    const nextDomain =
      req.body.official_domain !== undefined
        ? req.body.official_domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
        : ws.official_domain;
    const domainChanged = nextDomain !== ws.official_domain;
    const verifyToken = ws.domain_verify_token || `mdr_${crypto.randomBytes(12).toString('hex')}`;

    const nextCfg = {
      ...prevCfg,
      ...(req.body.push_relay_enabled !== undefined ? { push_relay_enabled: req.body.push_relay_enabled } : {}),
      ...(req.body.relay_url !== undefined ? { relay_url: req.body.relay_url } : {}),
      ...(req.body.tenant_token ? { tenant_token: req.body.tenant_token } : {}),
      ...(req.body.sms_provider !== undefined ? { sms_provider: req.body.sms_provider } : {}),
      ...(req.body.sms_webhook_url !== undefined ? { sms_webhook_url: req.body.sms_webhook_url } : {}),
      ...(req.body.sms_webhook_secret ? { sms_webhook_secret: req.body.sms_webhook_secret } : {}),
    };

    const updated = await db.one(
      `UPDATE workspace
       SET official_domain = $2,
           domain_verify_token = $3,
           domain_verified = CASE WHEN $4 THEN FALSE ELSE domain_verified END,
           cloud_services_config = $5::jsonb
       WHERE id = $1
       RETURNING *`,
      [ws.id, nextDomain || null, verifyToken, domainChanged, JSON.stringify(nextCfg)],
    );

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'cloud_services.updated',
      targetType: 'workspace',
      targetId: ws.id,
      metadata: {
        official_domain: updated.official_domain,
        push_relay_enabled: nextCfg.push_relay_enabled,
        sms_provider: nextCfg.sms_provider,
      },
    });

    res.json({
      success: true,
      cloud_services: {
        official_domain: updated.official_domain || '',
        domain_verified: Boolean(updated.domain_verified),
        dns_txt_host: `_madar-verify.${updated.official_domain || 'workspace.local'}`,
        dns_txt_expected: `madar-domain-verify=${verifyToken}`,
        push_relay_enabled: Boolean(nextCfg.push_relay_enabled),
        relay_url: nextCfg.relay_url || 'https://relay.madar.sa',
        tenant_token_configured: Boolean(nextCfg.tenant_token),
        sms_provider: nextCfg.sms_provider || 'console',
        sms_webhook_url: nextCfg.sms_webhook_url || '',
      },
    });
  },
);

/**
 * POST /api/v1/admin/cloud-services/verify-domain — Verify Official Domain ownership via DNS TXT record _madar-verify.<domain> (ENR-06).
 */
adminRouter.post(
  '/cloud-services/verify-domain',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z
      .object({
        simulated_txt_record: z.string().optional(),
      })
      .optional(),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    if (!ws.official_domain) {
      throw badRequest('missing_official_domain', 'يرجى حفظ النطاق الرسمي لمساحة العمل أولاً قبل التحقق');
    }
    const verifyToken = ws.domain_verify_token || `mdr_${crypto.randomBytes(12).toString('hex')}`;
    const expectedTxt = `madar-domain-verify=${verifyToken}`;
    const txtHost = `_madar-verify.${ws.official_domain}`;

    let verified = false;
    let foundRecords = [];

    if (req.body?.simulated_txt_record && !env.IS_PROD) {
      foundRecords = [req.body.simulated_txt_record];
      verified = foundRecords.includes(expectedTxt);
    } else {
      try {
        const records = await dns.resolveTxt(txtHost);
        foundRecords = records.map((chunks) => chunks.join(''));
        verified = foundRecords.some((r) => r.trim() === expectedTxt);
      } catch {
        verified = false;
      }
    }

    if (!verified) {
      throw badRequest(
        'domain_verification_failed',
        `لم يتم العثور على سجل DNS TXT المطابق (${expectedTxt}) على المضيف ${txtHost}`,
      );
    }

    const updated = await db.one(
      `UPDATE workspace
       SET domain_verified = TRUE,
           domain_verified_at = NOW(),
           domain_verify_token = $2
       WHERE id = $1
       RETURNING *`,
      [ws.id, verifyToken],
    );

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'domain.verified',
      targetType: 'workspace',
      targetId: ws.id,
      metadata: {
        official_domain: updated.official_domain,
        dns_txt_host: txtHost,
      },
    });

    res.json({
      success: true,
      official_domain: updated.official_domain,
      domain_verified: true,
      domain_verified_at: updated.domain_verified_at,
    });
  },
);

/**
 * Executes Active Directory / IdP user synchronization for a provider (AUTH-06).
 * Provisions new accounts, updates attributes, and automatically suspends/offboards
 * and revokes sessions + triggers selective device wipe for accounts disabled in the directory.
 */
export async function syncAuthProviderById(providerId, { actorUserId = null, actorDeviceId = null, directoryOverride = null } = {}) {
  const provider = await db.one('SELECT * FROM auth_providers WHERE id = $1', [providerId]);
  if (!provider) throw notFound('auth_provider_not_found', 'مزود الهوية غير موجود');

  const configJson = JSON.parse(
    decryptField(provider.config_ciphertext, provider.config_iv, provider.key_id),
  );
  const entries = Array.isArray(directoryOverride)
    ? directoryOverride
    : Array.isArray(configJson.directory_entries)
      ? configJson.directory_entries
      : [];

  if (Array.isArray(directoryOverride)) {
    configJson.directory_entries = directoryOverride;
    const reEnc = encryptField(JSON.stringify(configJson));
    await db.query(
      'UPDATE auth_providers SET config_ciphertext = $2, config_iv = $3, key_id = $4 WHERE id = $1',
      [provider.id, reEnc.ciphertext, reEnc.iv, reEnc.keyId],
    );
  }

  const depts = await db.many('SELECT id, code, channel_id, head_user_id FROM departments WHERE workspace_id = $1', [
    provider.workspace_id,
  ]);
  const deptByCode = new Map(depts.map((d) => [String(d.code || '').toLowerCase(), d]));

  let provisionedCount = 0;
  let updatedCount = 0;
  let disabledCount = 0;
  const wipedDevices = [];

  for (const item of entries) {
    const extId = String(item.dn || item.external_id || item.employee_no || item.username || '');
    const empNo = item.employee_no || item.username || extId;
    const email = item.email ? String(item.email).toLowerCase() : null;
    if (!extId && !empNo) continue;

    const dept = item.department_code
      ? deptByCode.get(String(item.department_code).toLowerCase())
      : null;

    const existing = await db.one(
      `SELECT * FROM users
       WHERE workspace_id = $1
         AND (
           (external_idp_id IS NOT NULL AND external_idp_id = $2)
           OR (employee_no IS NOT NULL AND employee_no = $3)
           OR (email IS NOT NULL AND LOWER(email) = LOWER($4))
         )
       LIMIT 1`,
      [provider.workspace_id, extId, empNo, email || ''],
    );

    const isDisabled = item.active === false || item.disabled === true || item.status === 'disabled';

    if (isDisabled) {
      if (existing && existing.account_status !== 'offboarded') {
        const wipeCmdId = crypto.randomUUID();
        await db.tx(async (client) => {
          await client.query(
            `UPDATE users
             SET account_status = 'offboarded', offboarded_at = NOW()
             WHERE id = $1`,
            [existing.id],
          );
          await client.query(
            'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL',
            [existing.id],
          );
          const { rows: devs } = await client.query(
            `UPDATE devices
             SET status = 'wipe_pending', wipe_command_id = $2, wipe_requested_at = NOW()
             WHERE user_id = $1 AND status IN ('active', 'suspended')
             RETURNING id, device_name`,
            [existing.id, wipeCmdId],
          );
          for (const d of devs) wipedDevices.push(d.id);
        });
        sendToUser(existing.id, 'device.wipe', {
          wipe_command_id: wipeCmdId,
          reason: 'directory_account_disabled',
          issued_at: new Date().toISOString(),
        });
        sendToUser(existing.id, 'session.revoked', {
          user_id: existing.id,
          reason: 'directory_sync_disabled',
        });
        disconnectUser(existing.id);
        disabledCount += 1;
      }
      continue;
    }

    if (!existing) {
      const created = await db.one(
        `INSERT INTO users (
           workspace_id, employee_no, name, email, title, department_id,
           account_status, profile_type, external_idp_id, auth_provider_id
         ) VALUES ($1, $2, $3, $4, $5, $6, 'active', 'workspace', $7, $8)
         RETURNING *`,
        [
          provider.workspace_id,
          empNo,
          item.name || empNo,
          email,
          item.title || '',
          dept?.id || null,
          extId,
          provider.id,
        ],
      );
      await db.query(
        'INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [created.id, item.role || 'MEMBER'],
      );
      if (dept?.channel_id) {
        await db.query(
          `INSERT INTO channel_members (channel_id, user_id, role)
           VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING`,
          [dept.channel_id, created.id],
        );
      }
      provisionedCount += 1;
    } else {
      await db.query(
        `UPDATE users
         SET name = COALESCE($2, name),
             email = COALESCE($3, email),
             title = COALESCE($4, title),
             department_id = COALESCE($5, department_id),
             external_idp_id = COALESCE($6, external_idp_id),
             auth_provider_id = $7
         WHERE id = $1`,
        [existing.id, item.name || null, email, item.title || null, dept?.id || null, extId, provider.id],
      );
      updatedCount += 1;
    }
  }

  const summary = {
    provisioned_count: provisionedCount,
    updated_count: updatedCount,
    disabled_count: disabledCount,
    wiped_devices: wipedDevices,
    synced_at: new Date().toISOString(),
  };

  await db.query(
    `UPDATE auth_providers
     SET last_synced_at = NOW(),
         last_sync_status = 'success',
         last_sync_summary = $2::jsonb
     WHERE id = $1`,
    [provider.id, JSON.stringify(summary)],
  );

  await appendAuditLog({
    workspaceId: provider.workspace_id,
    actorUserId,
    actorDeviceId,
    action: 'auth_provider.synced',
    targetType: 'auth_provider',
    targetId: provider.id,
    metadata: summary,
  });

  return summary;
}

/**
 * GET /api/v1/admin/auth-providers — List configured Enterprise Identity Providers (AUTH-01, AUTH-06).
 */
adminRouter.get(
  '/auth-providers',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const rows = await db.many(
      `SELECT id, workspace_id, kind, name, enabled, sync_interval_minutes,
              last_synced_at, last_sync_status, last_sync_summary, created_at
       FROM auth_providers
       WHERE workspace_id = $1
       ORDER BY created_at ASC`,
      [ws.id],
    );
    res.json({ success: true, providers: rows });
  },
);

/**
 * POST /api/v1/admin/auth-providers — Configure an Enterprise Identity Provider (OIDC, SAML 2.0, Active Directory LDAP) (AUTH-01, AUTH-06).
 */
adminRouter.post(
  '/auth-providers',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z.object({
      kind: z.enum(['oidc', 'saml', 'ldap']),
      name: z.string().trim().min(2).max(80),
      enabled: z.boolean().default(true),
      sync_interval_minutes: z.number().int().min(5).max(1440).default(15),
      config: z.record(z.string(), z.any()),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const { kind, name, enabled, sync_interval_minutes, config } = req.body;
    const enc = encryptField(JSON.stringify(config));

    const row = await db.one(
      `INSERT INTO auth_providers (
         workspace_id, kind, name, config_ciphertext, config_iv, key_id,
         enabled, sync_interval_minutes
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, workspace_id, kind, name, enabled, sync_interval_minutes, created_at`,
      [ws.id, kind, name, enc.ciphertext, enc.iv, enc.keyId, enabled, sync_interval_minutes],
    );

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'auth_provider.created',
      targetType: 'auth_provider',
      targetId: row.id,
      metadata: { kind, name, sync_interval_minutes },
    });

    res.status(201).json({ success: true, provider: row });
  },
);

/**
 * POST /api/v1/admin/auth-providers/:id/sync — Trigger immediate Active Directory / IdP synchronization (AUTH-06).
 */
adminRouter.post(
  '/auth-providers/:id/sync',
  requireRoles('SUPER_ADMIN', 'IT_ADMIN'),
  validate({
    body: z
      .object({
        directory_entries: z.array(z.record(z.string(), z.any())).optional(),
      })
      .optional(),
  }),
  async (req, res) => {
    const summary = await syncAuthProviderById(req.params.id, {
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      directoryOverride: req.body?.directory_entries,
    });
    res.json({ success: true, sync: summary });
  },
);


