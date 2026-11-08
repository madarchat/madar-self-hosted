import { Router } from 'express';
import { db } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { attachPolicyContext } from '../middleware/policyGuard.js';
import { validate, z } from '../lib/validate.js';
import { badRequest, forbidden, notFound, tooMany } from '../lib/errors.js';
import { encryptField, decryptField } from '../lib/fieldCrypto.js';
import { appendAuditLog } from '../lib/audit.js';
import { indexSearchDoc } from '../lib/arabicSearch.js';
import { ensureDefaultWorkspace } from '../services/policyEngine.js';
import { sendToUsers } from '../realtime/ws.js';

export const broadcastsRouter = Router();
broadcastsRouter.use(requireAuth, attachPolicyContext);

async function generateBroadcastRefNo(workspaceId) {
  const year = new Date().getUTCFullYear();
  const row = await db.one(
    'SELECT COUNT(*)::int AS c FROM broadcasts WHERE workspace_id = $1',
    [workspaceId],
  );
  const seq = (row?.c || 0) + 1;
  return `BRD-${year}-${String(seq).padStart(4, '0')}`;
}

async function resolveTargetUsers(workspaceId, targetSpec) {
  const scope = targetSpec?.scope || 'all';
  if (scope === 'all') {
    return db.many(
      `SELECT id, department_id FROM users
       WHERE (workspace_id = $1 OR workspace_id IS NULL) AND account_status = 'active'`,
      [workspaceId],
    );
  }

  const userMap = new Map();

  if (Array.isArray(targetSpec?.department_ids) && targetSpec.department_ids.length > 0) {
    const rows = await db.many(
      `SELECT id, department_id FROM users
       WHERE (workspace_id = $1 OR workspace_id IS NULL)
         AND account_status = 'active'
         AND department_id = ANY($2::uuid[])`,
      [workspaceId, targetSpec.department_ids],
    );
    for (const r of rows) userMap.set(r.id, r);
  }

  if (Array.isArray(targetSpec?.roles) && targetSpec.roles.length > 0) {
    const rows = await db.many(
      `SELECT DISTINCT u.id, u.department_id
       FROM users u
       JOIN user_roles ur ON ur.user_id = u.id
       WHERE (u.workspace_id = $1 OR u.workspace_id IS NULL)
         AND u.account_status = 'active'
         AND ur.role = ANY($2::text[])`,
      [workspaceId, targetSpec.roles],
    );
    for (const r of rows) userMap.set(r.id, r);
  }

  if (Array.isArray(targetSpec?.group_ids) && targetSpec.group_ids.length > 0) {
    const rows = await db.many(
      `SELECT DISTINCT u.id, u.department_id
       FROM users u
       JOIN policy_group_members pgm ON pgm.user_id = u.id
       WHERE pgm.group_id = ANY($1::uuid[]) AND u.account_status = 'active'`,
      [targetSpec.group_ids],
    );
    for (const r of rows) userMap.set(r.id, r);
  }

  if (Array.isArray(targetSpec?.user_ids) && targetSpec.user_ids.length > 0) {
    const rows = await db.many(
      `SELECT id, department_id FROM users
       WHERE id = ANY($1::bigint[]) AND account_status = 'active'`,
      [targetSpec.user_ids],
    );
    for (const r of rows) userMap.set(r.id, r);
  }

  return [...userMap.values()];
}

async function hydrateBroadcast(row, viewerUserId) {
  const version = await db.one(
    `SELECT * FROM broadcast_versions
     WHERE broadcast_id = $1 AND version_no = $2`,
    [row.id, row.current_version],
  );
  const body = version
    ? decryptField(version.body_ciphertext, version.body_iv, version.key_id)
    : '';

  const receipt = viewerUserId
    ? await db.one(
        `SELECT * FROM broadcast_receipts
         WHERE broadcast_id = $1 AND version_no = $2 AND user_id = $3`,
        [row.id, row.current_version, viewerUserId],
      )
    : null;

  const statsRow = await db.one(
    `SELECT
       (SELECT COUNT(*)::int FROM broadcast_recipients WHERE broadcast_id = $1) AS total_recipients,
       (SELECT COUNT(*)::int FROM broadcast_receipts WHERE broadcast_id = $1 AND version_no = $2) AS ack_count`,
    [row.id, row.current_version],
  );

  return {
    id: row.id,
    workspace_id: row.workspace_id,
    ref_no: row.ref_no,
    sender_id: row.sender_id,
    sender_name: row.sender_name || null,
    sender_title: row.sender_title || null,
    title: version?.title || '',
    body,
    change_note: version?.change_note || null,
    material_change: Boolean(version?.material_change),
    priority: row.priority,
    ack_type: row.ack_type,
    quiz_json: row.quiz_json
      ? {
          question: row.quiz_json.question,
          options: row.quiz_json.options,
          correct_index: row.quiz_json.correct_index ?? 0,
        }
      : null,
    ack_deadline: row.ack_deadline,
    target_spec: row.target_spec,
    status: row.status,
    current_version: row.current_version,
    published_at: row.published_at,
    retracted_at: row.retracted_at,
    retract_reason: row.retract_reason,
    acknowledged: Boolean(receipt),
    acknowledged_at: receipt?.acked_at || null,
    total_recipients: statsRow?.total_recipients || 0,
    ack_count: statsRow?.ack_count || 0,
  };
}

/**
 * GET /api/v1/broadcasts/templates — List reusable official broadcast templates (BRD-06).
 */
broadcastsRouter.get('/templates', async (req, res) => {
  const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
  const rows = await db.many(
    'SELECT * FROM broadcast_templates WHERE workspace_id = $1 ORDER BY created_at DESC',
    [wsId],
  );
  res.json({ success: true, templates: rows });
});

/**
 * POST /api/v1/broadcasts/templates — Create reusable broadcast template (BRD-06).
 */
broadcastsRouter.post(
  '/templates',
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(160),
      category: z.string().trim().max(80).default('general'),
      title_template: z.string().trim().min(1).max(300),
      body_template: z.string().trim().min(1).max(20_000),
      default_priority: z.enum(['info', 'important', 'mandatory_ack']).default('info'),
      default_ack_type: z.enum(['view', 'scroll_ack', 'quiz_ack']).default('view'),
    }),
  }),
  async (req, res) => {
    const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
    const allowedRoles = req.effectivePolicy?.policies?.['broadcast.allowed_sender_roles'] || [
      'SUPER_ADMIN',
      'DEPT_HEAD',
      'BROADCASTER',
    ];
    const callerRoles = req.auth.roles || [];
    if (!callerRoles.some((r) => allowedRoles.includes(r))) {
      throw forbidden('broadcast_role_required', 'غير مصرح لك بإنشاء قوالب التعاميم الرسمية');
    }

    const { name, category, title_template, body_template, default_priority, default_ack_type } = req.body;
    const tpl = await db.one(
      `INSERT INTO broadcast_templates (
         workspace_id, name, category, title_template, body_template,
         default_priority, default_ack_type, created_by
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [wsId, name, category, title_template, body_template, default_priority, default_ack_type, req.auth.userId],
    );
    res.status(201).json({ success: true, template: tpl });
  },
);

/**
 * GET /api/v1/broadcasts — List broadcasts visible to the caller.
 */
broadcastsRouter.get('/', async (req, res) => {
  const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
  const rows = await db.many(
    `SELECT b.*, u.name AS sender_name, u.title AS sender_title
     FROM broadcasts b
     LEFT JOIN users u ON u.id = b.sender_id
     WHERE b.workspace_id = $1
       AND (
         b.sender_id = $2
         OR EXISTS (SELECT 1 FROM broadcast_recipients br WHERE br.broadcast_id = b.id AND br.user_id = $2)
         OR $3 = TRUE
       )
     ORDER BY b.published_at DESC NULLS LAST, b.id DESC
     LIMIT 100`,
    [
      wsId,
      req.auth.userId,
      (req.auth.roles || []).some((r) => ['SUPER_ADMIN', 'COMPLIANCE_OFFICER', 'BROADCASTER'].includes(r)),
    ],
  );

  const items = await Promise.all(rows.map((r) => hydrateBroadcast(r, req.auth.userId)));
  res.json({ success: true, broadcasts: items });
});

/**
 * POST /api/v1/broadcasts — Publish an official broadcast (BRD-01..06, TC-POL-16, TC-POL-17, TC-BRD).
 */
broadcastsRouter.post(
  '/',
  validate({
    body: z.object({
      title: z.string().trim().min(1).max(300),
      body: z.string().trim().min(1).max(50_000),
      priority: z.enum(['info', 'important', 'mandatory_ack']).default('info'),
      ack_type: z.enum(['view', 'scroll_ack', 'quiz_ack']).default('view'),
      quiz_json: z
        .object({
          question: z.string().trim().min(1).max(500),
          options: z.array(z.string().trim().min(1).max(200)).min(2).max(6),
          correct_index: z.number().int().min(0).max(5),
        })
        .nullable()
        .optional(),
      ack_deadline: z.string().datetime().nullable().optional(),
      target_spec: z
        .object({
          scope: z.enum(['all', 'custom']).default('all'),
          department_ids: z.array(z.string().uuid()).optional(),
          roles: z.array(z.string()).optional(),
          group_ids: z.array(z.string().uuid()).optional(),
          user_ids: z.array(z.number().int()).optional(),
        })
        .default({ scope: 'all' }),
      override_quota: z.boolean().optional(),
      override_reason: z.string().trim().max(500).optional(),
    }),
  }),
  async (req, res) => {
    const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
    const policies = req.effectivePolicy?.policies || {};
    const allowedRoles = policies['broadcast.allowed_sender_roles'] || [
      'SUPER_ADMIN',
      'DEPT_HEAD',
      'BROADCASTER',
    ];
    const callerRoles = req.auth.roles || [];

    if (!callerRoles.some((r) => allowedRoles.includes(r))) {
      throw forbidden(
        'broadcast_sender_forbidden',
        'دورك الوظيفي غير مخوّل بإصدار التعاميم الرسمية (broadcast.allowed_sender_roles)',
      );
    }

    const {
      title,
      body,
      priority,
      ack_type,
      quiz_json,
      ack_deadline,
      target_spec,
      override_quota,
      override_reason,
    } = req.body;

    if (ack_type === 'quiz_ack' && !quiz_json) {
      throw badRequest('quiz_required', 'نوع الإقرار بالسؤال (quiz_ack) يتطلب إرفاق سؤال التحقق (quiz_json)');
    }

    // Enforce broadcast.max_mandatory_per_week (TC-POL-17)
    if (priority === 'mandatory_ack') {
      const maxPerWeek = Number(policies['broadcast.max_mandatory_per_week'] ?? 5);
      const recentCountRow = await db.one(
        `SELECT COUNT(*)::int AS c
         FROM broadcasts
         WHERE workspace_id = $1
           AND priority = 'mandatory_ack'
           AND status = 'published'
           AND published_at > NOW() - INTERVAL '7 days'`,
        [wsId],
      );
      const recentCount = recentCountRow?.c || 0;
      if (recentCount >= maxPerWeek) {
        const canOverride =
          override_quota === true &&
          callerRoles.some((r) => ['SUPER_ADMIN', 'COMPLIANCE_OFFICER'].includes(r));
        if (!canOverride) {
          throw tooMany(
            'mandatory_broadcast_quota_exceeded',
            `تم الوصول للحد الأقصى للتعاميم الإلزامية الأسبوعية (${maxPerWeek}) بموجب سياسة المؤسسة (broadcast.max_mandatory_per_week)`,
          );
        }
        await appendAuditLog({
          workspaceId: wsId,
          actorUserId: req.auth.userId,
          actorDeviceId: req.auth.deviceId,
          action: 'broadcast.quota_override',
          targetType: 'workspace',
          targetId: wsId,
          metadata: {
            max_mandatory_per_week: maxPerWeek,
            current_week_count: recentCount,
            override_reason: override_reason || 'تجاوز إداري معتمد',
          },
        });
      }
    }

    const refNo = await generateBroadcastRefNo(wsId);
    const enc = encryptField(body);
    const recipients = await resolveTargetUsers(wsId, target_spec);
    if (!recipients.some((r) => r.id === req.auth.userId)) {
      const senderRow = await db.one('SELECT id, department_id FROM users WHERE id = $1', [req.auth.userId]);
      if (senderRow) recipients.push(senderRow);
    }

    const broadcast = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO broadcasts (
           workspace_id, ref_no, sender_id, priority, ack_type, quiz_json,
           ack_deadline, target_spec, status, current_version, published_at
         ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::jsonb, 'published', 1, NOW())
         RETURNING *`,
        [
          wsId,
          refNo,
          req.auth.userId,
          priority,
          ack_type,
          quiz_json ? JSON.stringify(quiz_json) : null,
          ack_deadline ? new Date(ack_deadline) : null,
          JSON.stringify(target_spec),
        ],
      );
      const b = rows[0];

      await client.query(
        `INSERT INTO broadcast_versions (
           broadcast_id, version_no, title, body_ciphertext, body_iv, key_id,
           change_note, material_change, edited_by
         ) VALUES ($1, 1, $2, $3, $4, $5, NULL, TRUE, $6)`,
        [b.id, title, enc.ciphertext, enc.iv, enc.keyId, req.auth.userId],
      );

      const hubSection =
        priority === 'mandatory_ack' || ack_type !== 'view' ? 'requires_action' : 'announcements';
      const hubPriority = hubSection === 'requires_action' ? 100 : 50;

      for (const r of recipients) {
        await client.query(
          `INSERT INTO broadcast_recipients (broadcast_id, user_id, department_id, delivered_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (broadcast_id, user_id) DO NOTHING`,
          [b.id, r.id, r.department_id || null],
        );
        await client.query(
          `INSERT INTO hub_items (
             workspace_id, user_id, section, source_type, source_id, priority, due_at
           ) VALUES ($1, $2, $3, 'broadcast', $4, $5, $6)`,
          [
            wsId,
            r.id,
            hubSection,
            b.id,
            hubPriority,
            ack_deadline ? new Date(ack_deadline) : null,
          ],
        );
      }

      return b;
    });

    await indexSearchDoc({
      workspaceId: wsId,
      docType: 'broadcast',
      docId: broadcast.id,
      channelId: null,
      title: `${refNo} ${title}`,
      body,
    });

    await appendAuditLog({
      workspaceId: wsId,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'broadcast.published',
      targetType: 'broadcast',
      targetId: broadcast.id,
      metadata: {
        ref_no: refNo,
        priority,
        ack_type,
        recipient_count: recipients.length,
      },
    });

    const hydrated = await hydrateBroadcast(broadcast, req.auth.userId);
    sendToUsers(
      recipients.map((r) => r.id),
      'broadcast.new',
      { broadcast: hydrated },
    );

    res.status(201).json({
      success: true,
      broadcast: hydrated,
    });
  },
);

/**
 * PATCH /api/v1/broadcasts/:id — Edit / issue new version of a broadcast (BRD-08, TC-BRD).
 */
broadcastsRouter.patch(
  '/:id',
  validate({
    body: z.object({
      title: z.string().trim().min(1).max(300).optional(),
      body: z.string().trim().min(1).max(50_000),
      change_note: z.string().trim().min(1).max(500),
      material_change: z.boolean().default(false),
    }),
  }),
  async (req, res) => {
    const existing = await db.one('SELECT * FROM broadcasts WHERE id = $1', [req.params.id]);
    if (!existing) throw notFound('broadcast_not_found', 'التعميم غير موجود');
    if (existing.status === 'retracted') {
      throw badRequest('broadcast_retracted', 'لا يمكن تعديل تعميم تم سحبه');
    }

    const callerRoles = req.auth.roles || [];
    const canEdit =
      existing.sender_id === req.auth.userId ||
      callerRoles.some((r) => ['SUPER_ADMIN', 'BROADCASTER'].includes(r));
    if (!canEdit) {
      throw forbidden('forbidden_broadcast_edit', 'غير مصرح لك بتعديل هذا التعميم');
    }

    const prevVersion = await db.one(
      'SELECT * FROM broadcast_versions WHERE broadcast_id = $1 AND version_no = $2',
      [existing.id, existing.current_version],
    );

    const nextVersionNo = existing.current_version + 1;
    const nextTitle = req.body.title || prevVersion?.title || '';
    const enc = encryptField(req.body.body);
    const materialChange = Boolean(req.body.material_change);

    const updated = await db.tx(async (client) => {
      await client.query(
        `INSERT INTO broadcast_versions (
           broadcast_id, version_no, title, body_ciphertext, body_iv, key_id,
           change_note, material_change, edited_by
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          existing.id,
          nextVersionNo,
          nextTitle,
          enc.ciphertext,
          enc.iv,
          enc.keyId,
          req.body.change_note,
          materialChange,
          req.auth.userId,
        ],
      );

      const { rows } = await client.query(
        `UPDATE broadcasts SET current_version = $2 WHERE id = $1 RETURNING *`,
        [existing.id, nextVersionNo],
      );

      if (!materialChange) {
        // Carry over prior version receipts to the new non-material version
        await client.query(
          `INSERT INTO broadcast_receipts (broadcast_id, version_no, user_id, device_id, ack_type, quiz_answer, acked_at)
           SELECT broadcast_id, $2, user_id, device_id, ack_type, quiz_answer, acked_at
           FROM broadcast_receipts
           WHERE broadcast_id = $1 AND version_no = $3
           ON CONFLICT DO NOTHING`,
          [existing.id, nextVersionNo, existing.current_version],
        );
      } else {
        // Material change: re-open hub_items for all recipients so they must re-acknowledge
        await client.query(
          `UPDATE hub_items
           SET resolved_at = NULL, created_at = NOW()
           WHERE source_type = 'broadcast' AND source_id = $1`,
          [existing.id],
        );
      }

      return rows[0];
    });

    await indexSearchDoc({
      workspaceId: existing.workspace_id,
      docType: 'broadcast',
      docId: existing.id,
      channelId: null,
      title: `${existing.ref_no} ${nextTitle}`,
      body: req.body.body,
    });

    await appendAuditLog({
      workspaceId: existing.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'broadcast.updated',
      targetType: 'broadcast',
      targetId: existing.id,
      metadata: {
        version_no: nextVersionNo,
        material_change: materialChange,
        change_note: req.body.change_note,
      },
    });

    const recipientRows = await db.many(
      'SELECT user_id FROM broadcast_recipients WHERE broadcast_id = $1',
      [existing.id],
    );
    const hydrated = await hydrateBroadcast(updated, req.auth.userId);
    sendToUsers(
      recipientRows.map((r) => r.user_id),
      'broadcast.updated',
      {
        broadcast: hydrated,
        version_no: nextVersionNo,
        material_change: materialChange,
      },
    );

    res.json({
      success: true,
      broadcast: hydrated,
    });
  },
);

/**
 * POST /api/v1/broadcasts/:id/retract — Retract an official broadcast with mandatory reason (BRD-08).
 */
broadcastsRouter.post(
  '/:id/retract',
  validate({
    body: z.object({
      reason: z.string().trim().min(3).max(500),
    }),
  }),
  async (req, res) => {
    const existing = await db.one('SELECT * FROM broadcasts WHERE id = $1', [req.params.id]);
    if (!existing) throw notFound('broadcast_not_found', 'التعميم غير موجود');

    const callerRoles = req.auth.roles || [];
    const canRetract =
      existing.sender_id === req.auth.userId ||
      callerRoles.some((r) => ['SUPER_ADMIN', 'COMPLIANCE_OFFICER', 'BROADCASTER'].includes(r));
    if (!canRetract) {
      throw forbidden('forbidden_broadcast_retract', 'غير مصرح لك بسحب هذا التعميم');
    }

    const updated = await db.one(
      `UPDATE broadcasts
       SET status = 'retracted', retracted_at = NOW(), retract_reason = $2
       WHERE id = $1
       RETURNING *`,
      [existing.id, req.body.reason],
    );

    await db.query(
      `UPDATE hub_items SET resolved_at = NOW()
       WHERE source_type = 'broadcast' AND source_id = $1 AND resolved_at IS NULL`,
      [existing.id],
    );

    await appendAuditLog({
      workspaceId: existing.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'broadcast.retracted',
      targetType: 'broadcast',
      targetId: existing.id,
      metadata: { reason: req.body.reason },
    });

    const recipientRows = await db.many(
      'SELECT user_id FROM broadcast_recipients WHERE broadcast_id = $1',
      [existing.id],
    );
    sendToUsers(
      recipientRows.map((r) => r.user_id),
      'broadcast.retracted',
      {
        broadcast_id: existing.id,
        ref_no: existing.ref_no,
        reason: req.body.reason,
      },
    );

    res.json({
      success: true,
      broadcast: await hydrateBroadcast(updated, req.auth.userId),
    });
  },
);

/**
 * POST /api/v1/broadcasts/:id/ack — Acknowledge a broadcast (view, scroll_ack, quiz_ack) (BRD-03, TC-BRD).
 */
broadcastsRouter.post(
  '/:id/ack',
  validate({
    body: z.object({
      ack_type: z.enum(['view', 'scroll_ack', 'quiz_ack']).optional(),
      scrolled_to_end: z.boolean().optional(),
      quiz_answer_index: z.number().int().optional(),
    }),
  }),
  async (req, res) => {
    const broadcast = await db.one('SELECT * FROM broadcasts WHERE id = $1', [req.params.id]);
    if (!broadcast) throw notFound('broadcast_not_found', 'التعميم غير موجود');
    if (broadcast.status === 'retracted') {
      throw badRequest('broadcast_retracted', 'تم سحب هذا التعميم ولا يتطلب إقراراً');
    }

    if (broadcast.ack_type === 'scroll_ack' && req.body.scrolled_to_end === false) {
      throw badRequest('scroll_required', 'يجب قراءة التعميم بالكامل والتمرير حتى النهاية قبل الإقرار');
    }

    let quizAnswerRecord = null;
    if (broadcast.ack_type === 'quiz_ack') {
      if (typeof req.body.quiz_answer_index !== 'number') {
        throw badRequest('quiz_answer_required', 'يجب الإجابة على سؤال التحقق لإتمام الإقرار');
      }
      const correctIdx = Number(broadcast.quiz_json?.correct_index ?? 0);
      if (req.body.quiz_answer_index !== correctIdx) {
        throw badRequest('quiz_answer_incorrect', 'إجابة سؤال التحقق غير صحيحة، يرجى مراجعة نص التعميم والمحاولة مجدداً');
      }
      quizAnswerRecord = {
        selected_index: req.body.quiz_answer_index,
        correct: true,
      };
    }

    await db.query(
      `INSERT INTO broadcast_receipts (
         broadcast_id, version_no, user_id, device_id, ack_type, quiz_answer, acked_at
       ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, NOW())
       ON CONFLICT (broadcast_id, version_no, user_id) DO UPDATE
       SET acked_at = NOW(), device_id = EXCLUDED.device_id`,
      [
        broadcast.id,
        broadcast.current_version,
        req.auth.userId,
        req.auth.deviceId || null,
        broadcast.ack_type,
        quizAnswerRecord ? JSON.stringify(quizAnswerRecord) : null,
      ],
    );

    // Resolve hub item automatically (HUB-03)
    await db.query(
      `UPDATE hub_items
       SET resolved_at = NOW()
       WHERE user_id = $1 AND source_type = 'broadcast' AND source_id = $2 AND resolved_at IS NULL`,
      [req.auth.userId, broadcast.id],
    );

    await appendAuditLog({
      workspaceId: broadcast.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'broadcast.acknowledged',
      targetType: 'broadcast',
      targetId: broadcast.id,
      metadata: {
        version_no: broadcast.current_version,
        ack_type: broadcast.ack_type,
      },
    });

    res.json({
      success: true,
      acknowledged: true,
      broadcast_id: broadcast.id,
      version_no: broadcast.current_version,
      acked_at: new Date().toISOString(),
    });
  },
);

/**
 * GET /api/v1/broadcasts/:id/stats — Live acknowledgment statistics by department (BRD-04).
 */
broadcastsRouter.get('/:id/stats', async (req, res) => {
  const broadcast = await db.one('SELECT * FROM broadcasts WHERE id = $1', [req.params.id]);
  if (!broadcast) throw notFound('broadcast_not_found', 'التعميم غير موجود');

  const recipients = await db.many(
    `SELECT br.user_id, br.department_id, br.delivered_at,
            u.name, u.employee_no, u.email, u.title,
            d.name AS department_name,
            rc.acked_at, rc.device_id, rc.ack_type
     FROM broadcast_recipients br
     JOIN users u ON u.id = br.user_id
     LEFT JOIN departments d ON d.id = br.department_id
     LEFT JOIN broadcast_receipts rc
       ON rc.broadcast_id = br.broadcast_id
      AND rc.version_no = $2
      AND rc.user_id = br.user_id
     WHERE br.broadcast_id = $1
     ORDER BY d.name ASC NULLS LAST, u.name ASC`,
    [broadcast.id, broadcast.current_version],
  );

  const total = recipients.length;
  const acknowledged = recipients.filter((r) => Boolean(r.acked_at)).length;
  const pending = total - acknowledged;

  const byDeptMap = new Map();
  for (const r of recipients) {
    const key = r.department_id || 'unassigned';
    if (!byDeptMap.has(key)) {
      byDeptMap.set(key, {
        department_id: r.department_id || null,
        department_name: r.department_name || 'غير مصنف',
        total: 0,
        acknowledged: 0,
        pending: 0,
      });
    }
    const entry = byDeptMap.get(key);
    entry.total += 1;
    if (r.acked_at) entry.acknowledged += 1;
    else entry.pending += 1;
  }

  res.json({
    success: true,
    broadcast_id: broadcast.id,
    ref_no: broadcast.ref_no,
    current_version: broadcast.current_version,
    total_recipients: total,
    acknowledged_count: acknowledged,
    pending_count: pending,
    completion_rate: total > 0 ? Math.round((acknowledged / total) * 10000) / 100 : 100,
    by_department: [...byDeptMap.values()],
    recipients: recipients.map((r) => ({
      user_id: r.user_id,
      name: r.name,
      employee_no: r.employee_no,
      title: r.title,
      department_name: r.department_name,
      delivered_at: r.delivered_at,
      acknowledged: Boolean(r.acked_at),
      acked_at: r.acked_at,
      device_id: r.device_id,
    })),
  });
});

/**
 * POST /api/v1/broadcasts/:id/remind — Send 1-click reminder to pending recipients (BRD-05).
 */
broadcastsRouter.post('/:id/remind', async (req, res) => {
  const broadcast = await db.one('SELECT * FROM broadcasts WHERE id = $1', [req.params.id]);
  if (!broadcast) throw notFound('broadcast_not_found', 'التعميم غير موجود');

  const pendingRows = await db.many(
    `SELECT br.user_id
     FROM broadcast_recipients br
     LEFT JOIN broadcast_receipts rc
       ON rc.broadcast_id = br.broadcast_id
      AND rc.version_no = $2
      AND rc.user_id = br.user_id
     WHERE br.broadcast_id = $1 AND rc.acked_at IS NULL`,
    [broadcast.id, broadcast.current_version],
  );

  const pendingUserIds = pendingRows.map((r) => r.user_id);
  if (pendingUserIds.length > 0) {
    sendToUsers(pendingUserIds, 'broadcast.reminder', {
      broadcast_id: broadcast.id,
      ref_no: broadcast.ref_no,
      priority: broadcast.priority,
      ack_deadline: broadcast.ack_deadline,
    });
  }

  await appendAuditLog({
    workspaceId: broadcast.workspace_id,
    actorUserId: req.auth.userId,
    actorDeviceId: req.auth.deviceId,
    action: 'broadcast.reminded',
    targetType: 'broadcast',
    targetId: broadcast.id,
    metadata: { reminded_count: pendingUserIds.length },
  });

  res.json({
    success: true,
    reminded_count: pendingUserIds.length,
    reminded_user_ids: pendingUserIds,
  });
});

/**
 * GET /api/v1/broadcasts/:id/export — Export compliance report in CSV or JSON (BRD-07).
 */
broadcastsRouter.get('/:id/export', async (req, res) => {
  const broadcast = await db.one('SELECT * FROM broadcasts WHERE id = $1', [req.params.id]);
  if (!broadcast) throw notFound('broadcast_not_found', 'التعميم غير موجود');

  const versions = await db.many(
    `SELECT version_no, title, change_note, material_change, edited_by, created_at
     FROM broadcast_versions WHERE broadcast_id = $1 ORDER BY version_no ASC`,
    [broadcast.id],
  );

  const recipients = await db.many(
    `SELECT br.user_id, u.employee_no, u.name, u.email, d.name AS department_name,
            br.delivered_at, rc.acked_at, rc.ack_type, rc.device_id
     FROM broadcast_recipients br
     JOIN users u ON u.id = br.user_id
     LEFT JOIN departments d ON d.id = br.department_id
     LEFT JOIN broadcast_receipts rc
       ON rc.broadcast_id = br.broadcast_id
      AND rc.version_no = $2
      AND rc.user_id = br.user_id
     WHERE br.broadcast_id = $1
     ORDER BY u.employee_no ASC NULLS LAST, u.id ASC`,
    [broadcast.id, broadcast.current_version],
  );

  const format = String(req.query.format || 'json').toLowerCase();
  if (format === 'csv') {
    const csvCell = (val) => {
      if (val === null || val === undefined) return '""';
      let s = String(val);
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
      return `"${s.replace(/"/g, '""')}"`;
    };
    const header = 'ref_no,version_no,employee_no,name,department,delivered_at,acknowledged,acked_at,ack_type,device_id';
    const lines = recipients.map((r) =>
      [
        csvCell(broadcast.ref_no),
        csvCell(broadcast.current_version),
        csvCell(r.employee_no || ''),
        csvCell(r.name || ''),
        csvCell(r.department_name || ''),
        csvCell(r.delivered_at ? new Date(r.delivered_at).toISOString() : ''),
        csvCell(r.acked_at ? 'YES' : 'NO'),
        csvCell(r.acked_at ? new Date(r.acked_at).toISOString() : ''),
        csvCell(r.ack_type || ''),
        csvCell(r.device_id || ''),
      ].join(','),
    );
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${broadcast.ref_no}-compliance.csv"`,
    );
    res.send([header, ...lines].join('\n'));
    return;
  }

  res.json({
    success: true,
    report: {
      generated_at: new Date().toISOString(),
      broadcast: {
        id: broadcast.id,
        ref_no: broadcast.ref_no,
        priority: broadcast.priority,
        ack_type: broadcast.ack_type,
        status: broadcast.status,
        current_version: broadcast.current_version,
        published_at: broadcast.published_at,
      },
      versions,
      recipients,
    },
  });
});
