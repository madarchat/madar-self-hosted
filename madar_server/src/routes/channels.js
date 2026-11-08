import { Router } from 'express';
import { db } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { attachPolicyContext } from '../middleware/policyGuard.js';
import { validate, z } from '../lib/validate.js';
import { badRequest, forbidden, notFound, HttpError } from '../lib/errors.js';
import { encryptField, decryptField } from '../lib/fieldCrypto.js';
import { appendAuditLog } from '../lib/audit.js';
import { indexSearchDoc } from '../lib/arabicSearch.js';
import { ensureDefaultWorkspace } from '../services/policyEngine.js';
import { sendToUsers } from '../realtime/ws.js';

export const channelsRouter = Router();
export const decisionsRouter = Router();
export const followupsRouter = Router();

channelsRouter.use(requireAuth, attachPolicyContext);
decisionsRouter.use(requireAuth, attachPolicyContext);
followupsRouter.use(requireAuth, attachPolicyContext);

const ADMIN_ROLES = ['SUPER_ADMIN', 'IT_ADMIN', 'DEPT_HEAD'];

async function assertChannelAccess(channelId, userId, roles = []) {
  const ch = await db.one('SELECT * FROM channels WHERE id = $1', [channelId]);
  if (!ch) throw notFound('channel_not_found', 'القناة غير موجودة');

  let membership = await db.one(
    'SELECT * FROM channel_members WHERE channel_id = $1 AND user_id = $2',
    [channelId, userId],
  );
  const isAdmin = roles.some((r) => ADMIN_ROLES.includes(r) || r === 'COMPLIANCE_OFFICER');

  // Auto-join if public channel, broadcast_feed, announcement, or user's own department channel
  if (!membership) {
    const userRow = await db.one('SELECT department_id FROM users WHERE id = $1', [userId]);
    const isOwnDeptChannel =
      ch.kind === 'department' &&
      ch.department_id &&
      userRow?.department_id &&
      String(ch.department_id) === String(userRow.department_id);
    if (
      ['public_channel', 'broadcast_feed', 'announcement'].includes(ch.kind) ||
      isOwnDeptChannel ||
      isAdmin
    ) {
      await db.query(
        `INSERT INTO channel_members (channel_id, user_id, role)
         VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING`,
        [channelId, userId],
      );
      membership = await db.one(
        'SELECT * FROM channel_members WHERE channel_id = $1 AND user_id = $2',
        [channelId, userId],
      );
    }
  }

  if (!membership && !['public_channel', 'broadcast_feed', 'announcement'].includes(ch.kind) && !isAdmin) {
    throw forbidden('not_channel_member', 'أنت لست عضواً في هذه القناة');
  }

  return { channel: ch, membership };
}

async function getChannelMemberIds(channelId) {
  const rows = await db.many('SELECT user_id FROM channel_members WHERE channel_id = $1', [channelId]);
  return rows.map((r) => r.user_id);
}

async function isUnderLegalHold(workspaceId, channel, senderId) {
  if (channel.legal_hold) return true;
  const hold = await db.one(
    `SELECT id FROM legal_holds
     WHERE workspace_id = $1 AND released_at IS NULL
       AND (
         (scope_type = 'channel' AND scope_id = $2)
         OR (scope_type = 'user' AND scope_id = $3)
       )
     LIMIT 1`,
    [workspaceId, String(channel.id), String(senderId)],
  );
  return Boolean(hold);
}

async function insertSystemCardMessage(client, { channelId, senderId, msgType, bodyText, metadata }) {
  const seqRes = await client.query(
    'UPDATE channels SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq',
    [channelId],
  );
  const seq = Number(seqRes.rows[0].last_seq);
  const enc = encryptField(JSON.stringify({ text: bodyText, ...metadata }));
  const { rows } = await client.query(
    `INSERT INTO channel_messages (
       channel_id, seq, sender_id, msg_type, body_ciphertext, body_iv, key_id
     ) VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [channelId, seq, senderId, msgType, enc.ciphertext, enc.iv, enc.keyId],
  );
  return rows[0];
}

function hydrateChannelMessage(row, reactionsByMsg = new Map(), attachmentsByMsg = new Map()) {
  const isDeleted = Boolean(row.deleted_at);
  let body = '';
  let cardData = null;

  if (!isDeleted) {
    const raw = decryptField(row.body_ciphertext, row.body_iv, row.key_id);
    if (['decision_card', 'followup_card', 'system'].includes(row.msg_type)) {
      try {
        cardData = JSON.parse(raw);
        body = cardData.text || raw;
      } catch {
        body = raw;
      }
    } else {
      body = raw;
    }
  }

  return {
    id: row.id,
    channel_id: row.channel_id,
    seq: Number(row.seq),
    sender_id: row.sender_id,
    sender_name: row.sender_name || null,
    sender_title: row.sender_title || null,
    sender_avatar_url: row.sender_avatar_url || null,
    parent_id: row.parent_id || null,
    msg_type: row.msg_type,
    body: isDeleted ? '' : body,
    card_data: isDeleted ? null : cardData,
    client_msg_id: row.client_msg_id || null,
    created_at: row.created_at,
    edited_at: row.edited_at || null,
    deleted_at: row.deleted_at || null,
    reply_count: Number(row.reply_count || 0),
    edit_count: Number(row.edit_count || 0),
    reactions: reactionsByMsg.get(row.id) || [],
    attachments: attachmentsByMsg.get(row.id) || [],
    e2ee_envelope: row.e2ee_envelope || null,
  };
}

/**
 * GET /api/v1/channels — List workspace channels for the current user (CHAT-01).
 */
channelsRouter.get('/', async (req, res) => {
  const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;

  // Ensure default organization-wide channels exist so no employee ever sees an empty channel list
  const existingPublic = await db.one(
    "SELECT id FROM channels WHERE workspace_id = $1 AND kind IN ('public_channel', 'broadcast_feed') LIMIT 1",
    [wsId],
  );
  if (!existingPublic) {
    await db.query(
      `INSERT INTO channels (workspace_id, kind, name, description, posting_mode)
       VALUES
         ($1, 'public_channel', 'عام — الساحة المؤسسية', 'القناة العامة لتواصل جميع فرق وإدارات المؤسسة', 'all'),
         ($1, 'broadcast_feed', 'الإعلانات والقرارات الرسمية', 'القناة الرسمية للقرارات المعتمدة والتعاميم التنظيمية', 'moderators_only')`,
      [wsId],
    );
  }

  // Ensure current user is a member of public channels and their own department channel
  const userRow = await db.one('SELECT department_id FROM users WHERE id = $1', [req.auth.userId]);
  const autoChannels = await db.many(
    `SELECT id FROM channels
     WHERE workspace_id = $1 AND is_archived = FALSE
       AND (kind IN ('public_channel', 'broadcast_feed', 'announcement')
            OR ($2::uuid IS NOT NULL AND department_id = $2::uuid))`,
    [wsId, userRow?.department_id || null],
  );
  for (const ch of autoChannels) {
    await db.query(
      `INSERT INTO channel_members (channel_id, user_id, role)
       VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING`,
      [ch.id, req.auth.userId],
    );
  }

  const rows = await db.many(
    `SELECT c.*,
            d.name AS department_name,
            cm.role AS my_role,
            COALESCE(cm.last_read_seq, 0) AS last_read_seq,
            cm.muted_until,
            (SELECT u.name FROM channel_members pm JOIN users u ON u.id = pm.user_id WHERE pm.channel_id = c.id AND pm.user_id <> $2 LIMIT 1) AS dm_peer_name,
            (SELECT COUNT(*)::int FROM channel_members m WHERE m.channel_id = c.id) AS member_count,
            (SELECT COUNT(*)::int FROM decisions dc WHERE dc.channel_id = c.id AND dc.status = 'active') AS active_decisions_count,
            (SELECT COUNT(*)::int FROM followups f WHERE f.channel_id = c.id AND f.status = 'open') AS open_followups_count,
            (SELECT COUNT(*)::int FROM channel_references r WHERE r.channel_id = c.id) AS references_count
     FROM channels c
     LEFT JOIN departments d ON d.id = c.department_id
     LEFT JOIN channel_members cm ON cm.channel_id = c.id AND cm.user_id = $2
     WHERE c.workspace_id = $1
       AND (cm.user_id IS NOT NULL OR c.kind IN ('public_channel', 'broadcast_feed', 'announcement'))
     ORDER BY c.is_archived ASC,
              CASE c.kind
                WHEN 'public_channel' THEN 1
                WHEN 'broadcast_feed' THEN 2
                WHEN 'announcement' THEN 2
                WHEN 'department' THEN 3
                WHEN 'project' THEN 4
                WHEN 'dm' THEN 5
                ELSE 6
              END ASC,
              c.last_seq DESC,
              c.created_at ASC`,
    [wsId, req.auth.userId],
  );

  const channels = rows.map((r) => {
    const isDm = r.kind === 'dm' || r.kind === 'direct';
    const displayName = isDm && r.dm_peer_name ? `محادثة: ${r.dm_peer_name}` : r.name;
    const isOfficial = ['broadcast_feed', 'announcement'].includes(r.kind);
    const isReadOnly = r.posting_mode === 'read_only';
    return {
      id: r.id,
      workspace_id: r.workspace_id,
      kind: r.kind,
      name: displayName,
      description:
        r.description ||
        (isDm ? `محادثة مباشرة مع ${r.dm_peer_name || 'زميل'}` : 'قناة تواصل مؤسسي'),
      department_id: r.department_id,
      department_name: r.department_name || ( isDm ? 'محادثة مباشرة' : 'عام — المؤسسة'),
      posting_mode: r.posting_mode || 'all',
      privacy_mode: r.privacy_mode || 'standard_governed',
      e2ee_epoch: Number(r.e2ee_epoch || 1),
      is_official: isOfficial,
      is_read_only: isReadOnly,
      created_by: r.created_by,
      is_archived: r.is_archived,
      legal_hold: r.legal_hold,
      last_seq: Number(r.last_seq || 0),
      last_read_seq: Number(r.last_read_seq || 0),
      unread_count: Math.max(0, Number(r.last_seq || 0) - Number(r.last_read_seq || 0)),
      my_role: r.my_role || 'member',
      member_count: r.member_count,
      memory_counts: {
        decisions: r.active_decisions_count,
        followups: r.open_followups_count,
        references: r.references_count,
      },
      created_at: r.created_at,
    };
  });

  res.json({ success: true, channels });
});

/**
 * POST /api/v1/channels — Create a channel (enforces chat.allow_user_create_group, chat.max_group_members, chat.allow_external_guests) (TC-POL-09).
 */
channelsRouter.post(
  '/',
  validate({
    body: z.object({
      kind: z.enum(['dm', 'department', 'project', 'public_channel', 'broadcast_feed', 'private_group']).default('project'),
      name: z.string().trim().min(1).max(160).optional(),
      description: z.string().trim().max(1000).optional(),
      department_id: z.string().uuid().optional(),
      privacy_mode: z.enum(['standard_governed', 'confidential_e2ee', 'enhanced_privacy']).default('standard_governed'),
      member_ids: z.array(z.number().int().positive()).max(500).default([]),
    }),
  }),
  async (req, res) => {
    const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
    const policies = req.effectivePolicy?.policies || {};
    const callerRoles = req.auth.roles || [];
    const isAdmin = callerRoles.some((r) => ADMIN_ROLES.includes(r));

    const { kind, name, description, department_id, privacy_mode, member_ids } = req.body;

    if (kind !== 'dm') {
      const allowCreateGroup = policies['chat.allow_user_create_group'] ?? true;
      if (allowCreateGroup === false && !isAdmin) {
        throw forbidden(
          'group_creation_disabled',
          'إنشاء القنوات والمجموعات غير متاح للمستخدمين العاديين بموجب سياسة المؤسسة (chat.allow_user_create_group)',
        );
      }
      if (!name) {
        throw badRequest('channel_name_required', 'اسم القناة مطلوب');
      }
    }

    const allMembers = [...new Set([req.auth.userId, ...member_ids])];
    const maxMembers = Number(policies['chat.max_group_members'] ?? 250);
    if (allMembers.length > maxMembers) {
      throw badRequest(
        'max_group_members_exceeded',
        `تجاوز عدد الأعضاء الحد الأقصى المسموح به (${maxMembers}) بموجب سياسة المؤسسة`,
      );
    }

    const allowExternalGuests = policies['chat.allow_external_guests'] ?? false;
    if (!allowExternalGuests && allMembers.length > 0) {
      const guestRow = await db.one(
        `SELECT user_id FROM user_roles
         WHERE user_id = ANY($1::bigint[]) AND role = 'GUEST'
         LIMIT 1`,
        [allMembers],
      );
      if (guestRow) {
        throw forbidden(
          'external_guests_disabled',
          'إضافة الضيوف الخارجيين غير مسموح بها بموجب سياسة المؤسسة (chat.allow_external_guests)',
        );
      }
    }

    // Reuse existing DM if kind === 'dm' and 2 members
    if (kind === 'dm' && allMembers.length === 2) {
      const [u1, u2] = allMembers;
      const existingDm = await db.one(
        `SELECT c.*
         FROM channels c
         JOIN channel_members m1 ON m1.channel_id = c.id AND m1.user_id = $2
         JOIN channel_members m2 ON m2.channel_id = c.id AND m2.user_id = $3
         WHERE c.workspace_id = $1 AND c.kind = 'dm'
         LIMIT 1`,
        [wsId, u1, u2],
      );
      if (existingDm) {
        res.json({ success: true, channel: existingDm });
        return;
      }
    }

    const channel = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO channels (workspace_id, kind, name, description, department_id, privacy_mode, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [
          wsId,
          kind,
          name || 'محادثة مباشرة',
          description || null,
          department_id || null,
          privacy_mode || 'standard_governed',
          req.auth.userId,
        ],
      );
      const ch = rows[0];

      for (const uid of allMembers) {
        const role = uid === req.auth.userId ? 'owner' : 'member';
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
      workspaceId: wsId,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'channel.created',
      targetType: 'channel',
      targetId: channel.id,
      metadata: { kind, name: channel.name, member_count: allMembers.length },
    });

    res.status(201).json({ success: true, channel });
  },
);

/**
 * PATCH /api/v1/channels/:id — Update channel metadata or archive status.
 */
channelsRouter.patch(
  '/:id',
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(160).optional(),
      description: z.string().trim().max(1000).optional(),
      is_archived: z.boolean().optional(),
      legal_hold: z.boolean().optional(),
    }),
  }),
  async (req, res) => {
    const { channel, membership } = await assertChannelAccess(
      req.params.id,
      req.auth.userId,
      req.auth.roles,
    );
    const isAdmin = (req.auth.roles || []).some((r) =>
      ['SUPER_ADMIN', 'IT_ADMIN', 'COMPLIANCE_OFFICER', 'DEPT_HEAD'].includes(r),
    );
    if (!isAdmin && (!membership || !['owner', 'admin'].includes(membership.role))) {
      throw forbidden('channel_admin_required', 'تعديل إعدادات القناة يتطلب صلاحية مشرف القناة');
    }

    const updated = await db.one(
      `UPDATE channels
       SET name = COALESCE($2, name),
           description = COALESCE($3, description),
           is_archived = COALESCE($4, is_archived),
           legal_hold = COALESCE($5, legal_hold)
       WHERE id = $1
       RETURNING *`,
      [
        channel.id,
        req.body.name ?? null,
        req.body.description ?? null,
        typeof req.body.is_archived === 'boolean' ? req.body.is_archived : null,
        typeof req.body.legal_hold === 'boolean' ? req.body.legal_hold : null,
      ],
    );

    res.json({ success: true, channel: updated });
  },
);

/**
 * POST /api/v1/channels/:id/members — Add members to a channel.
 */
channelsRouter.post(
  '/:id/members',
  validate({
    body: z.object({
      user_ids: z.array(z.number().int().positive()).min(1).max(200),
      role: z.enum(['owner', 'admin', 'member', 'readonly']).default('member'),
    }),
  }),
  async (req, res) => {
    const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
    const policies = req.effectivePolicy?.policies || {};
    const allowExternalGuests = policies['chat.allow_external_guests'] ?? false;

    if (!allowExternalGuests) {
      const guestRow = await db.one(
        `SELECT user_id FROM user_roles
         WHERE user_id = ANY($1::bigint[]) AND role = 'GUEST'
         LIMIT 1`,
        [req.body.user_ids],
      );
      if (guestRow) {
        throw forbidden('external_guests_disabled', 'إضافة الضيوف الخارجيين غير مسموح بها');
      }
    }

    for (const uid of req.body.user_ids) {
      await db.query(
        `INSERT INTO channel_members (channel_id, user_id, role)
         VALUES ($1, $2, $3)
         ON CONFLICT (channel_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
        [channel.id, uid, req.body.role],
      );
    }

    const members = await db.many(
      `SELECT cm.user_id, cm.role, cm.joined_at, u.name, u.title, u.avatar_url, u.presence_status
       FROM channel_members cm
       JOIN users u ON u.id = cm.user_id
       WHERE cm.channel_id = $1
       ORDER BY u.name ASC`,
      [channel.id],
    );

    res.json({ success: true, members });
  },
);

/**
 * GET /api/v1/channels/:id/messages — List channel messages with differential sync (after_seq) and sub-threads (parent_id) (CHAT-02, CHAT-06).
 */
channelsRouter.get('/:id/messages', async (req, res) => {
  const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
  const afterSeq = req.query.after_seq ? Number(req.query.after_seq) : 0;
  const parentId = req.query.parent_id ? String(req.query.parent_id) : null;
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 300);

  const params = [channel.id, afterSeq];
  let parentClause = '';
  if (parentId) {
    params.push(parentId);
    parentClause = `AND (cm.parent_id = $${params.length} OR cm.id = $${params.length})`;
  }

  params.push(limit);
  const rows = await db.many(
    `SELECT cm.*,
            u.name AS sender_name, u.title AS sender_title, u.avatar_url AS sender_avatar_url,
            (SELECT COUNT(*)::int FROM channel_messages r WHERE r.parent_id = cm.id AND r.deleted_at IS NULL) AS reply_count,
            (SELECT COUNT(*)::int FROM message_edits me WHERE me.message_id = cm.id) AS edit_count
     FROM channel_messages cm
     LEFT JOIN users u ON u.id = cm.sender_id
     WHERE cm.channel_id = $1
       AND cm.seq > $2
       ${parentClause}
     ORDER BY cm.seq ASC
     LIMIT $${params.length}`,
    params,
  );

  const msgIds = rows.map((r) => r.id);
  const reactionsByMsg = new Map();
  const attachmentsByMsg = new Map();

  if (msgIds.length > 0) {
    const reactions = await db.many(
      'SELECT * FROM reactions WHERE message_id = ANY($1::uuid[]) ORDER BY created_at ASC',
      [msgIds],
    );
    for (const rc of reactions) {
      if (!reactionsByMsg.has(rc.message_id)) reactionsByMsg.set(rc.message_id, []);
      reactionsByMsg.get(rc.message_id).push({
        user_id: rc.user_id,
        emoji: rc.emoji,
        created_at: rc.created_at,
      });
    }

    const attachments = await db.many(
      `SELECT id, message_id, file_name, mime_type, size_bytes, sha256_hex, scan_status, created_at
       FROM attachments WHERE message_id = ANY($1::uuid[])`,
      [msgIds],
    );
    for (const att of attachments) {
      if (!attachmentsByMsg.has(att.message_id)) attachmentsByMsg.set(att.message_id, []);
      attachmentsByMsg.get(att.message_id).push(att);
    }
  }

  const messages = rows.map((r) => hydrateChannelMessage(r, reactionsByMsg, attachmentsByMsg));
  res.json({
    success: true,
    channel_id: channel.id,
    last_seq: Number(channel.last_seq || 0),
    messages,
  });
});

/**
 * POST /api/v1/channels/:id/messages — Send a message in a channel (enforces voice notes, attachments, MIME types, sub-threads, @mentions) (TC-POL-12..14).
 */
channelsRouter.post(
  '/:id/messages',
  validate({
    body: z.object({
      body: z.string().max(20_000).default(''),
      msg_type: z
        .enum(['text', 'file', 'voice', 'system', 'decision_card', 'followup_card'])
        .default('text'),
      parent_id: z.string().uuid().nullable().optional(),
      client_msg_id: z.string().trim().min(1).max(80).optional(),
      mention_user_ids: z.array(z.number().int().positive()).max(50).optional(),
      e2ee_envelope: z.record(z.string(), z.any()).nullable().optional(),
      attachments: z
        .array(
          z.object({
            file_name: z.string().trim().min(1).max(255),
            mime_type: z.string().trim().min(1).max(120),
            size_bytes: z.number().int().positive(),
            sha256_hex: z.string().trim().min(8).max(64).default('00000000'),
            storage_path: z.string().trim().max(500).default('vault://inline'),
          }),
        )
        .max(10)
        .optional(),
    }),
  }),
  async (req, res) => {
    const { channel, membership } = await assertChannelAccess(
      req.params.id,
      req.auth.userId,
      req.auth.roles,
    );
    if (channel.is_archived) {
      throw forbidden('channel_archived', 'هذه القناة مؤرشفة للقراءة فقط');
    }
    if (membership?.role === 'readonly') {
      throw forbidden('channel_readonly', 'صلاحيتك في هذه القناة للقراءة فقط');
    }

    const policies = req.effectivePolicy?.policies || {};
    const {
      body,
      msg_type,
      parent_id,
      client_msg_id,
      mention_user_ids = [],
      e2ee_envelope = null,
      attachments = [],
    } = req.body;

    // Enforce chat.allow_voice_notes (TC-POL-14)
    const allowVoiceNotes = policies['chat.allow_voice_notes'] ?? true;
    const hasAudioAttachment = attachments.some((a) =>
      String(a.mime_type || '').toLowerCase().startsWith('audio/'),
    );
    if ((msg_type === 'voice' || hasAudioAttachment) && allowVoiceNotes === false) {
      throw forbidden(
        'voice_notes_disabled',
        'إرسال الرسائل الصوتية غير مسموح به بموجب سياسة المؤسسة (chat.allow_voice_notes)',
      );
    }

    // Enforce chat.max_attachment_mb (TC-POL-12) & chat.allowed_mime_types (TC-POL-13)
    const maxAttachmentMb = Number(policies['chat.max_attachment_mb'] ?? 25);
    const maxBytes = maxAttachmentMb * 1024 * 1024;
    const allowedMimes = policies['chat.allowed_mime_types'] || [
      'application/pdf',
      'image/png',
      'image/jpeg',
      'image/webp',
      'text/plain',
    ];

    for (const att of attachments) {
      if (att.size_bytes > maxBytes) {
        throw new HttpError(
          413,
          'attachment_too_large',
          `حجم المرفق يتجاوز الحد المسموح به (${maxAttachmentMb} ميجابايت) بموجب سياسة المؤسسة (chat.max_attachment_mb)`,
        );
      }
      if (!allowedMimes.includes(att.mime_type)) {
        throw new HttpError(
          415,
          'mime_type_not_allowed',
          `نوع الملف (${att.mime_type}) غير مسموح به بموجب سياسة المؤسسة (chat.allowed_mime_types)`,
        );
      }
    }

    if (!body.trim() && attachments.length === 0 && !e2ee_envelope) {
      throw badRequest('empty_message', 'لا يمكن إرسال رسالة فارغة');
    }

    // Enforce single-level sub-threads (CHAT-02)
    if (parent_id) {
      const parentMsg = await db.one(
        'SELECT id, channel_id, parent_id FROM channel_messages WHERE id = $1',
        [parent_id],
      );
      if (!parentMsg || parentMsg.channel_id !== channel.id) {
        throw badRequest('invalid_parent_message', 'الرسالة الأصلية غير موجودة في هذه القناة');
      }
      if (parentMsg.parent_id) {
        throw badRequest(
          'nested_threads_not_supported',
          'الردود الفرعية تدعم مستوى واحداً فقط منعاً لتشتت النقاش (CHAT-02)',
        );
      }
    }

    // Idempotency check on client_msg_id
    if (client_msg_id) {
      const dup = await db.one(
        `SELECT cm.*, u.name AS sender_name, u.title AS sender_title
         FROM channel_messages cm
         LEFT JOIN users u ON u.id = cm.sender_id
         WHERE cm.channel_id = $1 AND cm.sender_id = $2 AND cm.client_msg_id = $3`,
        [channel.id, req.auth.userId, client_msg_id],
      );
      if (dup) {
        res.json({
          success: true,
          message: hydrateChannelMessage(dup),
        });
        return;
      }
    }

    const enc = encryptField(body);
    const created = await db.tx(async (client) => {
      // Ensure sender is recorded in channel_members
      await client.query(
        `INSERT INTO channel_members (channel_id, user_id, role)
         VALUES ($1, $2, 'member')
         ON CONFLICT (channel_id, user_id) DO NOTHING`,
        [channel.id, req.auth.userId],
      );

      const seqRes = await client.query(
        'UPDATE channels SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq',
        [channel.id],
      );
      const seq = Number(seqRes.rows[0].last_seq);

      const { rows } = await client.query(
        `INSERT INTO channel_messages (
           channel_id, seq, sender_id, parent_id, msg_type,
           body_ciphertext, body_iv, key_id, client_msg_id, e2ee_envelope
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *`,
        [
          channel.id,
          seq,
          req.auth.userId,
          parent_id || null,
          msg_type,
          enc.ciphertext,
          enc.iv,
          enc.keyId,
          client_msg_id || null,
          e2ee_envelope ? JSON.stringify(e2ee_envelope) : null,
        ],
      );
      const msg = rows[0];

      const insertedAttachments = [];
      for (const att of attachments) {
        const attEnc = encryptField(att.storage_path);
        const { rows: attRows } = await client.query(
          `INSERT INTO attachments (
             message_id, workspace_id, uploader_id, file_name, mime_type,
             size_bytes, sha256_hex, storage_path, file_iv, key_id, scan_status
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'clean')
           RETURNING id, message_id, file_name, mime_type, size_bytes, sha256_hex, scan_status, created_at`,
          [
            msg.id,
            channel.workspace_id,
            req.auth.userId,
            att.file_name,
            att.mime_type,
            att.size_bytes,
            att.sha256_hex,
            att.storage_path,
            attEnc.iv,
            attEnc.keyId,
          ],
        );
        insertedAttachments.push(attRows[0]);
      }

      const uniqueMentions = [...new Set(mention_user_ids)].filter((id) => id !== req.auth.userId);
      for (const targetUid of uniqueMentions) {
        await client.query(
          `INSERT INTO mentions (message_id, mentioned_user_id)
           VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [msg.id, targetUid],
        );
        await client.query(
          `INSERT INTO hub_items (
             workspace_id, user_id, section, source_type, source_id, priority
           ) VALUES ($1, $2, 'requires_action', 'mention', $3, 85)`,
          [channel.workspace_id, targetUid, msg.id],
        );
      }

      // If replying to a parent message, auto-resolve any mention hub_item on the parent message for this user (HUB-03)
      if (parent_id) {
        await client.query(
          `UPDATE hub_items
           SET resolved_at = NOW()
           WHERE user_id = $1 AND source_type = 'mention' AND source_id = $2 AND resolved_at IS NULL`,
          [req.auth.userId, parent_id],
        );
      }

      await client.query(
        'UPDATE channel_members SET last_read_seq = GREATEST(last_read_seq, $3) WHERE channel_id = $1 AND user_id = $2',
        [channel.id, req.auth.userId, seq],
      );

      return { msg, insertedAttachments };
    });

    if (body.trim() && !e2ee_envelope && (channel.privacy_mode || 'standard_governed') === 'standard_governed') {
      await indexSearchDoc({
        workspaceId: channel.workspace_id,
        docType: 'message',
        docId: created.msg.id,
        channelId: channel.id,
        title: channel.name || '',
        body,
      });
    }

    const sender = await db.one('SELECT name, title, avatar_url FROM users WHERE id = $1', [
      req.auth.userId,
    ]);
    const attMap = new Map([[created.msg.id, created.insertedAttachments]]);
    const hydrated = hydrateChannelMessage(
      {
        ...created.msg,
        sender_name: sender?.name,
        sender_title: sender?.title,
        sender_avatar_url: sender?.avatar_url,
      },
      new Map(),
      attMap,
    );

    const memberIds = await getChannelMemberIds(channel.id);
    sendToUsers(memberIds, 'msg.new', {
      channel_id: channel.id,
      message: hydrated,
    });

    res.status(201).json({
      success: true,
      message: hydrated,
    });
  },
);

/**
 * PATCH /api/v1/channels/:id/messages/:msgId — Edit message within allowed policy window (CHAT-03, TC-POL-10).
 */
channelsRouter.patch(
  '/:id/messages/:msgId',
  validate({
    body: z.object({
      body: z.string().trim().min(1).max(20_000),
    }),
  }),
  async (req, res) => {
    const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
    const msg = await db.one(
      'SELECT * FROM channel_messages WHERE id = $1 AND channel_id = $2',
      [req.params.msgId, channel.id],
    );
    if (!msg || msg.deleted_at) throw notFound('message_not_found', 'الرسالة غير موجودة');

    if (msg.sender_id !== req.auth.userId) {
      throw forbidden('only_sender_can_edit', 'يمكن للمرسل فقط تعديل رسالته');
    }

    const policies = req.effectivePolicy?.policies || {};
    const allowEditMinutes = Number(policies['chat.allow_message_edit_minutes'] ?? 15);
    const elapsedMinutes = (Date.now() - new Date(msg.created_at).getTime()) / 60_000;

    if (allowEditMinutes <= 0 || elapsedMinutes > allowEditMinutes) {
      throw forbidden(
        'edit_window_expired',
        `انتهت المهلة المسموح بها لتعديل الرسالة (${allowEditMinutes} دقيقة) بموجب سياسة المؤسسة (chat.allow_message_edit_minutes)`,
      );
    }

    const enc = encryptField(req.body.body);
    const updated = await db.tx(async (client) => {
      // Preserve previous ciphertext in message_edits (CHAT-03)
      await client.query(
        `INSERT INTO message_edits (message_id, prev_ciphertext, prev_iv, key_id)
         VALUES ($1, $2, $3, $4)`,
        [msg.id, msg.body_ciphertext, msg.body_iv, msg.key_id],
      );

      const { rows } = await client.query(
        `UPDATE channel_messages
         SET body_ciphertext = $2, body_iv = $3, key_id = $4, edited_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [msg.id, enc.ciphertext, enc.iv, enc.keyId],
      );
      return rows[0];
    });

    await indexSearchDoc({
      workspaceId: channel.workspace_id,
      docType: 'message',
      docId: msg.id,
      channelId: channel.id,
      title: channel.name || '',
      body: req.body.body,
    });

    const hydrated = hydrateChannelMessage(updated);
    const memberIds = await getChannelMemberIds(channel.id);
    sendToUsers(memberIds, 'msg.edited', {
      channel_id: channel.id,
      message: hydrated,
    });

    res.json({ success: true, message: hydrated });
  },
);

/**
 * DELETE /api/v1/channels/:id/messages/:msgId — Delete message respecting chat.allow_message_delete & legal_hold (TC-POL-11, ADM-06).
 */
channelsRouter.delete('/:id/messages/:msgId', async (req, res) => {
  const { channel, membership } = await assertChannelAccess(
    req.params.id,
    req.auth.userId,
    req.auth.roles,
  );
  const msg = await db.one(
    'SELECT * FROM channel_messages WHERE id = $1 AND channel_id = $2',
    [req.params.msgId, channel.id],
  );
  if (!msg) throw notFound('message_not_found', 'الرسالة غير موجودة');

  const policies = req.effectivePolicy?.policies || {};
  const deleteMode = policies['chat.allow_message_delete'] || 'sender_and_admin';

  if (deleteMode === 'none') {
    throw forbidden(
      'message_delete_disabled',
      'حذف الرسائل غير مسموح به بموجب سياسة المؤسسة (chat.allow_message_delete = none)',
    );
  }

  const isSender = msg.sender_id === req.auth.userId;
  const isAdmin =
    (req.auth.roles || []).some((r) => ADMIN_ROLES.includes(r)) ||
    ['owner', 'admin'].includes(membership?.role);

  if (deleteMode === 'sender_only' && !isSender) {
    throw forbidden('only_sender_can_delete', 'تسمح السياسة للمرسل فقط بحذف رسالته');
  }
  if (deleteMode === 'sender_and_admin' && !isSender && !isAdmin) {
    throw forbidden('forbidden_message_delete', 'غير مصرح لك بحذف هذه الرسالة');
  }

  const holdActive = await isUnderLegalHold(channel.workspace_id, channel, msg.sender_id);

  await db.tx(async (client) => {
    if (holdActive) {
      // Under legal hold: archive original ciphertext in message_edits before marking deleted_at
      await client.query(
        `INSERT INTO message_edits (message_id, prev_ciphertext, prev_iv, key_id)
         VALUES ($1, $2, $3, $4)`,
        [msg.id, msg.body_ciphertext, msg.body_iv, msg.key_id],
      );
    }
    await client.query(
      'UPDATE channel_messages SET deleted_at = NOW() WHERE id = $1',
      [msg.id],
    );
  });

  const memberIds = await getChannelMemberIds(channel.id);
  sendToUsers(memberIds, 'msg.deleted', {
    channel_id: channel.id,
    message_id: msg.id,
    deleted_at: new Date().toISOString(),
  });

  res.json({
    success: true,
    message_id: msg.id,
    legal_hold_preserved: holdActive,
  });
});

/**
 * POST /api/v1/channels/:id/messages/:msgId/reactions — Toggle reaction (enforces chat.allow_reactions) (TC-POL-15).
 */
channelsRouter.post(
  '/:id/messages/:msgId/reactions',
  validate({
    body: z.object({
      emoji: z.string().trim().min(1).max(16),
    }),
  }),
  async (req, res) => {
    const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
    const allowReactions = req.effectivePolicy?.policies?.['chat.allow_reactions'] ?? true;
    if (allowReactions === false) {
      throw forbidden(
        'reactions_disabled',
        'التفاعلات التعبيرية معطلة بموجب سياسة المؤسسة (chat.allow_reactions)',
      );
    }

    const msg = await db.one(
      'SELECT id FROM channel_messages WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL',
      [req.params.msgId, channel.id],
    );
    if (!msg) throw notFound('message_not_found', 'الرسالة غير موجودة');

    const existing = await db.one(
      'SELECT 1 FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
      [msg.id, req.auth.userId, req.body.emoji],
    );

    if (existing) {
      await db.query(
        'DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
        [msg.id, req.auth.userId, req.body.emoji],
      );
    } else {
      await db.query(
        'INSERT INTO reactions (message_id, user_id, emoji) VALUES ($1, $2, $3)',
        [msg.id, req.auth.userId, req.body.emoji],
      );
    }

    const reactions = await db.many(
      'SELECT user_id, emoji, created_at FROM reactions WHERE message_id = $1 ORDER BY created_at ASC',
      [msg.id],
    );

    res.json({ success: true, message_id: msg.id, reactions });
  },
);

/**
 * POST /api/v1/channels/:id/read — Mark channel read up to seq.
 */
channelsRouter.post(
  '/:id/read',
  validate({
    body: z.object({
      seq: z.number().int().min(0).optional(),
    }),
  }),
  async (req, res) => {
    const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
    const targetSeq = req.body.seq ?? Number(channel.last_seq || 0);

    await db.query(
      `INSERT INTO channel_members (channel_id, user_id, role, last_read_seq)
       VALUES ($1, $2, 'member', $3)
       ON CONFLICT (channel_id, user_id) DO UPDATE
       SET last_read_seq = GREATEST(channel_members.last_read_seq, EXCLUDED.last_read_seq)`,
      [channel.id, req.auth.userId, targetSeq],
    );

    res.json({ success: true, channel_id: channel.id, last_read_seq: targetSeq });
  },
);

/* ============================================================================
 * INSTITUTIONAL MEMORY: DECISIONS, FOLLOW-UPS, REFERENCES & DIGEST (MEM-01..06)
 * ========================================================================== */

/**
 * GET /api/v1/channels/:id/decisions — List channel decisions (MEM-01).
 */
channelsRouter.get('/:id/decisions', async (req, res) => {
  const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
  const rows = await db.many(
    `SELECT d.*, u.name AS decided_by_name, u.title AS decided_by_title
     FROM decisions d
     LEFT JOIN users u ON u.id = d.decided_by
     WHERE d.channel_id = $1
     ORDER BY d.decided_at DESC`,
    [channel.id],
  );
  res.json({ success: true, decisions: rows });
});

/**
 * POST /api/v1/channels/:id/decisions — Record a channel decision (MEM-01, TC-MEM).
 */
channelsRouter.post(
  '/:id/decisions',
  validate({
    body: z.object({
      title: z.string().trim().min(1).max(300),
      rationale: z.string().trim().max(5000).optional(),
      source_msg_id: z.string().uuid().nullable().optional(),
    }),
  }),
  async (req, res) => {
    const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
    const { title, rationale, source_msg_id } = req.body;

    const decision = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO decisions (
           workspace_id, channel_id, source_msg_id, title, rationale,
           decided_by, status
         ) VALUES ($1, $2, $3, $4, $5, $6, 'active')
         RETURNING *`,
        [
          channel.workspace_id,
          channel.id,
          source_msg_id || null,
          title,
          rationale || null,
          req.auth.userId,
        ],
      );
      const dec = rows[0];

      await insertSystemCardMessage(client, {
        channelId: channel.id,
        senderId: req.auth.userId,
        msgType: 'decision_card',
        bodyText: `قرار معتمد: ${title}`,
        metadata: {
          decision_id: dec.id,
          title: dec.title,
          rationale: dec.rationale,
          status: dec.status,
        },
      });

      const members = await client.query(
        'SELECT user_id FROM channel_members WHERE channel_id = $1',
        [channel.id],
      );
      for (const m of members.rows) {
        if (m.user_id !== req.auth.userId) {
          await client.query(
            `INSERT INTO hub_items (workspace_id, user_id, section, source_type, source_id, priority)
             VALUES ($1, $2, 'announcements', 'decision', $3, 45)`,
            [channel.workspace_id, m.user_id, dec.id],
          );
        }
      }

      return dec;
    });

    await indexSearchDoc({
      workspaceId: channel.workspace_id,
      docType: 'decision',
      docId: decision.id,
      channelId: channel.id,
      title,
      body: rationale || title,
    });

    await appendAuditLog({
      workspaceId: channel.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'decision.recorded',
      targetType: 'decision',
      targetId: decision.id,
      metadata: { channel_id: channel.id, title },
    });

    const memberIds = await getChannelMemberIds(channel.id);
    sendToUsers(memberIds, 'decision.recorded', {
      channel_id: channel.id,
      decision,
    });

    res.status(201).json({ success: true, decision });
  },
);

/**
 * POST /api/v1/decisions/:id/supersede — Supersede an existing decision without deleting it (MEM-06, TC-MEM).
 */
decisionsRouter.post(
  '/:id/supersede',
  validate({
    body: z.object({
      title: z.string().trim().min(1).max(300),
      rationale: z.string().trim().max(5000).optional(),
      source_msg_id: z.string().uuid().nullable().optional(),
    }),
  }),
  async (req, res) => {
    const oldDecision = await db.one('SELECT * FROM decisions WHERE id = $1', [req.params.id]);
    if (!oldDecision) throw notFound('decision_not_found', 'القرار غير موجود');
    if (oldDecision.status === 'superseded') {
      throw badRequest('decision_already_superseded', 'تم استبدال هذا القرار مسبقاً');
    }

    await assertChannelAccess(oldDecision.channel_id, req.auth.userId, req.auth.roles);
    const { title, rationale, source_msg_id } = req.body;

    const result = await db.tx(async (client) => {
      const { rows: newRows } = await client.query(
        `INSERT INTO decisions (
           workspace_id, channel_id, source_msg_id, title, rationale,
           decided_by, status
         ) VALUES ($1, $2, $3, $4, $5, $6, 'active')
         RETURNING *`,
        [
          oldDecision.workspace_id,
          oldDecision.channel_id,
          source_msg_id || null,
          title,
          rationale || null,
          req.auth.userId,
        ],
      );
      const newDecision = newRows[0];

      const { rows: oldRows } = await client.query(
        `UPDATE decisions
         SET status = 'superseded', superseded_by = $2
         WHERE id = $1
         RETURNING *`,
        [oldDecision.id, newDecision.id],
      );

      await insertSystemCardMessage(client, {
        channelId: oldDecision.channel_id,
        senderId: req.auth.userId,
        msgType: 'decision_card',
        bodyText: `قرار محدث (يحل محل القرار السابق: ${oldDecision.title}): ${title}`,
        metadata: {
          decision_id: newDecision.id,
          supersedes_id: oldDecision.id,
          title: newDecision.title,
          rationale: newDecision.rationale,
          status: 'active',
        },
      });

      return { oldDecision: oldRows[0], newDecision };
    });

    await indexSearchDoc({
      workspaceId: oldDecision.workspace_id,
      docType: 'decision',
      docId: result.newDecision.id,
      channelId: oldDecision.channel_id,
      title,
      body: rationale || title,
    });

    await appendAuditLog({
      workspaceId: oldDecision.workspace_id,
      actorUserId: req.auth.userId,
      actorDeviceId: req.auth.deviceId,
      action: 'decision.superseded',
      targetType: 'decision',
      targetId: oldDecision.id,
      metadata: { superseded_by: result.newDecision.id, new_title: title },
    });

    const memberIds = await getChannelMemberIds(oldDecision.channel_id);
    sendToUsers(memberIds, 'decision.superseded', {
      channel_id: oldDecision.channel_id,
      old_decision: result.oldDecision,
      new_decision: result.newDecision,
    });

    res.status(201).json({
      success: true,
      superseded_decision: result.oldDecision,
      decision: result.newDecision,
    });
  },
);

/**
 * GET /api/v1/channels/:id/followups — List channel follow-ups (MEM-02).
 */
channelsRouter.get('/:id/followups', async (req, res) => {
  const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
  const rows = await db.many(
    `SELECT f.*, u.name AS owner_name, u.title AS owner_title, c.name AS created_by_name
     FROM followups f
     LEFT JOIN users u ON u.id = f.owner_id
     LEFT JOIN users c ON c.id = f.created_by
     WHERE f.channel_id = $1
     ORDER BY (f.status = 'open') DESC, f.due_at ASC NULLS LAST, f.created_at DESC`,
    [channel.id],
  );
  res.json({ success: true, followups: rows });
});

/**
 * POST /api/v1/channels/:id/followups — Create a lightweight follow-up (owner + due_at, status: open/done) (MEM-02, TC-MEM).
 */
channelsRouter.post(
  '/:id/followups',
  validate({
    body: z.object({
      title: z.string().trim().min(1).max(300),
      owner_id: z.number().int().positive(),
      due_at: z.string().datetime().nullable().optional(),
      source_msg_id: z.string().uuid().nullable().optional(),
    }),
  }),
  async (req, res) => {
    const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
    const { title, owner_id, due_at, source_msg_id } = req.body;

    const owner = await db.one('SELECT id, name FROM users WHERE id = $1', [owner_id]);
    if (!owner) throw badRequest('owner_not_found', 'المسؤول المحدد للمتابعة غير موجود');

    const dueDate = due_at ? new Date(due_at) : null;
    const isOverdue = dueDate && dueDate < new Date();
    const hubSection = isOverdue ? 'requires_action' : 'followups';
    const hubPriority = isOverdue ? 90 : 70;

    const followup = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO followups (
           workspace_id, channel_id, source_msg_id, title, owner_id,
           due_at, status, created_by
         ) VALUES ($1, $2, $3, $4, $5, $6, 'open', $7)
         RETURNING *`,
        [
          channel.workspace_id,
          channel.id,
          source_msg_id || null,
          title,
          owner_id,
          dueDate,
          req.auth.userId,
        ],
      );
      const fu = rows[0];

      await insertSystemCardMessage(client, {
        channelId: channel.id,
        senderId: req.auth.userId,
        msgType: 'followup_card',
        bodyText: `متابعة: ${title} (المسؤول: ${owner.name || owner.id})`,
        metadata: {
          followup_id: fu.id,
          title: fu.title,
          owner_id: fu.owner_id,
          owner_name: owner.name,
          due_at: fu.due_at,
          status: fu.status,
        },
      });

      await client.query(
        `INSERT INTO hub_items (
           workspace_id, user_id, section, source_type, source_id, priority, due_at
         ) VALUES ($1, $2, $3, 'followup', $4, $5, $6)`,
        [channel.workspace_id, owner_id, hubSection, fu.id, hubPriority, dueDate],
      );

      return fu;
    });

    await indexSearchDoc({
      workspaceId: channel.workspace_id,
      docType: 'followup',
      docId: followup.id,
      channelId: channel.id,
      title,
      body: `${title} ${owner.name || ''}`,
    });

    const memberIds = await getChannelMemberIds(channel.id);
    sendToUsers([...new Set([...memberIds, owner_id])], 'followup.assigned', {
      channel_id: channel.id,
      followup: { ...followup, owner_name: owner.name },
    });

    res.status(201).json({
      success: true,
      followup: { ...followup, owner_name: owner.name },
    });
  },
);

/**
 * PATCH /api/v1/followups/:id — Update follow-up status (strictly 'open' or 'done') (MEM-02, TC-MEM).
 */
followupsRouter.patch(
  '/:id',
  validate({
    body: z.object({
      status: z.enum(['open', 'done'], {
        errorMap: () => ({ message: "حالة المتابعة تقبل فقط 'open' أو 'done'" }),
      }),
      title: z.string().trim().min(1).max(300).optional(),
      due_at: z.string().datetime().nullable().optional(),
    }),
  }),
  async (req, res) => {
    const existing = await db.one('SELECT * FROM followups WHERE id = $1', [req.params.id]);
    if (!existing) throw notFound('followup_not_found', 'عنصر المتابعة غير موجود');

    await assertChannelAccess(existing.channel_id, req.auth.userId, req.auth.roles);
    const { status, title, due_at } = req.body;

    const updated = await db.tx(async (client) => {
      const completedAt = status === 'done' ? new Date() : null;
      const { rows } = await client.query(
        `UPDATE followups
         SET status = $2,
             completed_at = $3,
             title = COALESCE($4, title),
             due_at = COALESCE($5, due_at)
         WHERE id = $1
         RETURNING *`,
        [
          existing.id,
          status,
          completedAt,
          title ?? null,
          due_at !== undefined ? (due_at ? new Date(due_at) : null) : null,
        ],
      );

      if (status === 'done') {
        await client.query(
          `UPDATE hub_items
           SET resolved_at = NOW()
           WHERE source_type = 'followup' AND source_id = $1 AND resolved_at IS NULL`,
          [existing.id],
        );
      } else {
        await client.query(
          `UPDATE hub_items
           SET resolved_at = NULL
           WHERE source_type = 'followup' AND source_id = $1`,
          [existing.id],
        );
      }

      return rows[0];
    });

    const memberIds = await getChannelMemberIds(existing.channel_id);
    sendToUsers(memberIds, 'followup.updated', {
      channel_id: existing.channel_id,
      followup: updated,
    });

    res.json({ success: true, followup: updated });
  },
);

/**
 * GET /api/v1/channels/:id/references — List pinned channel references (MEM-03).
 */
channelsRouter.get('/:id/references', async (req, res) => {
  const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
  const rows = await db.many(
    `SELECT r.*, u.name AS pinned_by_name
     FROM channel_references r
     LEFT JOIN users u ON u.id = r.pinned_by
     WHERE r.channel_id = $1
     ORDER BY r.pinned_at DESC`,
    [channel.id],
  );
  res.json({ success: true, references: rows });
});

/**
 * POST /api/v1/channels/:id/references — Pin a reference (max 10 per channel) (MEM-03).
 */
channelsRouter.post(
  '/:id/references',
  validate({
    body: z.object({
      title: z.string().trim().min(1).max(200),
      ref_type: z.enum(['link', 'file', 'message']).default('link'),
      target_url: z.string().trim().max(2000).optional(),
      attachment_id: z.string().uuid().optional(),
      message_id: z.string().uuid().optional(),
    }),
  }),
  async (req, res) => {
    const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);

    const countRow = await db.one(
      'SELECT COUNT(*)::int AS c FROM channel_references WHERE channel_id = $1',
      [channel.id],
    );
    if ((countRow?.c || 0) >= 10) {
      throw badRequest(
        'max_references_reached',
        'الحد الأقصى للمراجع المثبتة في القناة الواحدة هو 10 مراجع منعاً للتكدس (MEM-03)',
      );
    }

    const { title, ref_type, target_url, attachment_id, message_id } = req.body;
    const ref = await db.one(
      `INSERT INTO channel_references (
         channel_id, title, ref_type, target_url, attachment_id, message_id, pinned_by
       ) VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        channel.id,
        title,
        ref_type,
        target_url || null,
        attachment_id || null,
        message_id || null,
        req.auth.userId,
      ],
    );

    await indexSearchDoc({
      workspaceId: channel.workspace_id,
      docType: 'reference',
      docId: ref.id,
      channelId: channel.id,
      title,
      body: target_url || title,
    });

    res.status(201).json({ success: true, reference: ref });
  },
);

/**
 * DELETE /api/v1/channels/:id/references/:refId — Unpin a reference.
 */
channelsRouter.delete('/:id/references/:refId', async (req, res) => {
  const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);
  const deleted = await db.one(
    'DELETE FROM channel_references WHERE id = $1 AND channel_id = $2 RETURNING id',
    [req.params.refId, channel.id],
  );
  if (!deleted) throw notFound('reference_not_found', 'المرجع غير موجود');
  res.json({ success: true, deleted_id: deleted.id });
});

/**
 * GET /api/v1/channels/:id/digest — Weekly channel digest of decisions, open/overdue followups & references (MEM-04).
 */
channelsRouter.get('/:id/digest', async (req, res) => {
  const { channel } = await assertChannelAccess(req.params.id, req.auth.userId, req.auth.roles);

  const [recentDecisions, openFollowups, completedFollowups, references] = await Promise.all([
    db.many(
      `SELECT d.*, u.name AS decided_by_name
       FROM decisions d
       LEFT JOIN users u ON u.id = d.decided_by
       WHERE d.channel_id = $1 AND d.decided_at > NOW() - INTERVAL '7 days'
       ORDER BY d.decided_at DESC`,
      [channel.id],
    ),
    db.many(
      `SELECT f.*, u.name AS owner_name
       FROM followups f
       LEFT JOIN users u ON u.id = f.owner_id
       WHERE f.channel_id = $1 AND f.status = 'open'
       ORDER BY f.due_at ASC NULLS LAST`,
      [channel.id],
    ),
    db.many(
      `SELECT f.*, u.name AS owner_name
       FROM followups f
       LEFT JOIN users u ON u.id = f.owner_id
       WHERE f.channel_id = $1 AND f.status = 'done' AND f.completed_at > NOW() - INTERVAL '7 days'
       ORDER BY f.completed_at DESC`,
      [channel.id],
    ),
    db.many(
      `SELECT r.*, u.name AS pinned_by_name
       FROM channel_references r
       LEFT JOIN users u ON u.id = r.pinned_by
       WHERE r.channel_id = $1
       ORDER BY r.pinned_at DESC`,
      [channel.id],
    ),
  ]);

  const now = new Date();
  const overdueFollowups = openFollowups.filter((f) => f.due_at && new Date(f.due_at) < now);

  res.json({
    success: true,
    digest: {
      channel_id: channel.id,
      channel_name: channel.name,
      generated_at: now.toISOString(),
      period_days: 7,
      summary_counts: {
        recent_decisions: recentDecisions.length,
        open_followups: openFollowups.length,
        overdue_followups: overdueFollowups.length,
        completed_followups: completedFollowups.length,
        pinned_references: references.length,
      },
      recent_decisions: recentDecisions,
      open_followups: openFollowups,
      overdue_followups: overdueFollowups,
      completed_followups: completedFollowups,
      pinned_references: references,
    },
  });
});
