import path from 'node:path';
import { Router } from 'express';
import { db } from '../db/pool.js';
import { validate, z, idParam, optionalPositiveInt, optionalNonNegativeInt } from '../lib/validate.js';
import { badRequest, notFound, forbidden } from '../lib/errors.js';
import { requireAuth } from '../middleware/auth.js';
import { uploadMessageMedia, publicPath, kindFromMime, tryVideoThumb, removeFile } from '../lib/media.js';
import { serializeUser, serializeMessage, userCols } from '../lib/serialize.js';
import { hub } from '../realtime/hub.js';
import { assertMember, memberIds, directThreadBetween } from '../services/relations.js';
import { assertThreadSend } from '../services/blocks.js';
import { pushToUser } from '../services/push.js';
import { enqueueOfflineMessage } from '../lib/offlineQueue.js';

export const threadsRouter = Router();
threadsRouter.use(requireAuth);

const MESSAGE_SELECT = `
  m.*, u.name AS sender_name, u.avatar_url AS sender_avatar_url,
  (SELECT COUNT(*) FROM thread_members r WHERE r.thread_id = m.thread_id AND r.user_id <> m.sender_id AND r.last_read_message_id >= m.id) AS read_by_count`;

async function loadMessage(id) {
  return db.one(`SELECT ${MESSAGE_SELECT} FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = $1`, [id]);
}

function previewOf(m) {
  if (m.deleted_at) return null;
  if (m.is_e2ee) return '🔒 رسالة مشفرة';
  if (typeof m.body === 'string' && m.body.includes('"c"') && m.body.includes('"m"')) return '🔒 رسالة مشفرة';
  if (m.body) return m.body;
  if (m.kind === 'image') return 'صورة';
  if (m.kind === 'video') return 'فيديو';
  if (m.kind === 'audio') return 'رسالة صوتية';
  if (m.kind === 'file') return m.media_name || 'ملف';
  return 'رسالة جديدة';
}

function readE2ee(body) {
  const flag = body?.is_e2ee === true || body?.is_e2ee === 'true' || body?.is_e2ee === '1';
  let header = null;
  const raw = body?.e2ee_header;
  if (raw && typeof raw === 'object') header = raw;
  else if (typeof raw === 'string' && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) header = parsed;
    } catch {
      header = null;
    }
  }
  return { isE2ee: flag || !!header, header };
}

async function threadSummaryRows(me, whereExtra = '', params = []) {
  return db.many(
    `SELECT t.id, t.kind, t.title, t.avatar_url, t.created_at, t.last_message_at, mm.muted, mm.last_read_message_id,
            lm.id AS lm_id, lm.client_id AS lm_client_id, lm.kind AS lm_kind, lm.body AS lm_body, lm.sender_id AS lm_sender_id, lm.created_at AS lm_created_at, lm.deleted_at AS lm_deleted_at, lm.is_e2ee AS lm_is_e2ee, lm.e2ee_header AS lm_e2ee_header,
            (SELECT COUNT(*) FROM messages x WHERE x.thread_id = t.id AND x.sender_id <> $1 AND x.deleted_at IS NULL AND x.id > COALESCE(mm.last_read_message_id, 0)) AS unread,
            (SELECT COUNT(*) FROM thread_members c WHERE c.thread_id = t.id) AS member_count,
            ou.id AS o_id, ou.phone AS o_phone, ou.name AS o_name, ou.note AS o_note, ou.avatar_url AS o_avatar_url, ou.accent AS o_accent, ou.last_seen_at AS o_last_seen_at, ou.created_at AS o_created_at, ou.show_phone_number AS o_show_phone_number,
            EXISTS (
              SELECT 1 FROM user_blocks b
              WHERE b.blocker_id = $1 AND b.blocked_id = ou.id
            ) AS blocked_by_me
     FROM thread_members mm
     JOIN threads t ON t.id = mm.thread_id
     LEFT JOIN LATERAL (
       SELECT id, client_id, kind, body, sender_id, created_at, deleted_at, is_e2ee, e2ee_header FROM messages WHERE thread_id = t.id ORDER BY id DESC LIMIT 1
     ) lm ON TRUE
     LEFT JOIN LATERAL (
       SELECT u.* FROM thread_members om JOIN users u ON u.id = om.user_id
       WHERE om.thread_id = t.id AND om.user_id <> $1 AND t.kind = 'direct' LIMIT 1
     ) ou ON TRUE
     WHERE mm.user_id = $1 ${whereExtra}
     ORDER BY COALESCE(lm.created_at, t.created_at) DESC`,
    [me, ...params],
  );
}

function serializeThreadSummary(r) {
  const other = r.o_id
    ? serializeUser({
        id: r.o_id, phone: r.o_phone, name: r.o_name, note: r.o_note, avatar_url: r.o_avatar_url,
        accent: r.o_accent, last_seen_at: r.o_last_seen_at, created_at: r.o_created_at,
        show_phone_number: r.o_show_phone_number,
      })
    : null;
  const summary = {
    id: r.id,
    kind: r.kind,
    title: r.kind === 'direct' ? other?.name || 'Madar' : r.title,
    avatar_url: r.kind === 'direct' ? other?.avatar_url || null : r.avatar_url,
    other_user: other,
    member_count: Number(r.member_count),
    muted: !!r.muted,
    unread: Number(r.unread) || 0,
    last_read_message_id: Number(r.last_read_message_id) || 0,
    created_at: new Date(r.created_at).toISOString(),
    last_message: r.lm_id
      ? {
          id: r.lm_id, client_id: r.lm_client_id || null, kind: r.lm_kind, body: r.lm_deleted_at ? null : r.lm_body, sender_id: r.lm_sender_id,
          created_at: new Date(r.lm_created_at).toISOString(), is_deleted: !!r.lm_deleted_at,
          is_e2ee: !!r.lm_is_e2ee, e2ee_header: r.lm_e2ee_header ?? null,
        }
      : null,
  };
  if (r.blocked_by_me === true) summary.blocked_by_me = true;
  return summary;
}

threadsRouter.get('/', async (req, res) => {
  const rows = await threadSummaryRows(req.auth.userId);
  res.json({ success: true, threads: rows.map(serializeThreadSummary) });
});

/** Create a group thread (direct threads are created by accepting a wave). */
threadsRouter.post(
  '/',
  validate({
    body: z.object({
      title: z.string().trim().min(1).max(120),
      member_ids: z.array(z.coerce.number().int().positive()).min(1).max(100),
    }),
  }),
  async (req, res) => {
    const me = req.auth.userId;
    const members = [...new Set(req.body.member_ids.filter((id) => id !== me))];
    // Only people I'm connected with can be pulled into a group.
    for (const id of members) {
      if (!(await directThreadBetween(me, id))) throw forbidden('not_connected', `You are not connected with user ${id}`);
    }
    const thread = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO threads (kind, title, created_by) VALUES ('group', $1, $2) RETURNING *`, [req.body.title, me],
      );
      const t = rows[0];
      const all = [me, ...members];
      const values = all.map((_, i) => `($1, $${i + 2}, $${all.length + 2 + i})`).join(', ');
      await client.query(
        `INSERT INTO thread_members (thread_id, user_id, role) VALUES ${values}`,
        [t.id, ...all, ...all.map((id) => (id === me ? 'owner' : 'member'))],
      );
      return t;
    });
    const rows = await threadSummaryRows(me, 'AND t.id = $2', [thread.id]);
    const summary = serializeThreadSummary(rows[0]);
    hub.sendMany(members, 'thread.new', { thread: summary });
    res.status(201).json({ success: true, thread: summary });
  },
);

threadsRouter.get('/:id', validate({ params: idParam() }), async (req, res) => {
  const { id } = req.paramsParsed;
  if (!(await assertMember(id, req.auth.userId))) throw notFound('thread_not_found');
  const rows = await threadSummaryRows(req.auth.userId, 'AND t.id = $2', [id]);
  const members = await db.many(
    `SELECT ${userCols('u')}, tm.role, tm.joined_at FROM thread_members tm JOIN users u ON u.id = tm.user_id WHERE tm.thread_id = $1`, [id],
  );
  res.json({
    success: true,
    thread: {
      ...serializeThreadSummary(rows[0]),
      members: members.map((m) => ({ ...serializeUser(m, { self: m.id === req.auth.userId }), role: m.role })),
    },
  });
});

threadsRouter.get(
  '/:id/messages',
  validate({ params: idParam(), query: z.object({ before: z.coerce.number().int().optional(), after: z.coerce.number().int().optional(), limit: z.coerce.number().int().min(1).max(100).default(40) }) }),
  async (req, res) => {
    const { id } = req.paramsParsed;
    const { before, after, limit } = req.queryParsed;
    if (!(await assertMember(id, req.auth.userId))) throw notFound('thread_not_found');
    const where = ['m.thread_id = $1'];
    const params = [id];
    if (before) { params.push(before); where.push(`m.id < $${params.length}`); }
    if (after) { params.push(after); where.push(`m.id > $${params.length}`); }
    params.push(limit + 1);
    const rows = await db.many(
      `SELECT ${MESSAGE_SELECT} FROM messages m JOIN users u ON u.id = m.sender_id
       WHERE ${where.join(' AND ')} ORDER BY m.id DESC LIMIT $${params.length}`,
      params,
    );
    const hasMore = rows.length > limit;
    const page = rows.slice(0, limit);
    res.json({ success: true, messages: page.map(serializeMessage), has_more: hasMore });
  },
);

/** Send a message. multipart/form-data with optional `media` and `thumb` files. */
threadsRouter.post(
  '/:id/messages',
  validate({ params: idParam() }),
  uploadMessageMedia.fields([{ name: 'media', maxCount: 1 }, { name: 'thumb', maxCount: 1 }]),
  validate({
    body: z.object({
      body: z.string().max(262_144).optional(),
      kind: z.enum(['text', 'image', 'video', 'audio', 'file']).optional(),
      client_id: z.string().max(64).optional(),
      reply_to_id: optionalPositiveInt,
      duration_ms: optionalNonNegativeInt,
      moment_id: optionalPositiveInt,
      is_e2ee: z.union([z.boolean(), z.enum(['true', 'false', '1', '0'])]).optional(),
      e2ee_header: z.string().max(8_000).optional(),
      media_mime: z.string().max(100).optional(),
    }),
  }),
  async (req, res) => {
    const { id: threadId } = req.paramsParsed;
    const me = req.auth.userId;
    if (!(await assertMember(threadId, me))) throw notFound('thread_not_found');
    await assertThreadSend(threadId, me);

    const media = req.files?.media?.[0];
    const thumb = req.files?.thumb?.[0];
    const body = (req.body.body || '').trim();
    if (!media && !body) throw badRequest('empty_message', 'Message needs text or media');

    let kind = req.body.kind || (media ? kindFromMime(req.body.media_mime || media.mimetype, media.originalname) : 'text');
    if (!media && kind !== 'text') kind = 'text';
    const e2ee = readE2ee(req.body);
    let thumbName = thumb?.filename || null;
    if (media && kind === 'video' && !thumbName && !e2ee.isE2ee) thumbName = await tryVideoThumb(media.path);

    // Idempotent on client_id: re-sending the same message returns the stored one.
    if (req.body.client_id) {
      const dup = await db.one('SELECT id FROM messages WHERE sender_id = $1 AND client_id = $2', [me, req.body.client_id]);
      if (dup) return res.json({ success: true, message: serializeMessage(await loadMessage(dup.id)), duplicate: true });
    }

    const inserted = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO messages (thread_id, sender_id, client_id, kind, body, media_url, thumb_url, media_mime, media_name, media_size, duration_ms, reply_to_id, moment_id, is_e2ee, e2ee_header)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
        [
          threadId, me, req.body.client_id || null, kind, body || null,
          media ? publicPath('messages', media.filename) : null,
          thumbName ? publicPath('thumbs', thumbName) : null,
          req.body.media_mime || media?.mimetype || null, media?.originalname || null, media?.size ?? null,
          req.body.duration_ms ?? null, req.body.reply_to_id ?? null, req.body.moment_id ?? null,
          e2ee.isE2ee, e2ee.header ? JSON.stringify(e2ee.header) : null,
        ],
      );
      await client.query('UPDATE threads SET last_message_at = NOW() WHERE id = $1', [threadId]);
      await client.query(
        'UPDATE thread_members SET last_read_message_id = GREATEST(last_read_message_id, $3) WHERE thread_id = $1 AND user_id = $2',
        [threadId, me, rows[0].id],
      );
      return rows[0];
    });

    const message = serializeMessage(await loadMessage(inserted.id));
    const recipients = (await memberIds(threadId)).filter((uid) => uid !== me);
    hub.sendMany([...recipients, me], 'message.new', { thread_id: threadId, message });
    for (const uid of recipients) {
      if (!hub.isOnline(uid)) {
        await enqueueOfflineMessage(uid, threadId, message.id);
      }
      pushToUser(uid, {
        title: message.sender_name || 'Madar',
        body: previewOf(message) || (kind === 'text' ? '' : `[${kind}]`),
        data: { type: 'message', thread_id: String(threadId), message_id: String(message.id) },
      });
    }
    res.status(201).json({ success: true, message });
  },
);

/** JSON message send (E2EE ciphertext + direct R2 media URLs). */
threadsRouter.post(
  '/:id/messages/json',
  validate({
    params: idParam(),
    body: z.object({
      body: z.string().max(262_144).optional(),
      kind: z.enum(['text', 'image', 'video', 'audio', 'file']).default('text'),
      client_id: z.string().max(64).optional(),
      reply_to_id: optionalPositiveInt,
      duration_ms: optionalNonNegativeInt,
      moment_id: optionalPositiveInt,
      is_e2ee: z.boolean().default(false),
      e2ee_header: z.record(z.any()).optional(),
      media_url: z.string().max(2_000).refine((value) => value.startsWith('/') || /^https?:\/\//.test(value), 'media_url must be absolute or root-relative').optional(),
      thumb_url: z.string().max(2_000).refine((value) => value.startsWith('/') || /^https?:\/\//.test(value), 'thumb_url must be absolute or root-relative').optional(),
      media_mime: z.string().max(100).optional(),
      media_name: z.string().max(255).optional(),
      media_size: z.coerce.number().int().min(0).optional(),
    }),
  }),
  async (req, res) => {
    const { id: threadId } = req.paramsParsed;
    const me = req.auth.userId;
    if (!(await assertMember(threadId, me))) throw notFound('thread_not_found');
    await assertThreadSend(threadId, me);

    const payload = req.body;
    const body = (payload.body || '').trim();
    const hasMedia = !!payload.media_url;
    if (!hasMedia && !body) throw badRequest('empty_message', 'Message needs text or media');

    if (payload.client_id) {
      const dup = await db.one('SELECT id FROM messages WHERE sender_id = $1 AND client_id = $2', [me, payload.client_id]);
      if (dup) return res.json({ success: true, message: serializeMessage(await loadMessage(dup.id)), duplicate: true });
    }

    const kind = payload.kind || (hasMedia ? 'file' : 'text');
    const inserted = await db.tx(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO messages (thread_id, sender_id, client_id, kind, body, media_url, thumb_url, media_mime, media_name, media_size, duration_ms, reply_to_id, moment_id, is_e2ee, e2ee_header)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
        [
          threadId, me, payload.client_id || null, kind, body || null,
          payload.media_url || null, payload.thumb_url || null,
          payload.media_mime || null, payload.media_name || null, payload.media_size ?? null,
          payload.duration_ms ?? null, payload.reply_to_id ?? null, payload.moment_id ?? null,
          payload.is_e2ee, payload.e2ee_header ? JSON.stringify(payload.e2ee_header) : null,
        ],
      );
      await client.query('UPDATE threads SET last_message_at = NOW() WHERE id = $1', [threadId]);
      await client.query(
        'UPDATE thread_members SET last_read_message_id = GREATEST(last_read_message_id, $3) WHERE thread_id = $1 AND user_id = $2',
        [threadId, me, rows[0].id],
      );
      return rows[0];
    });

    const message = serializeMessage(await loadMessage(inserted.id));
    const recipients = (await memberIds(threadId)).filter((uid) => uid !== me);
    hub.sendMany([...recipients, me], 'message.new', { thread_id: threadId, message });
    for (const uid of recipients) {
      if (!hub.isOnline(uid)) {
        await enqueueOfflineMessage(uid, threadId, message.id);
      }
      pushToUser(uid, {
        title: message.sender_name || 'Madar',
        body: message.is_e2ee ? '🔒 رسالة مشفرة' : previewOf(message) || `[${kind}]`,
        data: { type: 'message', thread_id: String(threadId), message_id: String(message.id) },
      });
    }
    res.status(201).json({ success: true, message });
  },
);

threadsRouter.post(
  '/:id/read',
  validate({ params: idParam(), body: z.object({ up_to_message_id: z.coerce.number().int().min(0) }) }),
  async (req, res) => {
    const { id } = req.paramsParsed;
    const me = req.auth.userId;
    if (!(await assertMember(id, me))) throw notFound('thread_not_found');
    const row = await db.one(
      `UPDATE thread_members SET last_read_message_id = GREATEST(last_read_message_id, $3)
       WHERE thread_id = $1 AND user_id = $2 RETURNING last_read_message_id`,
      [id, me, req.body.up_to_message_id],
    );
    const others = (await memberIds(id)).filter((uid) => uid !== me);
    hub.sendMany(others, 'message.read', { thread_id: id, user_id: me, up_to_message_id: Number(row.last_read_message_id) });
    res.json({ success: true, last_read_message_id: Number(row.last_read_message_id) });
  },
);

threadsRouter.post('/:id/mute', validate({ params: idParam(), body: z.object({ muted: z.boolean() }) }), async (req, res) => {
  const { id } = req.paramsParsed;
  await db.query('UPDATE thread_members SET muted = $3 WHERE thread_id = $1 AND user_id = $2', [id, req.auth.userId, req.body.muted]);
  res.json({ success: true });
});

threadsRouter.delete('/:id/messages/:mid', validate({ params: z.object({ id: z.coerce.number().int(), mid: z.coerce.number().int() }) }), async (req, res) => {
  const { id, mid } = req.paramsParsed;
  const me = req.auth.userId;
  const msg = await db.one('SELECT * FROM messages WHERE id = $1 AND thread_id = $2', [mid, id]);
  if (!msg) throw notFound('message_not_found');
  if (msg.sender_id !== me) throw forbidden('not_your_message');
  await db.query('UPDATE messages SET deleted_at = NOW(), body = NULL WHERE id = $1', [mid]);
  if (msg.media_url) removeFile('messages', path.basename(msg.media_url));
  if (msg.thumb_url) removeFile('thumbs', path.basename(msg.thumb_url));
  hub.sendMany(await memberIds(id), 'message.deleted', { thread_id: id, message_id: mid });
  res.json({ success: true });
});

/** Leave (group) or delete (direct) a thread for everyone. */
threadsRouter.delete('/:id', validate({ params: idParam() }), async (req, res) => {
  const { id } = req.paramsParsed;
  const me = req.auth.userId;
  const thread = await db.one('SELECT * FROM threads WHERE id = $1', [id]);
  if (!thread || !(await assertMember(id, me))) throw notFound('thread_not_found');
  const members = await memberIds(id);
  if (thread.kind === 'group') {
    await db.query('DELETE FROM thread_members WHERE thread_id = $1 AND user_id = $2', [id, me]);
    hub.sendMany(members, 'thread.member_left', { thread_id: id, user_id: me });
  } else {
    await db.query('DELETE FROM threads WHERE id = $1', [id]);
    await db.query(`DELETE FROM waves WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)`, [
      members[0], members[1] ?? members[0],
    ]);
    hub.sendMany(members, 'thread.deleted', { thread_id: id });
  }
  res.json({ success: true });
});
