import { db } from '../db/pool.js';
import { badRequest, forbidden, notFound } from '../lib/errors.js';
import { hub } from '../realtime/hub.js';

/**
 * `blocker` when `me` blocked `other`.
 * `blocked` when `other` blocked `me`.
 * Null when neither row exists.
 * The blocked person must never receive a response that names the block.
 */
export async function blockRole(me, other) {
  if (!me || !other || Number(me) === Number(other)) return null;
  const row = await db.one(
    `SELECT blocker_id FROM user_blocks
     WHERE (blocker_id = $1 AND blocked_id = $2)
        OR (blocker_id = $2 AND blocked_id = $1)
     LIMIT 1`,
    [me, other],
  );
  if (!row) return null;
  return Number(row.blocker_id) === Number(me) ? 'blocker' : 'blocked';
}

export function blockSendError(role, kind) {
  if (role === 'blocker') {
    const message = kind === 'message' ? 'أزل الحظر لإرسال رسالة' : 'أزل الحظر لإرسال تلويحة';
    return forbidden('unblock_required', message);
  }
  const message = kind === 'message' ? 'تعذّر إرسال الرسالة' : 'تعذّر إرسال التلويحة';
  return forbidden('send_unavailable', message);
}

export async function assertNotBlocked(me, other, kind) {
  const role = await blockRole(me, other);
  if (role) throw blockSendError(role, kind);
}

/** Direct threads only. Group messages stay available. */
export async function assertThreadSend(threadId, me) {
  const thread = await db.one('SELECT kind FROM threads WHERE id = $1', [threadId]);
  if (thread?.kind !== 'direct') return;
  const peer = await db.one(
    'SELECT user_id FROM thread_members WHERE thread_id = $1 AND user_id <> $2 LIMIT 1',
    [threadId, me],
  );
  if (!peer) return;
  await assertNotBlocked(me, peer.user_id, 'message');
}

export async function createBlock(blockerId, blockedId) {
  if (Number(blockerId) === Number(blockedId)) throw badRequest('self_block', 'You cannot block yourself');
  const target = await db.one('SELECT id FROM users WHERE id = $1', [blockedId]);
  if (!target) throw notFound('user_not_found');
  await db.query(
    `INSERT INTO user_blocks (blocker_id, blocked_id) VALUES ($1, $2)
     ON CONFLICT DO NOTHING`,
    [blockerId, blockedId],
  );
  const waves = await db.many(
    `UPDATE waves SET status = 'declined', answered_at = NOW()
     WHERE status = 'pending'
       AND ((sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1))
     RETURNING id, sender_id`,
    [blockerId, blockedId],
  );
  for (const wave of waves) {
    hub.send(wave.sender_id, 'wave.answered', { wave_id: wave.id, accepted: false });
  }
}

export async function removeBlock(blockerId, blockedId) {
  await db.query('DELETE FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2', [blockerId, blockedId]);
}

export async function blocksFor(blockerId) {
  return db.many(
    `SELECT u.id, u.name, u.avatar_url, u.accent, b.created_at
     FROM user_blocks b
     JOIN users u ON u.id = b.blocked_id
     WHERE b.blocker_id = $1
     ORDER BY b.created_at DESC, u.id DESC`,
    [blockerId],
  );
}
