import { db } from '../db/pool.js';

/** Finds the direct thread shared by two users, if any. */
export async function directThreadBetween(a, b) {
  return db.one(
    `SELECT t.id FROM threads t
     JOIN thread_members m1 ON m1.thread_id = t.id AND m1.user_id = $1
     JOIN thread_members m2 ON m2.thread_id = t.id AND m2.user_id = $2
     WHERE t.kind = 'direct' LIMIT 1`,
    [a, b],
  );
}

/**
 * Relation of `me` to `other`: `connected` when a direct thread exists,
 * otherwise `none`.
 */
export async function relationBetween(me, other) {
  if (me === other) return { status: 'self' };
  // Inside a workspace, colleagues are already connected by the directory:
  // there is no wave handshake to request permission to talk. Either a direct
  // thread exists or it is opened on first message.
  const thread = await directThreadBetween(me, other);
  return thread ? { status: 'connected', thread_id: thread.id } : { status: 'none' };
}

export async function assertMember(threadId, userId) {
  const row = await db.one('SELECT 1 FROM thread_members WHERE thread_id = $1 AND user_id = $2', [threadId, userId]);
  return !!row;
}

export async function memberIds(threadId) {
  const rows = await db.many('SELECT user_id FROM thread_members WHERE thread_id = $1', [threadId]);
  return rows.map((r) => r.user_id);
}

/** Users who share a thread with `userId`. Presence is limited to this set. */
export async function peerUserIds(userId) {
  const rows = await db.many(
    `SELECT DISTINCT tm2.user_id FROM thread_members tm1
     JOIN thread_members tm2 ON tm1.thread_id = tm2.thread_id AND tm2.user_id <> tm1.user_id
     WHERE tm1.user_id = $1`,
    [userId],
  );
  return rows.map((r) => r.user_id);
}
