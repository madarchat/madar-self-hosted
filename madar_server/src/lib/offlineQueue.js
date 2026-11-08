import { db } from '../db/pool.js';
import { hub } from '../realtime/hub.js';
import { serializeMessage } from './serialize.js';

const MESSAGE_SELECT = `
  m.*, u.name AS sender_name, u.avatar_url AS sender_avatar_url,
  (SELECT COUNT(*) FROM thread_members r WHERE r.thread_id = m.thread_id AND r.user_id <> m.sender_id AND r.last_read_message_id >= m.id) AS read_by_count`;

async function loadMessage(id) {
  return db.one(`SELECT ${MESSAGE_SELECT} FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = $1`, [id]);
}

/** Queue a message for an offline recipient (store-and-forward). */
export async function enqueueOfflineMessage(recipientId, threadId, messageId) {
  if (!recipientId || !messageId) return;
  await db.query(
    `INSERT INTO offline_message_queue (recipient_id, thread_id, message_id)
     VALUES ($1, $2, $3) ON CONFLICT (recipient_id, message_id) DO NOTHING`,
    [recipientId, threadId, messageId],
  );
}

/** Deliver pending queue entries over WebSocket when a user connects. */
export async function flushOfflineQueue(userId) {
  const rows = await db.many(
    `SELECT message_id, thread_id FROM offline_message_queue WHERE recipient_id = $1 ORDER BY id ASC LIMIT 200`,
    [userId],
  );
  for (const row of rows) {
    const message = serializeMessage(await loadMessage(row.message_id));
    if (!message) continue;
    hub.send(userId, 'message.new', { thread_id: row.thread_id, message, offline: true });
  }
}

/** Client persisted the message locally — remove from store-and-forward queue. */
export async function ackOfflineMessage(userId, messageId) {
  const mid = Number(messageId);
  if (!mid) return false;
  const row = await db.one(
    'DELETE FROM offline_message_queue WHERE recipient_id = $1 AND message_id = $2 RETURNING id',
    [userId, mid],
  );
  return !!row;
}
