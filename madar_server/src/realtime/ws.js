import { WebSocketServer } from 'ws';
import { db } from '../db/pool.js';
import { hub } from './hub.js';
import { userIdFromToken } from '../middleware/auth.js';
import { assertMember, memberIds, peerUserIds } from '../services/relations.js';
import { handleCallInvite, handleCallAccept, handleCallDecline, handleCallEnd, relaySignal, activeCallFor, publicCall } from './calls.js';
import { logger } from '../lib/logger.js';
import { ackOfflineMessage, flushOfflineQueue } from '../lib/offlineQueue.js';

const HEARTBEAT_MS = 30_000;

function accessToken(req, url) {
  const authorization = req.headers.authorization;
  if (typeof authorization === 'string' && /^Bearer\s+/i.test(authorization)) {
    return authorization.replace(/^Bearer\s+/i, '').trim();
  }
  const offered = req.headers['sec-websocket-protocol'];
  if (typeof offered === 'string') {
    for (const part of offered.split(',')) {
      const token = part.trim();
      if (token.length > 'bearer.'.length && token.slice(0, 'bearer.'.length).toLowerCase() === 'bearer.') {
        return token.slice('bearer.'.length);
      }
    }
  }
  return url.searchParams.get('token');
}

/**
 * WebSocket endpoint: ws://host/ws?token=<access_token>
 * Every frame is JSON with a `t` (type) field.
 */
export function initRealtime(server) {
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: 256 * 1024,
    handleProtocols(protocols) {
      if (protocols.has('madar')) return 'madar';
      return false;
    },
  });

  async function completeWsHandshake(ws, userId) {
    ws.userId = userId;
    ws.isAlive = true;
    hub.add(userId, ws);
    logger.info({ userId, connections: hub.sockets.get(userId)?.size }, 'ws connected');

    const current = activeCallFor(userId);
    const peers = await peerUserIds(userId).catch((err) => {
      logger.warn({ err: err.message, userId }, 'peer lookup failed');
      return [];
    });
    if (ws.readyState === 1) {
      ws.send(JSON.stringify({
        t: 'hello',
        authenticated: true,
        user_id: userId,
        online_ids: peers.filter((id) => hub.isOnline(id)),
        active_call: current ? publicCall(current) : null,
        ts: Date.now(),
      }));
    }
    flushOfflineQueue(userId).catch((err) => logger.warn({ err: err.message, userId }, 'offline queue flush failed'));
  }

  server.on('upgrade', async (req, socket, head) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/ws') {
      socket.destroy();
      return;
    }
    const token = accessToken(req, url);
    if (token) {
      const userId = await userIdFromToken(token);
      if (!userId) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, userId));
      return;
    }
    // Section 9.2: Allow upgrade without URL query token so client can authenticate via first-frame {"t":"auth","token":"..."}
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, null));
  });

  wss.on('connection', async (ws, _req, initialUserId) => {
    ws.isAlive = true;
    let authTimer = null;

    if (initialUserId) {
      await completeWsHandshake(ws, initialUserId);
    } else {
      authTimer = setTimeout(() => {
        if (!ws.userId) {
          try {
            ws.send(JSON.stringify({ t: 'error', ref: 'auth', message: 'auth_timeout' }));
            ws.close(4001, 'auth_timeout');
          } catch {
            // ignore
          }
        }
      }, 5000);
    }

    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', async (raw) => {
      let frame;
      try {
        frame = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (!frame || typeof frame.t !== 'string') return;

      // Handle first-frame authentication (Section 9.2)
      if (!ws.userId) {
        if (frame.t !== 'auth' || typeof frame.token !== 'string') {
          ws.send(JSON.stringify({ t: 'error', ref: frame.t, message: 'unauthorized_send_auth_first' }));
          ws.close(4001, 'unauthorized');
          return;
        }
        const verifiedUserId = await userIdFromToken(frame.token.trim());
        if (!verifiedUserId) {
          ws.send(JSON.stringify({ t: 'error', ref: 'auth', message: 'invalid_token' }));
          ws.close(4001, 'invalid_token');
          return;
        }
        if (authTimer) {
          clearTimeout(authTimer);
          authTimer = null;
        }
        await completeWsHandshake(ws, verifiedUserId);
        return;
      }

      if (frame.t === 'auth') {
        ws.send(JSON.stringify({ t: 'auth.ok', user_id: ws.userId, ts: Date.now() }));
        return;
      }

      try {
        await dispatch(ws.userId, frame, ws);
      } catch (err) {
        logger.error({ err, type: frame.t, userId: ws.userId }, 'ws frame error');
        ws.send(JSON.stringify({ t: 'error', ref: frame.t, message: 'frame_failed' }));
      }
    });

    ws.on('close', () => {
      if (authTimer) clearTimeout(authTimer);
      if (ws.userId) {
        hub.remove(ws.userId, ws);
        logger.info({ userId: ws.userId }, 'ws disconnected');
      }
    });
    ws.on('error', (err) => logger.warn({ err: err.message, userId: ws.userId }, 'ws error'));
  });

  // Presence fan-out to everyone sharing a thread with the user.
  const peersOf = (userId) => peerUserIds(userId);
  hub.on('online', async (userId) => {
    await db.query('UPDATE users SET last_seen_at = NOW() WHERE id = $1', [userId]).catch(() => {});
    hub.sendMany(await peersOf(userId), 'presence', { user_id: userId, online: true });
  });
  hub.on('offline', async (userId) => {
    const now = new Date().toISOString();
    await db.query('UPDATE users SET last_seen_at = NOW() WHERE id = $1', [userId]).catch(() => {});
    hub.sendMany(await peersOf(userId), 'presence', { user_id: userId, online: false, last_seen_at: now });
  });

  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) { ws.terminate(); continue; }
      ws.isAlive = false;
      ws.ping();
    }
  }, HEARTBEAT_MS);
  wss.on('close', () => clearInterval(heartbeat));

  logger.info('realtime: websocket ready at /ws');
  return wss;
}

async function dispatch(userId, frame, ws) {
  switch (frame.t) {
    case 'ping':
      ws.send(JSON.stringify({ t: 'pong', ts: Date.now() }));
      return;

    case 'typing': {
      const threadId = Number(frame.thread_id);
      if (!threadId || !(await assertMember(threadId, userId))) return;
      const others = (await memberIds(threadId)).filter((id) => id !== userId);
      hub.sendMany(others, 'typing', { thread_id: threadId, user_id: userId, is_typing: !!frame.is_typing });
      return;
    }

    case 'message.ack': {
      const messageId = Number(frame.message_id);
      if (!messageId) return;
      await ackOfflineMessage(userId, messageId);
      ws.send(JSON.stringify({ t: 'message.ack', message_id: messageId, ok: true }));
      return;
    }

    case 'read': {
      const threadId = Number(frame.thread_id);
      const upTo = Number(frame.up_to_message_id) || 0;
      if (!threadId || !(await assertMember(threadId, userId))) return;
      const row = await db.one(
        `UPDATE thread_members SET last_read_message_id = GREATEST(last_read_message_id, $3)
         WHERE thread_id = $1 AND user_id = $2 RETURNING last_read_message_id`,
        [threadId, userId, upTo],
      );
      if (!row) return;
      const others = (await memberIds(threadId)).filter((id) => id !== userId);
      hub.sendMany(others, 'message.read', { thread_id: threadId, user_id: userId, up_to_message_id: Number(row.last_read_message_id) });
      return;
    }

    case 'call.invite': return handleCallInvite(userId, frame, ws);
    case 'call.accept': return handleCallAccept(userId, frame, ws);
    case 'call.decline': return handleCallDecline(userId, frame);
    case 'call.end': return handleCallEnd(userId, frame, ws);
    case 'call.sdp':
    case 'call.ice':
      return relaySignal(userId, frame.t, frame, ws);

    case 'channel_typing': {
      const channelId = frame.channel_id;
      if (!channelId) return;
      const member = await db.one(
        'SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2',
        [channelId, userId],
      );
      if (!member) return;
      const members = await db.many(
        'SELECT user_id FROM channel_members WHERE channel_id = $1 AND user_id <> $2',
        [channelId, userId],
      );
      hub.sendMany(
        members.map((m) => m.user_id),
        'channel_typing',
        { channel_id: channelId, user_id: userId, is_typing: Boolean(frame.is_typing) },
      );
      return;
    }

    case 'channel_read': {
      const channelId = frame.channel_id;
      const upToSeq = Number(frame.up_to_seq) || 0;
      if (!channelId || upToSeq <= 0) return;
      const row = await db.one(
        `UPDATE channel_members
         SET last_read_seq = GREATEST(last_read_seq, $3)
         WHERE channel_id = $1 AND user_id = $2
         RETURNING last_read_seq`,
        [channelId, userId, upToSeq],
      );
      if (!row) return;
      const members = await db.many(
        'SELECT user_id FROM channel_members WHERE channel_id = $1 AND user_id <> $2',
        [channelId, userId],
      );
      hub.sendMany(
        members.map((m) => m.user_id),
        'channel_message.read',
        { channel_id: channelId, user_id: userId, up_to_seq: Number(row.last_read_seq) },
      );
      return;
    }

    case 'presence.set': {
      const status = ['online', 'in_meeting', 'focus', 'away', 'offline'].includes(frame.status)
        ? frame.status
        : 'online';
      const customText = typeof frame.custom_text === 'string' ? frame.custom_text.slice(0, 140) : '';
      const updated = await db.one(
        `UPDATE users
         SET presence_status = $2,
             custom_status = jsonb_build_object('text', $3::text),
             last_seen_at = NOW()
         WHERE id = $1
         RETURNING id, workspace_id, presence_status, custom_status, last_seen_at`,
        [userId, status, customText],
      );
      if (updated?.workspace_id) {
        const wsPeers = await db.many(
          "SELECT id FROM users WHERE workspace_id = $1 AND account_status = 'active' AND id <> $2",
          [updated.workspace_id, userId],
        );
        hub.sendMany(
          wsPeers.map((p) => p.id),
          'presence.updated',
          {
            user_id: userId,
            presence_status: updated.presence_status,
            custom_status: updated.custom_status,
            last_seen_at: updated.last_seen_at,
          },
        );
      }
      ws.send(JSON.stringify({ t: 'presence.ack', presence_status: status, ts: Date.now() }));
      return;
    }

    case 'sync.since': {
      const channelId = frame.channel_id;
      const afterSeq = Number(frame.after_seq) || 0;
      if (!channelId) return;
      const member = await db.one(
        'SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2',
        [channelId, userId],
      );
      if (!member) return;
      const messages = await db.many(
        `SELECT cm.*, u.name AS sender_name
         FROM channel_messages cm
         JOIN users u ON u.id = cm.sender_id
         WHERE cm.channel_id = $1 AND cm.seq > $2
         ORDER BY cm.seq ASC
         LIMIT 200`,
        [channelId, afterSeq],
      );
      ws.send(
        JSON.stringify({
          t: 'sync.batch',
          channel_id: channelId,
          after_seq: afterSeq,
          messages,
          ts: Date.now(),
        }),
      );
      return;
    }

    default:
      ws.send(JSON.stringify({ t: 'error', ref: frame.t, message: 'unknown_frame' }));
  }
}

/**
 * Helper to send a typed realtime frame to a single user across all active sockets.
 */
export function sendToUser(userId, type, payload = {}) {
  return hub.send(Number(userId), type, payload);
}

/**
 * Helper to send a typed realtime frame to multiple users across all active sockets.
 */
export function sendToUsers(userIds, type, payload = {}) {
  if (!Array.isArray(userIds) || userIds.length === 0) return 0;
  return hub.sendMany(userIds, type, payload);
}

/**
 * Disconnects all live WebSocket connections for a user (used on offboarding or session revoke).
 */
export function disconnectUser(userId) {
  const set = hub.sockets.get(Number(userId));
  if (!set) return 0;
  let closed = 0;
  for (const ws of set) {
    try {
      ws.close(4001, 'session_revoked');
      closed += 1;
    } catch {
      // ignore close errors
    }
  }
  hub.sockets.delete(Number(userId));
  return closed;
}

