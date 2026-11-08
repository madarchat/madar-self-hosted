import crypto from 'node:crypto';
import { env } from '../config/env.js';
import { db } from '../db/pool.js';
import { hub } from './hub.js';
import { serializeUser, USER_COLUMNS } from '../lib/serialize.js';
import { directThreadBetween } from '../services/relations.js';
import { blockRole } from '../services/blocks.js';
import { pushToUser } from '../services/push.js';
import { logger } from '../lib/logger.js';

/**
 * Call signaling for WebRTC voice/video calls.
 *
 * The server never touches media: it owns the call state machine (ringing → answered →
 * ended / missed / declined / busy) and relays SDP offers/answers and ICE candidates
 * between the two peers over their WebSocket connections. Media flows peer-to-peer
 * (or through the self-hosted TURN relay when NAT requires it).
 */

const DISCONNECT_GRACE_MS = env.IS_TEST ? 300 : 12_000;

/**
 * @type {Map<string, {
 *   id: string,
 *   callerId: number,
 *   calleeId: number,
 *   kind: string,
 *   status: string,
 *   startedAt: number,
 *   answeredAt?: number,
 *   timer?: NodeJS.Timeout,
 *   disconnectTimer?: NodeJS.Timeout,
 *   callerWs?: import('ws').WebSocket,
 *   calleeWs?: import('ws').WebSocket,
 *   users?: { caller?: object, callee?: object },
 *   callerName?: string,
 *   callerAvatar?: string
 * }>}
 */
const active = new Map();

function peerOf(call, userId) {
  return call.callerId === userId ? call.calleeId : call.callerId;
}

function isBusy(userId) {
  for (const c of active.values()) {
    if ((c.callerId === userId || c.calleeId === userId) && c.status !== 'ended') return true;
  }
  return false;
}

export function activeCallFor(userId) {
  for (const c of active.values()) {
    if ((c.callerId === userId || c.calleeId === userId) && c.status !== 'ended') return c;
  }
  return null;
}

export function publicCall(call, users = call.users) {
  return {
    id: call.id,
    caller_id: call.callerId,
    callee_id: call.calleeId,
    kind: call.kind,
    status: call.status,
    started_at: new Date(call.startedAt).toISOString(),
    answered_at: call.answeredAt ? new Date(call.answeredAt).toISOString() : null,
    caller: users?.caller ?? undefined,
    callee: users?.callee ?? undefined,
  };
}

async function persist(call, extra = {}) {
  const duration = call.answeredAt && extra.ended ? Math.round((Date.now() - call.answeredAt) / 1000) : null;
  await db.query(
    `INSERT INTO calls (id, caller_id, callee_id, kind, status, started_at, answered_at, ended_at, duration_s, end_reason)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, answered_at = EXCLUDED.answered_at,
       ended_at = EXCLUDED.ended_at, duration_s = EXCLUDED.duration_s, end_reason = EXCLUDED.end_reason`,
    [
      call.id, call.callerId, call.calleeId, call.kind, call.status, new Date(call.startedAt),
      call.answeredAt ? new Date(call.answeredAt) : null,
      extra.ended ? new Date() : null, duration, extra.reason || null,
    ],
  ).catch((err) => logger.error({ err }, 'call persist failed'));
  return duration;
}

async function finish(call, status, reason, { notify = [call.callerId, call.calleeId] } = {}) {
  if (!active.has(call.id)) return;
  clearTimeout(call.timer);
  clearTimeout(call.disconnectTimer);
  call.status = status;
  active.delete(call.id);
  const duration = await persist(call, { ended: true, reason });
  hub.sendMany(notify, 'call.ended', { call_id: call.id, status, reason, duration_s: duration });
  logger.info({ callId: call.id, status, reason, duration }, 'call finished');
}

/** Cleans up any calls left in 'ringing' or 'answered' state from a previous server run. */
export async function cleanupOrphanedCallsOnBoot() {
  await db.query(
    `UPDATE calls
     SET status = CASE WHEN status = 'ringing' THEN 'missed' ELSE 'ended' END,
         ended_at = NOW(),
         end_reason = 'server_restart'
     WHERE status IN ('ringing', 'answered')`,
  ).catch((err) => logger.warn({ err: err.message }, 'orphan call cleanup failed'));
}

export async function handleCallInvite(userId, frame, ws) {
  const to = Number(frame.to);
  const kind = frame.kind === 'video' ? 'video' : 'audio';
  const callId = typeof frame.call_id === 'string' && frame.call_id.length <= 64 ? frame.call_id : crypto.randomUUID();

  if (!to || to === userId) return hub.send(userId, 'call.unavailable', { call_id: callId, reason: 'invalid_target' });
  if (isBusy(userId)) return hub.send(userId, 'call.unavailable', { call_id: callId, reason: 'you_are_busy' });
  if (!(await directThreadBetween(userId, to))) {
    return hub.send(userId, 'call.unavailable', { call_id: callId, reason: 'not_connected' });
  }
  if (await blockRole(userId, to)) {
    return hub.send(userId, 'call.unavailable', { call_id: callId, reason: 'unavailable' });
  }

  const call = {
    id: callId,
    callerId: userId,
    calleeId: to,
    kind,
    status: 'ringing',
    startedAt: Date.now(),
    callerName: 'مدار',
    callerAvatar: '',
    callerWs: ws,
  };

  if (isBusy(to)) {
    call.status = 'busy';
    await persist(call, { ended: true, reason: 'busy' });
    return hub.send(userId, 'call.busy', { call_id: callId });
  }
  const offline = !hub.isOnline(to);
  active.set(callId, call);
  await persist(call);

  const rows = await db.many(`SELECT ${USER_COLUMNS} FROM users WHERE id = ANY($1)`, [[userId, to]]);
  const users = {
    caller: serializeUser(rows.find((r) => r.id === userId), { withPhone: false }),
    callee: serializeUser(rows.find((r) => r.id === to), { withPhone: false }),
  };
  call.users = users;
  call.callerName = users.caller?.name || 'مدار';
  call.callerAvatar = users.caller?.avatar_url || '';

  call.timer = setTimeout(() => {
    const c = active.get(callId);
    if (c && c.status === 'ringing') {
      finish(c, 'missed', 'timeout');
      if (!hub.isOnline(to)) {
        pushToUser(to, {
          title: users.caller?.name || 'مدار',
          body: kind === 'video' ? 'مكالمة فيديو فائتة' : 'مكالمة صوتية فائتة',
          data: {
            type: 'missed_call',
            call_id: callId,
            kind,
            caller_id: userId,
            caller_name: call.callerName,
            caller_avatar_url: call.callerAvatar,
          },
          channel: 'calls',
        });
      }
    }
  }, env.CALL_RING_TIMEOUT_MS);

  if (offline) {
    pushToUser(to, {
      title: call.callerName,
      body: kind === 'video' ? 'مكالمة فيديو واردة' : 'مكالمة صوتية واردة',
      data: {
        type: 'incoming_call',
        call_id: callId,
        kind,
        caller_id: userId,
        caller_name: call.callerName,
        caller_avatar_url: call.callerAvatar,
        ring_timeout_ms: env.CALL_RING_TIMEOUT_MS,
      },
      channel: 'calls',
      dataOnly: true,
    });
  } else {
    hub.send(to, 'call.incoming', { call: publicCall(call, users), ring_timeout_ms: env.CALL_RING_TIMEOUT_MS });
  }
  hub.send(userId, 'call.ringing', { call: publicCall(call, users), ring_timeout_ms: env.CALL_RING_TIMEOUT_MS });
  logger.info({ callId, from: userId, to, kind, offline }, 'call ringing');
}

export async function handleCallAccept(userId, frame, ws) {
  const call = active.get(frame.call_id);
  if (!call || call.calleeId !== userId || call.status !== 'ringing') return;
  clearTimeout(call.timer);
  clearTimeout(call.disconnectTimer);
  call.status = 'answered';
  call.answeredAt = Date.now();
  call.calleeWs = ws;
  await persist(call);
  const payload = { call: publicCall(call) };
  hub.send(call.callerId, 'call.accepted', payload);
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ t: 'call.accepted', ...payload, ts: Date.now() }));
  } else {
    hub.send(call.calleeId, 'call.accepted', payload);
  }
  // Stop ringing on any other connected devices belonging to the callee
  const calleeSockets = hub.sockets.get(Number(call.calleeId));
  if (calleeSockets) {
    const dismissFrame = JSON.stringify({
      t: 'call.ended',
      call_id: call.id,
      status: 'answered',
      reason: 'answered_elsewhere',
      ts: Date.now(),
    });
    for (const sock of calleeSockets) {
      if (sock !== ws && sock.readyState === sock.OPEN) {
        try { sock.send(dismissFrame); } catch {}
      }
    }
  }
  logger.info({ callId: call.id }, 'call answered');
}

export async function handleCallDecline(userId, frame) {
  const call = active.get(frame.call_id);
  if (!call || call.calleeId !== userId || call.status !== 'ringing') return;
  await finish(call, 'declined', 'declined');
}

/** HTTP fallback so background notification "Decline" action can reject a ringing call without opening a WebSocket. */
export async function declineCallById(userId, callId) {
  const call = active.get(callId);
  if (!call || call.calleeId !== Number(userId)) return false;
  if (call.status === 'ringing') {
    await finish(call, 'declined', 'declined');
    return true;
  }
  return false;
}

export async function handleCallEnd(userId, frame, ws) {
  const call = active.get(frame.call_id);
  if (!call || (call.callerId !== userId && call.calleeId !== userId)) return;
  if (call.status === 'ringing') {
    const status = userId === call.callerId ? 'cancelled' : 'declined';
    return finish(call, status, frame.reason || status);
  }
  // Ignore hangup frames from secondary devices that are not participating in the answered call
  if (call.status === 'answered') {
    if (userId === call.callerId && call.callerWs && ws && call.callerWs !== ws && call.callerWs.readyState === call.callerWs.OPEN) return;
    if (userId === call.calleeId && call.calleeWs && ws && call.calleeWs !== ws && call.calleeWs.readyState === call.calleeWs.OPEN) return;
  }
  return finish(call, 'ended', frame.reason || 'hangup');
}

export function relaySignal(userId, type, frame, ws) {
  const call = active.get(frame.call_id);
  if (!call || (call.callerId !== userId && call.calleeId !== userId)) return;
  // Security: never relay SDP or ICE before callee has explicitly accepted the call (prevents IP leak)
  if (call.status !== 'answered') return;

  // Bind the active socket if the participant reconnected onto a new socket
  if (userId === call.callerId && ws) call.callerWs = ws;
  if (userId === call.calleeId && ws) call.calleeWs = ws;

  const payload = { call_id: call.id, from: userId };
  if (type === 'call.sdp') {
    payload.sdp = frame.sdp;
    if (typeof frame.fp === 'string' && frame.fp.length <= 200) payload.fp = frame.fp;
    if (typeof frame.fp_sig === 'string' && frame.fp_sig.length <= 200) payload.fp_sig = frame.fp_sig;
  }
  if (type === 'call.ice') payload.candidate = frame.candidate;

  const targetUserId = peerOf(call, userId);
  const delivered = hub.send(targetUserId, type, payload);
  if (delivered === 0) {
    logger.warn({ callId: call.id, targetUserId, type }, 'call signal relay: peer has no open websocket');
  }
}

/**
 * When a user's last socket drops:
 * - a ringing callee stays ringing so the push can wake the phone; the ring timer still marks it missed
 * - an answered call or ringing caller gets a grace period (DISCONNECT_GRACE_MS) to allow transient
 *   network handovers (Wi-Fi ↔ mobile data) without immediately dropping the call.
 */
export function handleUserOffline(userId) {
  for (const call of [...active.values()]) {
    if (call.callerId !== userId && call.calleeId !== userId) continue;
    if (call.status === 'ringing' && userId === call.calleeId) {
      pushToUser(userId, {
        title: call.callerName || 'مدار',
        body: call.kind === 'video' ? 'مكالمة فيديو واردة' : 'مكالمة صوتية واردة',
        data: {
          type: 'incoming_call',
          call_id: call.id,
          kind: call.kind,
          caller_id: call.callerId,
          caller_name: call.callerName || 'مدار',
          caller_avatar_url: call.callerAvatar || '',
          ring_timeout_ms: env.CALL_RING_TIMEOUT_MS,
        },
        channel: 'calls',
        dataOnly: true,
      });
      continue;
    }
    clearTimeout(call.disconnectTimer);
    call.disconnectTimer = setTimeout(() => {
      if (!active.has(call.id)) return;
      if (hub.isOnline(userId)) return;
      const status = call.status === 'ringing' ? 'cancelled' : 'ended';
      finish(call, status, 'peer_disconnected');
    }, DISCONNECT_GRACE_MS);
  }
}

export function handleUserOnline(userId) {
  for (const call of active.values()) {
    if (call.callerId === userId || call.calleeId === userId) {
      clearTimeout(call.disconnectTimer);
      call.disconnectTimer = undefined;
    }
  }
}

hub.on('offline', handleUserOffline);
hub.on('online', handleUserOnline);
