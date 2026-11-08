import fs from 'node:fs';
import path from 'node:path';
import { env, ROOT_DIR } from '../config/env.js';
import { db } from '../db/pool.js';
import { hub } from '../realtime/hub.js';
import { logger } from '../lib/logger.js';

/**
 * Push & Blind Wake Notification Service (Section 4.5, ADM-02).
 * - For Sovereign Workspace vaults: dispatches Zero-Payload Blind Wake signals
 *   (`{ t: "wake", vault_id, sync_hint, priority }`) via opaque 128-bit `push_handle`
 *   and `TENANT_TOKEN` without leaking message text, sender identity, or channel names.
 * - For Personal Mode (when FIREBASE_SERVICE_ACCOUNT is present): dispatches FCM/APNs.
 */
let messaging = null;
let initialized = false;

export async function initPush() {
  if (initialized) return;
  initialized = true;
  if (!env.FIREBASE_SERVICE_ACCOUNT || env.DEPLOYMENT_PROFILE === 'workspace') {
    logger.info('push: sovereign blind-relay wake mode active');
    return;
  }
  try {
    let file = path.isAbsolute(env.FIREBASE_SERVICE_ACCOUNT)
      ? env.FIREBASE_SERVICE_ACCOUNT
      : path.join(ROOT_DIR, env.FIREBASE_SERVICE_ACCOUNT);
    if (!fs.existsSync(file)) {
      const candidates = [
        '/run/secrets/firebase.json',
        path.join(ROOT_DIR, 'src/config', path.basename(env.FIREBASE_SERVICE_ACCOUNT)),
      ];
      file = candidates.find((c) => fs.existsSync(c)) || file;
    }
    if (!fs.existsSync(file)) {
      logger.warn({ file }, 'push: service account file not found, using blind-relay only');
      return;
    }
    const { initializeApp, cert } = await import('firebase-admin/app');
    const { getMessaging } = await import('firebase-admin/messaging');
    const app = initializeApp({ credential: cert(JSON.parse(fs.readFileSync(file, 'utf8'))) });
    messaging = getMessaging(app);
    logger.info('push: enabled');
  } catch (err) {
    logger.warn({ err: err.message }, 'push: failed to initialize FCM, using blind-relay only');
  }
}

/**
 * Dispatches a Zero-Payload Blind Wake Signal (`{ t: "wake", vault_id, sync_hint, priority }`)
 * to all enrolled workspace devices of `userId` that have a bound `push_handle`.
 */
export async function dispatchBlindWake(userId, { syncHint = 'normal', priority = 'high', force = false } = {}) {
  if (!force && hub.isOnline(userId)) return { dispatched: 0, skipped: 'online' };
  const devices = await db.many(
    `SELECT d.id, d.workspace_id, d.push_handle, w.cloud_services_config
     FROM devices d
     LEFT JOIN workspace w ON w.id = d.workspace_id
     WHERE d.user_id = $1
       AND d.status IN ('active', 'wipe_pending')
       AND d.push_handle IS NOT NULL`,
    [userId],
  );
  if (!devices.length) return { dispatched: 0 };

  let dispatched = 0;
  for (const dev of devices) {
    const vaultId = `ws_${dev.workspace_id || 'default'}`;
    await db.query(
      `UPDATE relay_push_handles
       SET wake_count = wake_count + 1,
           last_wake_at = NOW()
       WHERE push_handle = $1`,
      [dev.push_handle],
    );
    await db.query(
      `INSERT INTO relay_wake_events (push_handle, vault_id, sync_hint, priority)
       VALUES ($1, $2, $3, $4)`,
      [dev.push_handle, vaultId, syncHint, priority],
    );

    const cfg = dev.cloud_services_config || {};
    const relayUrl = (cfg.relay_url || process.env.MADAR_RELAY_URL || process.env.PUSH_RELAY_URL || '').replace(/\/+$/, '');
    const tenantToken = cfg.tenant_token || process.env.TENANT_TOKEN || process.env.PUSH_RELAY_TOKEN || '';
    if (relayUrl && tenantToken && cfg.push_relay_enabled !== false) {
      try {
        await fetch(`${relayUrl}/v1/wake`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${tenantToken}`,
          },
          body: JSON.stringify({
            push_handle: dev.push_handle,
            wake_signal: {
              t: 'wake',
              vault_id: vaultId,
              sync_hint: syncHint,
              priority,
            },
          }),
        });
      } catch (err) {
        logger.warn({ err: err.message, deviceId: dev.id }, 'blind relay HTTP wake failed');
      }
    }
    dispatched += 1;
  }
  return { dispatched };
}

/**
 * Fire-and-forget. Message pushes skip users who are on the socket.
 * Wave pushes pass `force` so the notification still arrives while the app is open.
 */
export function pushToUser(userId, { title, body, data = {}, channel = 'messages', dataOnly = false, force = false }) {
  // Always trigger Blind Relay wake for any enrolled workspace devices with push_handle
  dispatchBlindWake(userId, {
    syncHint: channel === 'broadcasts' ? 'urgent' : 'normal',
    priority: 'high',
    force,
  }).catch(() => {});

  if (!messaging || (!force && hub.isOnline(userId))) return;
  (async () => {
    const user = await db.one('SELECT push_token FROM users WHERE id = $1', [userId]);
    if (!user?.push_token) return;
    try {
      const payload = {
        token: user.push_token,
        data: Object.fromEntries(
          Object.entries({ title: title ?? '', body: body ?? '', ...data }).map(([k, v]) => [k, String(v ?? '')]),
        ),
        android: dataOnly
          ? { priority: 'high', ttl: 45_000 }
          : { priority: 'high', notification: { channelId: `madar_${channel}`, sound: 'default' } },
        apns: dataOnly
          ? {
              headers: { 'apns-priority': '10', 'apns-push-type': 'background' },
              payload: { aps: { 'content-available': 1 } },
            }
          : {
              payload: { aps: { alert: { title, body }, sound: 'default', 'content-available': 1 } },
            },
      };
      if (!dataOnly) {
        payload.notification = { title, body };
      }
      await messaging.send(payload);
    } catch (err) {
      if (['messaging/registration-token-not-registered', 'messaging/invalid-registration-token'].includes(err.code)) {
        await db.query('UPDATE users SET push_token = NULL WHERE id = $1', [userId]);
      } else {
        logger.warn({ err: err.message, userId }, 'push failed');
      }
    }
  })().catch(() => {});
}
