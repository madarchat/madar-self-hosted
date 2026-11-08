import { Router } from 'express';
import { db } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { attachPolicyContext } from '../middleware/policyGuard.js';
import { validate, z } from '../lib/validate.js';
import { badRequest, notFound } from '../lib/errors.js';
import { verifyDeviceSignature } from '../lib/jws.js';
import { appendAuditLog } from '../lib/audit.js';
import { hub } from '../realtime/hub.js';

export const devicesRouter = Router();

/** List current user's enrolled workspace devices. */
devicesRouter.get('/', requireAuth, attachPolicyContext, async (req, res) => {
  const devices = await db.many(
    `SELECT id, workspace_id, device_name, platform, os_version, app_version,
            attestation_state, status, policy_version, policy_applied_at,
            last_seen_at, wipe_requested_at, wipe_acked_at, created_at,
            (id = $2::uuid) AS is_current
     FROM devices
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [req.auth.userId, req.auth.deviceId || null],
  );
  res.json({
    success: true,
    devices,
  });
});

/** Revoke one of the current user's devices. */
devicesRouter.delete(
  '/:id',
  requireAuth,
  attachPolicyContext,
  validate({ params: z.object({ id: z.string().uuid() }) }),
  async (req, res) => {
    const { id } = req.paramsParsed;
    const device = await db.one(
      'SELECT * FROM devices WHERE id = $1 AND user_id = $2',
      [id, req.auth.userId],
    );
    if (!device) throw notFound('device_not_found', 'الجهاز غير موجود');

    await db.tx(async (client) => {
      await client.query(
        "UPDATE devices SET status = 'revoked' WHERE id = $1",
        [id],
      );
      await client.query(
        'UPDATE refresh_tokens SET revoked_at = NOW() WHERE device_id = $1 AND revoked_at IS NULL',
        [id],
      );
      if (device.workspace_id) {
        await appendAuditLog(
          {
            workspaceId: device.workspace_id,
            actorUserId: req.auth.userId,
            actorDeviceId: req.auth.deviceId || null,
            action: 'device.revoked',
            targetType: 'device',
            targetId: id,
            metadata: { self_revoked: true, device_name: device.device_name },
          },
          client,
        );
      }
    });

    hub.send(req.auth.userId, 'session.revoked', { device_id: id, reason: 'user_revoked' });
    res.json({ success: true, device_id: id, status: 'revoked' });
  },
);

/**
 * Cryptographic acknowledgment of selective workspace vault wipe (SEC-04, TC-WIPE).
 * Note: This endpoint does NOT require an active session token because a device in
 * `wipe_pending` state has already had its access/refresh tokens invalidated; instead,
 * it authenticates the acknowledgment using the device's bound Ed25519 public key (`device_pub_key`).
 */
devicesRouter.post(
  '/:id/wipe-ack',
  validate({
    params: z.object({ id: z.string().uuid() }),
    body: z.object({
      signature: z.string().min(16),
      payload: z.string().optional(),
      wiped_at: z.string().optional(),
    }),
  }),
  async (req, res) => {
    const { id } = req.paramsParsed;
    const { signature, payload } = req.body;

    const device = await db.one('SELECT * FROM devices WHERE id = $1', [id]);
    if (!device) throw notFound('device_not_found', 'الجهاز غير موجود');

    const canonicalPayload = payload || `wipe:${device.id}:${device.workspace_id}`;
    const validSig = verifyDeviceSignature(device.device_pub_key, canonicalPayload, signature);
    if (!validSig) {
      throw badRequest('invalid_wipe_signature', 'توقيع إقرار مسح الخزنة غير صالح (Ed25519 verification failed)');
    }

    const updated = await db.tx(async (client) => {
      const { rows } = await client.query(
        `UPDATE devices
         SET status = 'wiped',
             wipe_acked_at = NOW(),
             wipe_ack_sig = $2
         WHERE id = $1
         RETURNING id, user_id, workspace_id, status, wipe_requested_at, wipe_acked_at, wipe_ack_sig`,
        [id, signature],
      );
      await client.query(
        'UPDATE refresh_tokens SET revoked_at = NOW() WHERE device_id = $1 AND revoked_at IS NULL',
        [id],
      );
      if (device.workspace_id) {
        await appendAuditLog(
          {
            workspaceId: device.workspace_id,
            actorUserId: device.user_id,
            actorDeviceId: device.id,
            action: 'device.wipe.acked',
            targetType: 'device',
            targetId: device.id,
            metadata: { payload: canonicalPayload },
          },
          client,
        );
      }
      return rows[0];
    });

    res.json({
      success: true,
      device: updated,
    });
  },
);

/**
 * POST /api/v1/devices/:id/push-handle — Bind an opaque 128-bit Madar Relay push_handle to the device (ENR-02, Section 4.5).
 */
devicesRouter.post(
  '/:id/push-handle',
  requireAuth,
  attachPolicyContext,
  validate({
    params: z.object({ id: z.string().uuid() }),
    body: z.object({
      push_handle: z.string().trim().min(8).max(128),
    }),
  }),
  async (req, res) => {
    const { id } = req.paramsParsed;
    const { push_handle } = req.body;
    const updated = await db.one(
      `UPDATE devices
       SET push_handle = $3,
           last_seen_at = NOW()
       WHERE id = $1 AND user_id = $2
       RETURNING id, user_id, workspace_id, device_name, platform, push_handle, status`,
      [id, req.auth.userId, push_handle],
    );
    if (!updated) throw notFound('device_not_found', 'الجهاز غير موجود');
    res.json({
      success: true,
      device: updated,
    });
  },
);

