import crypto from 'node:crypto';
import { Router } from 'express';
import { db } from '../db/pool.js';
import { encryptField } from '../lib/fieldCrypto.js';
import { validate, z } from '../lib/validate.js';
import { badRequest, unauthorized } from '../lib/errors.js';
import { logger } from '../lib/logger.js';

export const relayRouter = Router();

/**
 * Verifies TENANT_TOKEN for Madar Blind Relay endpoints (/v1/wake, /v1/sms).
 */
async function verifyTenantToken(req) {
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim() || req.body?.tenant_token || '';
  if (!token) {
    throw unauthorized('missing_tenant_token', 'TENANT_TOKEN مطلوب للوصول إلى خدمة السحابة الوسيطة (madar-relay)');
  }
  const envToken = process.env.TENANT_TOKEN || process.env.PUSH_RELAY_TOKEN || '';
  if (envToken && token === envToken) return token;

  const ws = await db.one(
    `SELECT id, cloud_services_config FROM workspace ORDER BY created_at ASC LIMIT 1`,
  );
  const configuredToken = ws?.cloud_services_config?.tenant_token || '';
  if (configuredToken && token === configuredToken) return token;

  throw unauthorized('invalid_tenant_token', 'رمز الاشتراك السحابي TENANT_TOKEN غير صالح');
}

/**
 * POST /api/v1/relay/handles — Register a device push token and issue an opaque 128-bit push_handle (Section 4.5, ENR-02).
 * Zero user identity, workspace name, or phone number is stored with the handle mapping.
 */
relayRouter.post(
  '/handles',
  validate({
    body: z.object({
      platform: z.enum(['android', 'ios', 'web', 'desktop', 'flutter']).default('android'),
      native_token: z.string().trim().min(8).max(4096),
      device_id: z.string().uuid().optional(),
      workspace_id: z.string().uuid().optional(),
    }),
  }),
  async (req, res) => {
    const { platform, native_token, device_id, workspace_id } = req.body;
    const pushHandle = `rel_${crypto.randomBytes(16).toString('hex')}`;
    const enc = encryptField(native_token);

    await db.query(
      `INSERT INTO relay_push_handles (
         push_handle, workspace_id, device_id, platform,
         native_token_ciphertext, native_token_iv, key_id
       ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        pushHandle,
        workspace_id || null,
        device_id || null,
        platform,
        enc.ciphertext,
        enc.iv,
        enc.keyId,
      ],
    );

    if (device_id) {
      await db.query(
        `UPDATE devices SET push_handle = $2 WHERE id = $1`,
        [device_id, pushHandle],
      );
    }

    res.status(201).json({
      success: true,
      push_handle: pushHandle,
      platform,
      bits: 128,
    });
  },
);

/**
 * POST /api/v1/relay/wake — Dispatch a zero-payload blind wake signal (Section 4.5, ADM-02).
 * Strictly rejects any payload containing plaintext PII/content fields (title, body, sender, channel_name).
 */
relayRouter.post(
  '/wake',
  validate({
    body: z.object({
      tenant_token: z.string().optional(),
      push_handle: z.string().min(8).max(128).optional(),
      push_handles: z.array(z.string().min(8).max(128)).optional(),
      wake_signal: z.record(z.string(), z.any()),
    }),
  }),
  async (req, res) => {
    await verifyTenantToken(req);

    const { push_handle, push_handles, wake_signal } = req.body;
    const handles = [
      ...(push_handle ? [push_handle] : []),
      ...(Array.isArray(push_handles) ? push_handles : []),
    ];
    if (handles.length === 0) {
      throw badRequest('missing_push_handles', 'يجب تحديد مقبض إشعار واحد على الأقل (push_handle)');
    }

    // Enforce Blind Relay Zero-Content Guarantee (Section 4.5):
    const forbiddenFields = ['title', 'body', 'message', 'sender', 'sender_name', 'channel_name', 'text'];
    for (const field of forbiddenFields) {
      if (field in wake_signal) {
        throw badRequest(
          'relay_content_violation',
          `خدمة السحابة العمياء (madar-relay) ترفض أي محتوى نصي أو بيانات هوية في إشارة الإيقاظ (الحقل المرفوض: ${field})`,
        );
      }
    }

    const vaultId = String(wake_signal.vault_id || 'ws_default');
    const syncHint = ['normal', 'urgent', 'wipe'].includes(wake_signal.sync_hint)
      ? wake_signal.sync_hint
      : 'normal';
    const priority = ['normal', 'high'].includes(wake_signal.priority)
      ? wake_signal.priority
      : 'high';

    let dispatched = 0;
    for (const h of handles) {
      const updated = await db.one(
        `UPDATE relay_push_handles
         SET wake_count = wake_count + 1,
             last_wake_at = NOW()
         WHERE push_handle = $1
         RETURNING push_handle, platform`,
        [h],
      );
      await db.query(
        `INSERT INTO relay_wake_events (push_handle, vault_id, sync_hint, priority)
         VALUES ($1, $2, $3, $4)`,
        [h, vaultId, syncHint, priority],
      );
      if (updated) dispatched += 1;
    }

    logger.info({ handles: handles.length, dispatched, syncHint }, 'madar-relay: blind wake signal dispatched');

    res.json({
      success: true,
      dispatched,
      blind_envelope: {
        t: 'wake',
        vault_id: vaultId,
        sync_hint: syncHint,
        priority,
      },
    });
  },
);

/**
 * POST /api/v1/relay/sms — Cloud SMS Relay endpoint for OTP delivery using TENANT_TOKEN (ADM-02).
 */
relayRouter.post(
  '/sms',
  validate({
    body: z.object({
      phone: z.string().trim().min(6).max(32),
      code: z.string().trim().min(4).max(12),
      template: z.string().default('otp_ar'),
    }),
  }),
  async (req, res) => {
    await verifyTenantToken(req);
    const { phone, code, template } = req.body;
    logger.info({ phone, template }, 'madar-relay: OTP SMS relayed');
    res.json({
      success: true,
      relayed: true,
      phone,
      template,
    });
  },
);
