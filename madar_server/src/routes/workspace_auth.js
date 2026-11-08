import crypto from 'node:crypto';
import { Router } from 'express';
import { env } from '../config/env.js';
import { db } from '../db/pool.js';
import { validate, z } from '../lib/validate.js';
import { badRequest, unauthorized, forbidden, notFound } from '../lib/errors.js';
import {
  newRefreshToken,
  sha256,
  signWorkspaceAccessToken,
  signMfaPreAuthToken,
  verifyAccessToken,
} from '../lib/tokens.js';
import { hashPassword, verifyPassword, validatePasswordComplexity } from '../lib/password.js';
import {
  generateTotpSecret,
  totpUri,
  verifyTotpCode,
  generateRecoveryCodes,
} from '../lib/totp.js';
import { encryptField, decryptField } from '../lib/fieldCrypto.js';
import { ensureWorkspaceSigningKey, verifyEd25519Jws } from '../lib/jws.js';
import {
  ensureDefaultWorkspace,
  resolveEffectivePolicy,
  buildSignedPolicyBundle,
} from '../services/policyEngine.js';
import { appendAuditLog } from '../lib/audit.js';
import { requireAuth } from '../middleware/auth.js';

export const workspaceAuthRouter = Router();

const ADMIN_ROLES = new Set([
  'SUPER_ADMIN',
  'EXEC_MANAGER',
  'IT_ADMIN',
  'COMPLIANCE_OFFICER',
  'DEPT_HEAD',
  'BROADCASTER',
]);

export async function getDiscoveryPayload(req, res, next) {
  try {
    const ws = await ensureDefaultWorkspace();
    const signingKey = await ensureWorkspaceSigningKey(ws.id);
    const proto = req?.protocol || 'http';
    const host = (typeof req?.get === 'function' && req.get('host')) || `localhost:${env.PORT}`;
    const baseUrl = env.PUBLIC_URL || `${proto}://${host}`;
    const wsUrl = baseUrl.replace(/^http/, 'ws') + '/ws';

    const providers = await db.many(
      'SELECT id, kind, name FROM auth_providers WHERE workspace_id = $1 AND enabled = TRUE ORDER BY created_at ASC',
      [ws.id],
    );
    const authMethods = ['local', 'enrollment_token', ...providers.map((p) => p.kind)];
    const cloudCfg = ws.cloud_services_config || {};

    const payload = {
      workspace_id: ws.id,
      name: ws.name,
      logo_url: ws.logo_url || null,
      primary_color: ws.primary_color || '#0F766E',
      locale: ws.locale || 'ar',
      timezone: ws.timezone || 'Asia/Riyadh',
      official_domain: ws.official_domain || null,
      domain_verified: Boolean(ws.domain_verified),
      setup_completed: ws.setup_completed,
      setup_complete: ws.setup_completed,
      deployment_profile: (process.env.DEPLOYMENT_PROFILE || env.DEPLOYMENT_PROFILE || ws.deployment_profile).toLowerCase(),
      api_base: `${baseUrl}${env.API_PREFIX}`,
      ws_url: wsUrl,
      auth_methods: [...new Set(authMethods)],
      sso_providers: providers.map((p) => ({ id: p.id, kind: p.kind, name: p.name })),
      cloud_relay_enabled: Boolean(cloudCfg.push_relay_enabled || process.env.MADAR_RELAY_URL),
      policy_signing_pub_key: signingKey.publicKeyEd25519,
      kid: signingKey.kid,
    };

    if (res && typeof res.json === 'function') {
      res.json(payload);
      return payload;
    }
    return payload;
  } catch (err) {
    if (typeof next === 'function') return next(err);
    throw err;
  }
}

async function getUserRoles(userId) {
  const rows = await db.many('SELECT role FROM user_roles WHERE user_id = $1', [userId]);
  return rows.map((r) => r.role);
}

/**
 * Validates device constraints against effective workspace policy (TC-POL-06, TC-POL-07, TC-POL-08)
 * and registers or updates the device row.
 */
async function registerOrUpdateDevice({
  userId,
  workspaceId,
  deviceName,
  platform,
  osVersion,
  appVersion,
  devicePubKey,
  pushHandle,
  attestationToken,
  ipHash,
  effectivePolicies,
  policyVersion,
}) {
  const allowedPlatforms = effectivePolicies['device.allowed_platforms'] || ['android', 'ios', 'web', 'desktop'];
  if (!allowedPlatforms.includes(platform)) {
    throw forbidden(
      'platform_not_allowed',
      `المنصة (${platform}) غير مسموح بها بموجب سياسة مساحة العمل (device.allowed_platforms)`,
    );
  }

  const attestationState = attestationToken ? 'verified' : 'unverified';
  if (effectivePolicies['device.require_attestation'] === true && attestationState !== 'verified') {
    throw forbidden(
      'attestation_required',
      'تتطلب سياسة مساحة العمل التحقق من سلامة الجهاز (device.require_attestation)',
    );
  }

  const existing = await db.one(
    `SELECT * FROM devices
     WHERE user_id = $1 AND workspace_id = $2 AND device_pub_key = $3
     ORDER BY created_at DESC LIMIT 1`,
    [userId, workspaceId, devicePubKey],
  );

  if (existing && (existing.status === 'wipe_pending' || existing.status === 'wiped')) {
    throw forbidden('device_wiped', 'تم إصدار أمر مسح لهذا الجهاز ولا يمكن إعادة استخدامه بمفتاح الجهاز ذاته');
  }

  const maxDevices = Number(effectivePolicies['device.max_per_user'] ?? 3);
  const activeCountRow = await db.one(
    `SELECT COUNT(*)::int AS c
     FROM devices
     WHERE user_id = $1 AND workspace_id = $2 AND status = 'active'
       AND ($3::uuid IS NULL OR id <> $3::uuid)`,
    [userId, workspaceId, existing?.id || null],
  );
  if ((activeCountRow?.c || 0) >= maxDevices) {
    throw forbidden(
      'max_devices_reached',
      `تم الوصول للحد الأقصى للأجهزة المسموح بها (${maxDevices}) بموجب سياسة مساحة العمل (device.max_per_user)`,
    );
  }

  if (existing) {
    return db.one(
      `UPDATE devices
       SET device_name = $2,
           platform = $3,
           os_version = COALESCE($4, os_version),
           app_version = COALESCE($5, app_version),
           push_handle = COALESCE($6, push_handle),
           attestation_state = $7,
           status = 'active',
           policy_version = $8,
           policy_applied_at = NOW(),
           last_seen_at = NOW(),
           last_ip_hash = $9
       WHERE id = $1
       RETURNING *`,
      [
        existing.id,
        deviceName,
        platform,
        osVersion || null,
        appVersion || null,
        pushHandle || null,
        attestationState,
        policyVersion,
        ipHash,
      ],
    );
  }

  return db.one(
    `INSERT INTO devices (
       user_id, workspace_id, device_name, platform, os_version, app_version,
       device_pub_key, push_handle, attestation_state, status, policy_version,
       policy_applied_at, last_seen_at, last_ip_hash
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, NOW(), NOW(), $11)
     RETURNING *`,
    [
      userId,
      workspaceId,
      deviceName,
      platform,
      osVersion || null,
      appVersion || null,
      devicePubKey,
      pushHandle || null,
      attestationState,
      policyVersion,
      ipHash,
    ],
  );
}

async function issueWorkspaceTokens({ user, device, workspaceId, roles, effectivePolicies }) {
  const sessionTtlDays = Number(effectivePolicies['auth.session_ttl_days'] ?? 30);
  const refreshRaw = newRefreshToken();
  const refreshExpires = new Date(Date.now() + sessionTtlDays * 86_400_000);

  await db.query(
    `INSERT INTO refresh_tokens (device_id, user_id, token_hash, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [device.id, user.id, sha256(refreshRaw), refreshExpires],
  );

  const accessToken = signWorkspaceAccessToken({
    userId: user.id,
    workspaceId,
    deviceId: device.id,
    roles,
    profileType: user.profile_type || 'workspace',
    expiresIn: '15m',
  });

  const policyBundle = await buildSignedPolicyBundle(workspaceId, user.id, user.profile_type || 'workspace');

  let departmentName = user.department_name || null;
  if (!departmentName && user.department_id) {
    const deptRow = await db.one('SELECT name FROM departments WHERE id = $1', [user.department_id]);
    if (deptRow) departmentName = deptRow.name;
  }

  return {
    access_token: accessToken,
    refresh_token: refreshRaw,
    token_type: 'Bearer',
    expires_in: '15m',
    session_ttl_days: sessionTtlDays,
    device: {
      id: device.id,
      device_name: device.device_name,
      platform: device.platform,
      status: device.status,
      policy_version: device.policy_version,
    },
    user: {
      id: user.id,
      workspace_id: workspaceId,
      employee_no: user.employee_no,
      employee_id: user.employee_no,
      email: user.email,
      work_phone: user.work_phone,
      name: user.name,
      title: user.title,
      job_title: user.title,
      department_id: user.department_id,
      department_name: departmentName,
      avatar_url: user.avatar_url,
      presence_status: user.presence_status || 'available',
      presence_note: user.presence_note || '',
      roles,
      profile_type: user.profile_type || 'workspace',
    },
    policy_bundle: policyBundle,
  };
}

/**
 * Verify TOTP or Recovery Code for a user.
 */
async function verifyUserMfaCode(userId, code) {
  const clean = String(code || '').trim();
  const factor = await db.one(
    `SELECT * FROM mfa_factors
     WHERE user_id = $1 AND kind = 'totp'
     ORDER BY created_at DESC LIMIT 1`,
    [userId],
  );

  if (factor && /^\d{6}$/.test(clean)) {
    const secret = decryptField(factor.secret_ciphertext, factor.secret_iv, factor.key_id);
    const check = verifyTotpCode(secret, clean, factor.last_used_step);
    if (check.valid) {
      await db.query(
        'UPDATE mfa_factors SET verified_at = COALESCE(verified_at, NOW()), last_used_step = $2 WHERE id = $1',
        [factor.id, check.step],
      );
      return { verified: true, method: 'totp' };
    }
    if (check.reason === 'replay_detected') {
      return { verified: false, reason: 'replay_detected' };
    }
  }

  // Check single-use recovery code (e.g. XXXX-XXXX)
  const codeHash = sha256(clean.toUpperCase());
  const rec = await db.one(
    `UPDATE recovery_codes
     SET used_at = NOW()
     WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
     RETURNING id`,
    [userId, codeHash],
  );
  if (rec) {
    return { verified: true, method: 'recovery_code' };
  }

  return { verified: false };
}

/**
 * POST /api/v1/enroll — Enrolls a device into a workspace using a signed enrollment token (ENR-02..04).
 */
export async function handleEnrollment(req, res) {
  const {
    enrollment_token,
    device_name,
    platform,
    os_version,
    app_version,
    device_pub_key,
    device_id,
    push_handle,
    attestation_token,
    identifier,
    password,
    name,
  } = req.body || {};

  if (!enrollment_token || typeof enrollment_token !== 'string') {
    throw badRequest('invalid_enrollment_token', 'رمز الالتحاق مطلوب');
  }

  const normalizedPlatform =
    !platform || platform === 'flutter' ? 'android' : platform;
  const resolvedDeviceName = (device_name || 'Madar Agent').trim();
  const resolvedPubKey = (
    device_pub_key ||
    device_id ||
    `agent-ed25519-${crypto.randomUUID()}`
  ).trim();

  const tokenHash = sha256(enrollment_token.trim());
  let tokenRow = await db.one(
    'SELECT * FROM enrollment_tokens WHERE token_hash = $1 OR jws_compact = $2',
    [tokenHash, enrollment_token.trim()],
  );

  if (!tokenRow) {
    throw badRequest('invalid_enrollment_token', 'رمز الالتحاق غير صالح');
  }
  if (tokenRow.revoked_at) {
    throw forbidden('enrollment_token_revoked', 'تم إلغاء رمز الالتحاق');
  }
  if (new Date(tokenRow.expires_at) < new Date()) {
    throw badRequest('enrollment_token_expired', 'انتهت صلاحية رمز الالتحاق');
  }
  if (tokenRow.used_count >= tokenRow.max_uses) {
    throw badRequest('enrollment_token_exhausted', 'تم استنفاد عدد مرات استخدام رمز الالتحاق');
  }

  // Verify JWS signature if jws_compact is stored
  if (tokenRow.jws_compact) {
    const signingKey = await ensureWorkspaceSigningKey(tokenRow.workspace_id);
    try {
      verifyEd25519Jws(tokenRow.jws_compact, signingKey.publicKeyEd25519);
    } catch {
      throw badRequest('invalid_enrollment_signature', 'توقيع رمز الالتحاق غير صالح');
    }
  }

  let user = null;
  if (tokenRow.target_user_id) {
    user = await db.one('SELECT * FROM users WHERE id = $1', [tokenRow.target_user_id]);
  } else if (identifier) {
    user = await db.one(
      `SELECT * FROM users
       WHERE workspace_id = $1
         AND (UPPER(employee_no) = UPPER($2) OR LOWER(email) = LOWER($2) OR work_phone = $2)`,
      [tokenRow.workspace_id, identifier.trim()],
    );
  }

  // If identifier was a default placeholder (e.g. EMP-4096) or slight typo (e.g. AMD-001 vs ADM-001)
  // and password matches an existing user in this workspace, bind to that user instead of creating a duplicate
  if (!user && !tokenRow.target_user_id && password) {
    const candidates = await db.many(
      `SELECT u.*, c.password_hash
       FROM users u
       JOIN credentials c ON c.user_id = u.id
       WHERE u.workspace_id = $1 AND u.account_status IN ('active', 'invited')`,
      [tokenRow.workspace_id],
    );
    const matched = candidates.filter((cand) => verifyPassword(password, cand.password_hash));
    if (matched.length === 1) {
      const { password_hash: _ph, ...matchedUser } = matched[0];
      user = matchedUser;
    }
  }

  // If token is a multi-use group invitation and user doesn't exist yet, create user if identifier & name provided
  if (!user) {
    if (!identifier && !name) {
      throw badRequest('user_info_required', 'الرجاء إدخال الرقم الوظيفي أو البريد واسم الموظف لإتمام الالتحاق');
    }
    user = await db.one(
      `INSERT INTO users (workspace_id, employee_no, name, account_status, profile_type, last_seen_at)
       VALUES ($1, $2, $3, 'active', 'workspace', NOW())
       RETURNING *`,
      [tokenRow.workspace_id, identifier || `EMP-${Date.now()}`, name || identifier],
    );
    await db.query(
      "INSERT INTO user_roles (user_id, role) VALUES ($1, 'MEMBER') ON CONFLICT DO NOTHING",
      [user.id],
    );
  } else if (user.account_status === 'invited') {
    user = await db.one(
      "UPDATE users SET account_status = 'active', updated_at = NOW() WHERE id = $1 RETURNING *",
      [user.id],
    );
  }

  if (user.account_status === 'suspended' || user.account_status === 'offboarded') {
    throw forbidden('account_inactive', 'حساب مساحة العمل هذا غير نشط');
  }

  if (tokenRow.default_group_id) {
    const inGroup = await db.one(
      'SELECT 1 FROM policy_group_members WHERE group_id = $1 AND user_id = $2',
      [tokenRow.default_group_id, user.id],
    );
    if (!inGroup) {
      await db.query(
        'INSERT INTO policy_group_members (group_id, user_id) VALUES ($1, $2)',
        [tokenRow.default_group_id, user.id],
      );
    }
  }

  const resolved = await resolveEffectivePolicy(tokenRow.workspace_id, user.id, 'workspace');

  // Check if user already has a password in credentials
  const existingCred = await db.one('SELECT * FROM credentials WHERE user_id = $1', [user.id]);
  if (existingCred && !tokenRow.target_user_id) {
    // Shared multi-use organization QR code: if account already has a password, require & verify it
    if (!password || !verifyPassword(password, existingCred.password_hash)) {
      throw unauthorized(
        'invalid_credentials',
        'كلمة مرور مساحة العمل مطلوبة أو غير صحيحة لهذا الحساب عند استخدام رمز إلحاق عام',
      );
    }
  } else if (password) {
    if (!existingCred || !verifyPassword(password, existingCred.password_hash)) {
      const minLen = Number(resolved.policies['auth.password_min_length'] ?? 10);
      const check = validatePasswordComplexity(password, minLen);
      if (!check.valid) {
        throw badRequest('weak_password', check.reason);
      }
      await db.query(
        `INSERT INTO credentials (user_id, password_hash, must_change_password, password_changed_at)
         VALUES ($1, $2, FALSE, NOW())
         ON CONFLICT (user_id) DO UPDATE
         SET password_hash = EXCLUDED.password_hash, must_change_password = FALSE, password_changed_at = NOW()`,
        [user.id, hashPassword(password)],
      );
    }
  }

  // Auto-join department channel and default public channels
  const autoChannels = await db.many(
    `SELECT id FROM channels
     WHERE workspace_id = $1 AND is_archived = FALSE
       AND (kind IN ('public_channel', 'broadcast_feed') OR ($2::uuid IS NOT NULL AND department_id = $2::uuid))`,
    [tokenRow.workspace_id, user.department_id || null],
  );
  for (const ch of autoChannels) {
    await db.query(
      `INSERT INTO channel_members (channel_id, user_id, role)
       VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING`,
      [ch.id, user.id],
    );
  }

  const ipHash = sha256(String(req.ip || 'unknown')).slice(0, 32);
  const device = await registerOrUpdateDevice({
    userId: user.id,
    workspaceId: tokenRow.workspace_id,
    deviceName: resolvedDeviceName,
    platform: normalizedPlatform,
    osVersion: os_version,
    appVersion: app_version,
    devicePubKey: resolvedPubKey,
    pushHandle: push_handle,
    attestationToken: attestation_token,
    ipHash,
    effectivePolicies: resolved.policies,
    policyVersion: resolved.version,
  });

  await db.query(
    'UPDATE enrollment_tokens SET used_count = used_count + 1 WHERE id = $1',
    [tokenRow.id],
  );

  const roles = await getUserRoles(user.id);
  await appendAuditLog({
    workspaceId: tokenRow.workspace_id,
    actorUserId: user.id,
    actorDeviceId: device.id,
    action: 'device.enrolled',
    targetType: 'device',
    targetId: device.id,
    metadata: {
      enrollment_token_id: tokenRow.id,
      platform: normalizedPlatform,
      device_name: resolvedDeviceName,
    },
    ipHash,
  });

  const sessionPayload = await issueWorkspaceTokens({
    user,
    device,
    workspaceId: tokenRow.workspace_id,
    roles,
    effectivePolicies: resolved.policies,
  });

  res.status(201).json({
    success: true,
    ...sessionPayload,
  });
}

/**
 * POST /api/v1/auth/login — Workspace credential login with lockout, device binding & MFA enforcement.
 */
workspaceAuthRouter.post(
  ['/login', '/workspace/login', '/password/login'],
  validate({
    body: z.object({
      identifier: z.string().trim().min(1).max(255),
      password: z.string().min(1).max(255),
      workspace_id: z.string().uuid().optional(),
      device_name: z.string().trim().min(1).max(120).default('جهاز العمل'),
      platform: z.enum(['android', 'ios', 'web', 'desktop', 'flutter']).default('web'),
      os_version: z.string().trim().max(40).optional(),
      app_version: z.string().trim().max(32).optional(),
      device_pub_key: z.string().trim().min(4).max(512).default('web-ephemeral-device-key'),
      device_id: z.string().trim().max(128).optional(),
      push_handle: z.string().trim().max(128).optional(),
      attestation_token: z.string().trim().max(4096).optional(),
      totp_code: z.string().trim().max(32).optional(),
    }),
  }),
  async (req, res) => {
    const {
      identifier,
      password,
      workspace_id,
      device_name,
      platform: rawPlatform,
      os_version,
      app_version,
      device_pub_key,
      device_id,
      push_handle,
      attestation_token,
      totp_code,
    } = req.body;
    const platform = rawPlatform === 'flutter' ? 'android' : rawPlatform;
    const resolvedPubKey =
      device_pub_key === 'web-ephemeral-device-key' && device_id
        ? device_id
        : device_pub_key;

    const ws = workspace_id
      ? await db.one('SELECT * FROM workspace WHERE id = $1', [workspace_id])
      : await ensureDefaultWorkspace();
    if (!ws) throw notFound('workspace_not_found', 'مساحة العمل غير موجودة');

    const user = await db.one(
      `SELECT * FROM users
       WHERE (workspace_id = $1 OR workspace_id IS NULL)
         AND (employee_no = $2 OR LOWER(email) = LOWER($2) OR work_phone = $2 OR phone = $2)
       ORDER BY workspace_id NULLS LAST LIMIT 1`,
      [ws.id, identifier],
    );

    const ipHash = sha256(String(req.ip || 'unknown')).slice(0, 32);

    if (!user) {
      throw unauthorized('invalid_credentials', 'بيانات الدخول غير صحيحة');
    }

    if (user.account_status === 'suspended' || user.account_status === 'offboarded') {
      throw forbidden('account_inactive', 'تم تعليق حساب مساحة العمل هذا أو إنهاء صلاحيته');
    }

    const resolved = await resolveEffectivePolicy(ws.id, user.id, 'workspace');
    const maxAttempts = Number(resolved.policies['auth.max_failed_attempts'] ?? 5);
    const lockoutMinutes = Number(resolved.policies['auth.lockout_minutes'] ?? 15);

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      throw forbidden('account_locked', 'تم قفل الحساب مؤقتاً بسبب تجاوز محاولات الدخول الخاطئة', {
        locked_until: new Date(user.locked_until).toISOString(),
      });
    }

    const cred = await db.one('SELECT * FROM credentials WHERE user_id = $1', [user.id]);
    if (!cred || !verifyPassword(password, cred.password_hash)) {
      const nextFails = (user.failed_login_attempts || 0) + 1;
      const shouldLock = nextFails >= maxAttempts;
      const lockedUntil = shouldLock ? new Date(Date.now() + lockoutMinutes * 60_000) : null;

      await db.query(
        'UPDATE users SET failed_login_attempts = $2, locked_until = $3, updated_at = NOW() WHERE id = $1',
        [user.id, nextFails, lockedUntil],
      );

      await appendAuditLog({
        workspaceId: ws.id,
        actorUserId: user.id,
        action: shouldLock ? 'auth.account.locked' : 'auth.login.failed',
        targetType: 'user',
        targetId: user.id,
        metadata: { attempts: nextFails, locked: shouldLock },
        ipHash,
      });

      if (shouldLock) {
        throw forbidden('account_locked', 'تم قفل الحساب مؤقتاً بسبب تجاوز محاولات الدخول الخاطئة', {
          locked_until: lockedUntil.toISOString(),
        });
      }
      throw unauthorized('invalid_credentials', 'بيانات الدخول غير صحيحة', {
        remaining_attempts: Math.max(maxAttempts - nextFails, 0),
      });
    }

    // Password verified — reset failed login attempts
    await db.query(
      "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, account_status = 'active', last_seen_at = NOW() WHERE id = $1",
      [user.id],
    );

    const device = await registerOrUpdateDevice({
      userId: user.id,
      workspaceId: ws.id,
      deviceName: device_name,
      platform,
      osVersion: os_version,
      appVersion: app_version,
      devicePubKey: resolvedPubKey,
      pushHandle: push_handle,
      attestationToken: attestation_token,
      ipHash,
      effectivePolicies: resolved.policies,
      policyVersion: resolved.version,
    });

    const roles = await getUserRoles(user.id);
    const mfaPolicy = resolved.policies['auth.mfa_required'] || 'admins_only';
    const isAdmin = roles.some((r) => ADMIN_ROLES.has(r));
    const mfaRequiredByPolicy = mfaPolicy === 'all' || (mfaPolicy === 'admins_only' && isAdmin);

    const verifiedFactor = await db.one(
      "SELECT id FROM mfa_factors WHERE user_id = $1 AND kind = 'totp' AND verified_at IS NOT NULL LIMIT 1",
      [user.id],
    );

    if (verifiedFactor) {
      if (totp_code) {
        const mfaRes = await verifyUserMfaCode(user.id, totp_code);
        if (!mfaRes.verified) {
          if (mfaRes.reason === 'replay_detected') {
            throw badRequest('totp_replay_detected', 'تم استخدام رمز التحقق هذا مسبقاً في نفس النافذة الزمنية');
          }
          throw unauthorized('invalid_mfa_code', 'رمز التحقق الثنائي (TOTP) غير صحيح');
        }
      } else {
        const mfaToken = signMfaPreAuthToken({
          userId: user.id,
          workspaceId: ws.id,
          deviceId: device.id,
        });
        res.json({
          success: true,
          mfa_required: true,
          mfa_setup_required: false,
          mfa_token: mfaToken,
          user_id: user.id,
          device_id: device.id,
        });
        return;
      }
    }

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: user.id,
      actorDeviceId: device.id,
      action: 'auth.login.succeeded',
      targetType: 'user',
      targetId: user.id,
      metadata: { platform, device_name },
      ipHash,
    });

    const tokens = await issueWorkspaceTokens({
      user,
      device,
      workspaceId: ws.id,
      roles,
      effectivePolicies: resolved.policies,
    });

    res.json({
      success: true,
      mfa_setup_required: !verifiedFactor && mfaRequiredByPolicy,
      must_change_password: Boolean(cred.must_change_password),
      ...tokens,
    });
  },
);

/**
 * Helper to resolve user from either normal Bearer access_token or mfa_token.
 */
function resolveMfaOrAuthUser(req) {
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
  const rawToken = req.body?.mfa_token || bearer;
  if (!rawToken) throw unauthorized('missing_token', 'مطلوب رمز مصادقة');
  try {
    const payload = verifyAccessToken(rawToken);
    return {
      userId: Number(payload.sub),
      workspaceId: payload.wid || null,
      deviceId: payload.did || null,
      mfaPending: Boolean(payload.mfa_pending),
    };
  } catch {
    throw unauthorized('invalid_token', 'رمز المصادقة غير صالح أو منتهي الصلاحية');
  }
}

/**
 * POST /api/v1/auth/totp/setup — Generates a TOTP secret and 10 single-use recovery codes (AUTH-02, AUTH-03).
 */
workspaceAuthRouter.post('/totp/setup', async (req, res) => {
  const ctx = resolveMfaOrAuthUser(req);
  const user = await db.one('SELECT * FROM users WHERE id = $1', [ctx.userId]);
  if (!user) throw notFound('user_not_found');

  const ws = ctx.workspaceId
    ? await db.one('SELECT * FROM workspace WHERE id = $1', [ctx.workspaceId])
    : await ensureDefaultWorkspace();

  const secret = generateTotpSecret(20);
  const enc = encryptField(secret);
  const { codes, hashes } = generateRecoveryCodes(10);

  await db.tx(async (client) => {
    await client.query("DELETE FROM mfa_factors WHERE user_id = $1 AND kind = 'totp'", [user.id]);
    await client.query('DELETE FROM recovery_codes WHERE user_id = $1', [user.id]);

    await client.query(
      `INSERT INTO mfa_factors (user_id, kind, secret_ciphertext, secret_iv, key_id)
       VALUES ($1, 'totp', $2, $3, $4)`,
      [user.id, enc.ciphertext, enc.iv, enc.keyId],
    );

    for (const h of hashes) {
      await client.query(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)',
        [user.id, h],
      );
    }
  });

  const accountName = user.email || user.employee_no || user.phone || `user-${user.id}`;
  res.json({
    success: true,
    secret,
    otpauth_uri: totpUri({ secret, accountName, issuer: ws?.name || 'Madar Workspace' }),
    recovery_codes: codes,
  });
});

/**
 * POST /api/v1/auth/totp/verify — Verifies a 6-digit TOTP or recovery code and completes login if mfa_token was used.
 */
workspaceAuthRouter.post(
  '/totp/verify',
  validate({
    body: z.object({
      code: z.string().trim().min(6).max(32),
      mfa_token: z.string().optional(),
    }),
  }),
  async (req, res) => {
    const ctx = resolveMfaOrAuthUser(req);
    const { code } = req.body;

    const result = await verifyUserMfaCode(ctx.userId, code);
    if (!result.verified) {
      if (result.reason === 'replay_detected') {
        throw badRequest('totp_replay_detected', 'تم استخدام رمز التحقق هذا مسبقاً في نفس النافذة الزمنية (منع إعادة الاستخدام RFC 6238)');
      }
      throw unauthorized('invalid_mfa_code', 'رمز التحقق الثنائي أو رمز الاسترداد غير صحيح');
    }

    const user = await db.one('SELECT * FROM users WHERE id = $1', [ctx.userId]);
    const ws = ctx.workspaceId
      ? await db.one('SELECT * FROM workspace WHERE id = $1', [ctx.workspaceId])
      : await ensureDefaultWorkspace();

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: user.id,
      actorDeviceId: ctx.deviceId,
      action: 'auth.mfa.verified',
      targetType: 'user',
      targetId: user.id,
      metadata: { method: result.method },
    });

    if (ctx.deviceId) {
      const device = await db.one('SELECT * FROM devices WHERE id = $1', [ctx.deviceId]);
      if (device) {
        const roles = await getUserRoles(user.id);
        const resolved = await resolveEffectivePolicy(ws.id, user.id, 'workspace');
        const tokens = await issueWorkspaceTokens({
          user,
          device,
          workspaceId: ws.id,
          roles,
          effectivePolicies: resolved.policies,
        });
        res.json({
          success: true,
          verified: true,
          method: result.method,
          ...tokens,
        });
        return;
      }
    }

    res.json({
      success: true,
      verified: true,
      method: result.method,
    });
  },
);

/**
 * POST /api/v1/auth/password — Change password for current authenticated user.
 */
workspaceAuthRouter.post(
  '/password',
  requireAuth,
  validate({
    body: z.object({
      current_password: z.string().optional(),
      new_password: z.string().min(6).max(255),
    }),
  }),
  async (req, res) => {
    const { current_password, new_password } = req.body;
    const user = await db.one('SELECT * FROM users WHERE id = $1', [req.auth.userId]);
    if (!user) throw notFound('user_not_found');

    const wsId = req.auth.workspaceId || user.workspace_id || (await ensureDefaultWorkspace()).id;
    const resolved = await resolveEffectivePolicy(wsId, user.id, 'workspace');
    const minLen = Number(resolved.policies['auth.password_min_length'] ?? 10);
    const check = validatePasswordComplexity(new_password, minLen);
    if (!check.valid) {
      throw badRequest('weak_password', check.reason);
    }

    const existing = await db.one('SELECT * FROM credentials WHERE user_id = $1', [user.id]);
    if (existing && !existing.must_change_password) {
      if (!current_password || !verifyPassword(current_password, existing.password_hash)) {
        throw unauthorized('invalid_current_password', 'كلمة المرور الحالية غير صحيحة');
      }
    }

    await db.query(
      `INSERT INTO credentials (user_id, password_hash, must_change_password, password_changed_at)
       VALUES ($1, $2, FALSE, NOW())
       ON CONFLICT (user_id) DO UPDATE
       SET password_hash = EXCLUDED.password_hash, must_change_password = FALSE, password_changed_at = NOW()`,
      [user.id, hashPassword(new_password)],
    );

    await appendAuditLog({
      workspaceId: wsId,
      actorUserId: user.id,
      actorDeviceId: req.auth.deviceId || null,
      action: 'auth.password.changed',
      targetType: 'user',
      targetId: user.id,
    });

    res.json({ success: true });
  },
);

/**
 * POST /api/v1/auth/sso/login — Enterprise SSO & Directory Login (AUTH-01: OIDC, SAML 2.0, Active Directory LDAP).
 */
workspaceAuthRouter.post(
  '/sso/login',
  validate({
    body: z.object({
      provider_id: z.string().uuid().optional(),
      provider_kind: z.enum(['oidc', 'saml', 'ldap']).optional(),
      id_token: z.string().optional(),
      saml_assertion: z.string().optional(),
      ldap_username: z.string().optional(),
      ldap_password: z.string().optional(),
      device_name: z.string().trim().min(1).max(120).default('Enterprise SSO Device'),
      platform: z.enum(['android', 'ios', 'web', 'desktop']).default('web'),
      os_version: z.string().max(40).optional(),
      app_version: z.string().max(32).optional(),
      device_pub_key: z.string().min(8).default('sso-ephemeral-device-key'),
      push_handle: z.string().max(128).optional(),
      attestation_token: z.string().optional(),
    }),
  }),
  async (req, res) => {
    const ws = await ensureDefaultWorkspace();
    const {
      provider_id,
      provider_kind,
      id_token,
      saml_assertion,
      ldap_username,
      ldap_password,
      device_name,
      platform,
      os_version,
      app_version,
      device_pub_key,
      push_handle,
      attestation_token,
    } = req.body;

    const providerRow = provider_id
      ? await db.one(
          'SELECT * FROM auth_providers WHERE id = $1 AND workspace_id = $2 AND enabled = TRUE',
          [provider_id, ws.id],
        )
      : await db.one(
          'SELECT * FROM auth_providers WHERE workspace_id = $1 AND ($2::text IS NULL OR kind = $2) AND enabled = TRUE ORDER BY created_at DESC LIMIT 1',
          [ws.id, provider_kind || null],
        );

    if (!providerRow) {
      throw notFound('sso_provider_not_found', 'مزود هوية مساحة العمل (OIDC / SAML / LDAP) غير مفعل أو غير موجود');
    }

    const configJson = JSON.parse(
      decryptField(providerRow.config_ciphertext, providerRow.config_iv, providerRow.key_id),
    );

    let externalId = null;
    let email = null;
    let employeeNo = null;
    let displayName = null;
    let title = null;
    let departmentCode = null;

    if (providerRow.kind === 'oidc') {
      if (!id_token) throw badRequest('missing_id_token', 'رمز الهوية (OIDC id_token) مطلوب');
      let claims;
      if (configJson.signing_pub_key) {
        const verified = verifyEd25519Jws(id_token, configJson.signing_pub_key);
        claims = verified.payload;
      } else if (configJson.client_secret) {
        const parts = id_token.split('.');
        if (parts.length !== 3) throw unauthorized('invalid_oidc_token', 'صيغة رمز OIDC غير صالحة');
        const expectedSig = crypto
          .createHmac('sha256', configJson.client_secret)
          .update(`${parts[0]}.${parts[1]}`)
          .digest('base64url');
        if (parts[2] !== expectedSig) {
          throw unauthorized('invalid_oidc_signature', 'توقيع رمز OIDC غير صالح');
        }
        claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      } else {
        throw unauthorized('oidc_verifier_not_configured', 'لم يتم تكوين مفتاح التحقق لمزود OIDC');
      }
      if (configJson.issuer && claims.iss !== configJson.issuer) {
        throw unauthorized('invalid_oidc_issuer', 'مصدر رمز OIDC (iss) غير مطابق للمزود المعتمد');
      }
      if (claims.exp && Date.now() / 1000 > Number(claims.exp)) {
        throw unauthorized('expired_oidc_token', 'انتهت صلاحية رمز OIDC');
      }
      externalId = String(claims.sub || claims.oid || '');
      email = claims.email ? String(claims.email).toLowerCase() : null;
      employeeNo = claims.employee_no || claims.employeeNumber || externalId;
      displayName = claims.name || email || employeeNo;
      title = claims.title || claims.jobTitle || null;
      departmentCode = claims.department_code || claims.department || null;
    } else if (providerRow.kind === 'saml') {
      if (!saml_assertion) throw badRequest('missing_saml_assertion', 'إفادة SAML 2.0 مطلوبة');
      const decoded = Buffer.from(saml_assertion, 'base64').toString('utf8');
      let assertion;
      try {
        assertion = JSON.parse(decoded);
      } catch {
        throw unauthorized('invalid_saml_assertion', 'صيغة إفادة SAML غير صالحة');
      }
      if (configJson.idp_signing_secret) {
        const expectedMac = crypto
          .createHmac('sha256', configJson.idp_signing_secret)
          .update(`${assertion.issuer}|${assertion.name_id}|${assertion.not_on_or_after}`)
          .digest('hex');
        if (assertion.signature !== expectedMac) {
          throw unauthorized('invalid_saml_signature', 'توقيع إفادة SAML 2.0 غير صالح');
        }
      }
      if (assertion.not_on_or_after && Date.now() > new Date(assertion.not_on_or_after).getTime()) {
        throw unauthorized('expired_saml_assertion', 'انتهت صلاحية إفادة SAML 2.0');
      }
      externalId = String(assertion.name_id || '');
      email = assertion.email ? String(assertion.email).toLowerCase() : null;
      employeeNo = assertion.employee_no || externalId;
      displayName = assertion.display_name || assertion.name || email;
      title = assertion.title || null;
      departmentCode = assertion.department_code || null;
    } else if (providerRow.kind === 'ldap') {
      if (!ldap_username || !ldap_password) {
        throw badRequest('missing_ldap_credentials', 'اسم مستخدم وكلمة مرور الدليل النشط (Active Directory / LDAP) مطلوبان');
      }
      const directoryUsers = Array.isArray(configJson.directory_entries) ? configJson.directory_entries : [];
      const entry = directoryUsers.find(
        (u) =>
          u.username === ldap_username ||
          u.employee_no === ldap_username ||
          (u.email && u.email.toLowerCase() === ldap_username.toLowerCase()),
      );
      if (!entry) {
        throw unauthorized('ldap_bind_failed', 'الحساب غير موجود في الدليل النشط (Active Directory)');
      }
      if (entry.active === false || entry.disabled === true || entry.status === 'disabled') {
        throw forbidden('ldap_account_disabled', 'تم تعطيل هذا الحساب في الدليل النشط (Active Directory)');
      }
      const pwdValid = entry.password_hash
        ? verifyPassword(ldap_password, entry.password_hash)
        : entry.password === ldap_password;
      if (!pwdValid) {
        throw unauthorized('ldap_bind_failed', 'بيانات اعتماد الدليل النشط (LDAP Bind) غير صحيحة');
      }
      externalId = String(entry.dn || entry.external_id || entry.employee_no || ldap_username);
      email = entry.email ? String(entry.email).toLowerCase() : null;
      employeeNo = entry.employee_no || ldap_username;
      displayName = entry.name || ldap_username;
      title = entry.title || null;
      departmentCode = entry.department_code || null;
    }

    if (!externalId && !email && !employeeNo) {
      throw unauthorized('sso_identity_missing', 'تعذر استخراج هوية الموظف من مزود الهوية');
    }

    let deptId = null;
    if (departmentCode) {
      const dept = await db.one(
        'SELECT id FROM departments WHERE workspace_id = $1 AND UPPER(code) = UPPER($2)',
        [ws.id, departmentCode],
      );
      deptId = dept?.id || null;
    }

    // Lookup existing user or JIT provision
    let user = await db.one(
      `SELECT * FROM users
       WHERE workspace_id = $1
         AND (
           (external_idp_id IS NOT NULL AND external_idp_id = $2)
           OR (email IS NOT NULL AND LOWER(email) = LOWER($3))
           OR (employee_no IS NOT NULL AND employee_no = $4)
         )
       LIMIT 1`,
      [ws.id, externalId || '', email || '', employeeNo || ''],
    );

    if (user && (user.account_status === 'suspended' || user.account_status === 'offboarded')) {
      throw forbidden('account_inactive', 'تم تعليق حساب مساحة العمل هذا أو إنهاء ارتباطه');
    }

    if (!user) {
      user = await db.one(
        `INSERT INTO users (
           workspace_id, employee_no, name, email, title, department_id,
           account_status, profile_type, external_idp_id, auth_provider_id
         ) VALUES ($1, $2, $3, $4, $5, $6, 'active', 'workspace', $7, $8)
         RETURNING *`,
        [
          ws.id,
          employeeNo,
          displayName || employeeNo,
          email,
          title,
          deptId,
          externalId,
          providerRow.id,
        ],
      );
      await db.query(
        `INSERT INTO user_roles (user_id, role) VALUES ($1, 'MEMBER') ON CONFLICT DO NOTHING`,
        [user.id],
      );
    } else {
      user = await db.one(
        `UPDATE users
         SET external_idp_id = COALESCE($2, external_idp_id),
             auth_provider_id = $3,
             department_id = COALESCE($4, department_id),
             title = COALESCE($5, title),
             account_status = CASE WHEN account_status = 'invited' THEN 'active' ELSE account_status END
         WHERE id = $1
         RETURNING *`,
        [user.id, externalId, providerRow.id, deptId, title],
      );
    }

    const roles = await getUserRoles(user.id);
    const resolved = await resolveEffectivePolicy(ws.id, user.id, 'workspace');
    const ipHash = sha256(req.ip || '127.0.0.1').slice(0, 32);

    const device = await registerOrUpdateDevice({
      userId: user.id,
      workspaceId: ws.id,
      deviceName: device_name,
      platform,
      osVersion: os_version,
      appVersion: app_version,
      devicePubKey: device_pub_key,
      pushHandle: push_handle,
      attestationToken: attestation_token,
      ipHash,
      effectivePolicies: resolved.policies,
      policyVersion: resolved.version,
    });

    const tokens = await issueWorkspaceTokens({
      user,
      device,
      workspaceId: ws.id,
      roles,
      effectivePolicies: resolved.policies,
    });
    const policyBundle = await buildSignedPolicyBundle(ws.id, user.id, 'workspace');

    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: user.id,
      actorDeviceId: device.id,
      action: 'auth.sso.login',
      targetType: 'user',
      targetId: user.id,
      metadata: {
        provider_id: providerRow.id,
        provider_kind: providerRow.kind,
        provider_name: providerRow.name,
      },
    });

    res.json({
      success: true,
      sso_provider: {
        id: providerRow.id,
        kind: providerRow.kind,
        name: providerRow.name,
      },
      user: {
        id: user.id,
        employee_no: user.employee_no,
        name: user.name,
        email: user.email,
        title: user.title,
        department_id: user.department_id,
        roles,
      },
      device: {
        id: device.id,
        device_name: device.device_name,
        platform: device.platform,
        status: device.status,
      },
      ...tokens,
      policy_bundle: policyBundle,
    });
  },
);

