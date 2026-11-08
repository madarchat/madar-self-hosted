import crypto from 'node:crypto';
import { Router } from 'express';
import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import { env } from '../config/env.js';
import { db } from '../db/pool.js';
import { validate, z, phoneSchema } from '../lib/validate.js';
import { HttpError, badRequest, unauthorized, tooMany } from '../lib/errors.js';
import {
  generateOtp, hashOtp, safeEqual, signAccessToken, signWorkspaceAccessToken, newRefreshToken, sha256,
} from '../lib/tokens.js';
import { sendOtpSms } from '../lib/sms.js';
import { FirebaseAuthError, fetchRecaptchaParams, sendFirebaseCode, verifyFirebaseCode } from '../lib/firebasePhone.js';
import { requireAuth } from '../middleware/auth.js';
import { serializeUser, USER_COLUMNS } from '../lib/serialize.js';
import { logger } from '../lib/logger.js';
import { syncUserPhoneHash } from '../lib/phoneHashSync.js';
import { workspaceAuthRouter } from './workspace_auth.js';
import { resolveEffectivePolicy, ensureDefaultWorkspace } from '../services/policyEngine.js';

export const authRouter = Router();
authRouter.use('/', workspaceAuthRouter);

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: env.IS_TEST ? 1000 : 50,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => `${ipKeyGenerator(req.ip)}:${req.body?.phone ?? ''}`,
  handler: (_req, _res, next) => next(tooMany('otp_rate_limited', 'Too many code requests. Try again later.')),
});

const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: env.IS_TEST ? 1000 : 50,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => `${ipKeyGenerator(req.ip)}:${req.body?.phone ?? ''}`,
  handler: (_req, _res, next) => next(tooMany('verify_rate_limited', 'Too many verification attempts. Try again later.')),
});

const refreshLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: env.IS_TEST ? 1000 : 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (_req, _res, next) => next(tooMany('refresh_rate_limited', 'Too many session refreshes. Try again later.')),
});

async function issueSession(user, deviceName) {
  const sessionId = crypto.randomUUID();
  const refreshToken = newRefreshToken();
  const expires = new Date(Date.now() + env.REFRESH_TOKEN_TTL_DAYS * 86_400_000);
  await db.query(
    `INSERT INTO sessions (id, user_id, refresh_token_hash, device_name, expires_at, last_used_at)
     VALUES ($1, $2, $3, $4, $5, NOW())`,
    [sessionId, user.id, sha256(refreshToken), deviceName || null, expires],
  );
  return {
    access_token: signAccessToken(user, sessionId),
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: env.ACCESS_TOKEN_TTL,
    session_id: sessionId,
  };
}

const attestationField = z.string().trim().min(1).max(20_000).optional();

const requestCodeSchema = z.object({
  phone: phoneSchema,
  device_id: z.string().trim().min(1).max(80).optional(),
  play_integrity_token: attestationField,
  recaptcha_token: attestationField,
  ios_receipt: attestationField,
  ios_secret: attestationField,
  client_platform: z.enum(['ios', 'android', 'web']).optional(),
  locale: z.string().trim().regex(/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$/).optional(),
});

async function enforceOtpQuotas(req, phone) {
  const phoneHash = sha256(phone);
  const ipHash = sha256(String(req.ip || 'unknown')).slice(0, 32);
  const rawDevice = req.body?.device_id || req.headers['x-device-id'];
  const deviceId = typeof rawDevice === 'string' && rawDevice.trim() ? rawDevice.trim().slice(0, 80) : null;
  const windowStart = new Date(Date.now() - env.OTP_QUOTA_WINDOW_MS);

  const [phoneCnt, ipCnt, devCnt] = await Promise.all([
    db.one('SELECT COUNT(*)::int AS c FROM otp_request_audit WHERE phone_hash = $1 AND created_at > $2', [phoneHash, windowStart]),
    db.one('SELECT COUNT(*)::int AS c FROM otp_request_audit WHERE ip_hash = $1 AND created_at > $2', [ipHash, windowStart]),
    deviceId
      ? db.one('SELECT COUNT(*)::int AS c FROM otp_request_audit WHERE device_id = $1 AND created_at > $2', [deviceId, windowStart])
      : Promise.resolve({ c: 0 }),
  ]);

  if ((phoneCnt?.c ?? 0) >= env.OTP_PHONE_LIMIT) {
    throw tooMany('otp_phone_quota_exceeded', 'تم تجاوز الحد المسموح لطلبات رمز التحقق لهذا الرقم. حاول لاحقاً.');
  }
  if ((ipCnt?.c ?? 0) >= env.OTP_IP_LIMIT) {
    throw tooMany('otp_ip_quota_exceeded', 'تم تجاوز الحد المسموح لطلبات رمز التحقق من هذه الشبكة. حاول لاحقاً.');
  }
  if (deviceId && (devCnt?.c ?? 0) >= env.OTP_DEVICE_LIMIT) {
    throw tooMany('otp_device_quota_exceeded', 'تم تجاوز الحد المسموح لطلبات رمز التحقق من هذا الجهاز. حاول لاحقاً.');
  }

  await db.query(
    'INSERT INTO otp_request_audit (phone_hash, ip_hash, device_id) VALUES ($1, $2, $3)',
    [phoneHash, ipHash, deviceId],
  );
}

function rethrowFirebase(err) {
  if (err instanceof FirebaseAuthError) {
    throw new HttpError(err.httpStatus, err.code, err.message, {
      firebase: err.firebaseCode,
      ...(err.code === 'needs_recaptcha' ? { fallback: 'recaptcha' } : {}),
    });
  }
  throw err;
}

/** Public: the login screen loads this when Play Integrity cannot send a real SMS. */
authRouter.get('/recaptcha', async (_req, res) => {
  try {
    const params = await fetchRecaptchaParams();
    res.json({
      success: true,
      site_key: params.siteKey,
      stoken: params.stoken,
      auth_domain: params.authDomain,
    });
  } catch (err) {
    rethrowFirebase(err);
  }
});

async function openAccount(phone, recordId, deviceName) {
  const user = await db.tx(async (client) => {
    const consumed = await client.query(
      'UPDATE auth_codes SET consumed_at = NOW() WHERE id = $1 AND consumed_at IS NULL RETURNING id',
      [recordId],
    );
    if (!consumed.rowCount) return null;
    const { rows } = await client.query(
      `INSERT INTO users (phone, phone_e164, last_seen_at) VALUES ($1, $1, NOW())
       ON CONFLICT (phone) DO UPDATE SET phone_e164 = EXCLUDED.phone_e164, last_seen_at = NOW(), updated_at = NOW()
       RETURNING ${USER_COLUMNS}`,
      [phone],
    );
    return rows[0];
  });
  if (!user) throw badRequest('code_not_requested', 'Request a code first');
  await syncUserPhoneHash(user.id, user.phone);
  const tokens = await issueSession(user, deviceName);
  logger.info({ userId: user.id }, 'login');
  return { success: true, ...tokens, user: serializeUser(user, { self: true }), is_new_user: !user.name };
}

/** Step 1 — request a one-time code. OTP_DEV_ECHO picks the delivery path. */
authRouter.post(
  '/request-code',
  validate({ body: requestCodeSchema }),
  otpLimiter,
  async (req, res) => {
    const { phone, play_integrity_token, recaptcha_token, ios_receipt, ios_secret, locale, client_platform } = req.body;

    await enforceOtpQuotas(req, phone);

    if (!env.OTP_DEV_ECHO) {
      if ((ios_receipt && !ios_secret) || (!ios_receipt && ios_secret)) {
        throw badRequest('attestation_required', 'iOS verification needs both the receipt and the secret');
      }
    }

    await db.query('UPDATE auth_codes SET consumed_at = NOW() WHERE phone = $1 AND consumed_at IS NULL', [phone]);

    if (env.OTP_DEV_ECHO) {
      const code = generateOtp();
      const expiresAt = new Date(Date.now() + env.OTP_TTL_SECONDS * 1000);
      await db.query('INSERT INTO auth_codes (phone, code_hash, expires_at) VALUES ($1, $2, $3)', [
        phone, hashOtp(phone, code), expiresAt,
      ]);
      await sendOtpSms(phone, code);
      res.json({ success: true, phone, expires_in: env.OTP_TTL_SECONDS, delivery: 'dev', dev_code: code });
      return;
    }

    let sessionInfo;
    try {
      sessionInfo = await sendFirebaseCode({
        phone,
        playIntegrityToken: play_integrity_token,
        recaptchaToken: recaptcha_token,
        iosReceipt: ios_receipt,
        iosSecret: ios_secret,
        locale,
        clientPlatform: client_platform,
      });
    } catch (err) {
      rethrowFirebase(err);
    }

    const expiresIn = Math.max(env.OTP_TTL_SECONDS, 15 * 60);
    const expiresAt = new Date(Date.now() + expiresIn * 1000);
    await db.query('INSERT INTO auth_codes (phone, session_info, expires_at) VALUES ($1, $2, $3)', [
      phone, sessionInfo, expiresAt,
    ]);
    res.json({ success: true, phone, expires_in: expiresIn, delivery: 'firebase' });
  },
);

/** Step 2 — verify the code, create the account on first login and open a session. */
authRouter.post(
  '/verify-code',
  verifyLimiter,
  validate({
    body: z.object({
      phone: phoneSchema,
      code: z.string().trim().regex(/^\d{4,8}$/, 'Code must be numeric'),
      device_name: z.string().trim().max(120).optional(),
    }),
  }),
  async (req, res) => {
    const { phone, code, device_name } = req.body;
    const record = await db.one(
      `SELECT * FROM auth_codes WHERE phone = $1 AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`,
      [phone],
    );
    if (!record) throw badRequest('code_not_requested', 'Request a code first');
    if (new Date(record.expires_at) < new Date()) throw badRequest('code_expired', 'Code expired, request a new one');
    if (record.attempts >= env.OTP_MAX_ATTEMPTS) {
      throw badRequest('too_many_attempts', 'Too many wrong attempts, request a new code');
    }

    if (record.session_info) {
      let verifiedPhone;
      try {
        verifiedPhone = await verifyFirebaseCode({ sessionInfo: record.session_info, code });
      } catch (err) {
        if (err instanceof FirebaseAuthError && err.code === 'invalid_code') {
          await db.query('UPDATE auth_codes SET attempts = attempts + 1 WHERE id = $1', [record.id]);
          const remaining = env.OTP_MAX_ATTEMPTS - record.attempts - 1;
          throw badRequest('invalid_code', 'Incorrect code', { remaining_attempts: Math.max(remaining, 0) });
        }
        rethrowFirebase(err);
      }
      if (verifiedPhone !== phone) {
        await db.query('UPDATE auth_codes SET consumed_at = NOW() WHERE id = $1 AND consumed_at IS NULL', [record.id]);
        throw badRequest('phone_mismatch', 'Verified number does not match the requested number');
      }
      res.json(await openAccount(phone, record.id, device_name));
      return;
    }

    if (!safeEqual(record.code_hash, hashOtp(phone, code))) {
      await db.query('UPDATE auth_codes SET attempts = attempts + 1 WHERE id = $1', [record.id]);
      const remaining = env.OTP_MAX_ATTEMPTS - record.attempts - 1;
      throw badRequest('invalid_code', 'Incorrect code', { remaining_attempts: Math.max(remaining, 0) });
    }

    res.json(await openAccount(phone, record.id, device_name));
  },
);

/** Rotates the refresh token and returns a new access token (Personal sessions & Workspace refresh_tokens). */
authRouter.post(
  '/refresh',
  refreshLimiter,
  validate({ body: z.object({ refresh_token: z.string().min(20) }) }),
  async (req, res) => {
    const hash = sha256(req.body.refresh_token);

    // 1. Check Workspace refresh_tokens first
    const wsToken = await db.one(
      `SELECT rt.*, d.workspace_id, d.status AS device_status, d.last_seen_at AS device_last_seen_at,
              u.profile_type, u.account_status
       FROM refresh_tokens rt
       JOIN devices d ON d.id = rt.device_id
       JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = $1`,
      [hash],
    );

    if (wsToken) {
      if (wsToken.revoked_at || new Date(wsToken.expires_at) < new Date()) {
        throw unauthorized('invalid_refresh_token', 'انتهت صلاحية الجلسة، الرجاء تسجيل الدخول مجدداً');
      }
      if (wsToken.device_status !== 'active') {
        throw unauthorized('device_revoked', 'الجهاز غير نشط أو تم سحبه');
      }
      if (wsToken.account_status === 'suspended' || wsToken.account_status === 'offboarded') {
        throw unauthorized('account_inactive', 'الحساب المؤسسي غير نشط');
      }

      const resolved = await resolveEffectivePolicy(wsToken.workspace_id, wsToken.user_id, 'workspace');
      const idleTimeoutMin = Number(resolved.policies['auth.idle_timeout_minutes'] ?? 0);
      if (idleTimeoutMin > 0 && wsToken.device_last_seen_at) {
        const idleMs = Date.now() - new Date(wsToken.device_last_seen_at).getTime();
        if (idleMs > idleTimeoutMin * 60_000) {
          await db.query('UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1', [wsToken.id]);
          throw unauthorized('idle_timeout_exceeded', 'انتهت الجلسة بسبب عدم النشاط (auth.idle_timeout_minutes)');
        }
      }

      const sessionTtlDays = Number(resolved.policies['auth.session_ttl_days'] ?? 30);
      const nextRefresh = newRefreshToken();
      const nextExpires = new Date(Date.now() + sessionTtlDays * 86_400_000);

      await db.tx(async (client) => {
        const ins = await client.query(
          `INSERT INTO refresh_tokens (device_id, user_id, token_hash, expires_at)
           VALUES ($1, $2, $3, $4) RETURNING id`,
          [wsToken.device_id, wsToken.user_id, sha256(nextRefresh), nextExpires],
        );
        await client.query(
          'UPDATE refresh_tokens SET revoked_at = NOW(), rotated_to = $2 WHERE id = $1',
          [wsToken.id, ins.rows[0].id],
        );
        await client.query(
          'UPDATE devices SET last_seen_at = NOW() WHERE id = $1',
          [wsToken.device_id],
        );
      });

      const roleRows = await db.many('SELECT role FROM user_roles WHERE user_id = $1', [wsToken.user_id]);
      const roles = roleRows.map((r) => r.role);

      res.json({
        success: true,
        access_token: signWorkspaceAccessToken({
          userId: wsToken.user_id,
          workspaceId: wsToken.workspace_id,
          deviceId: wsToken.device_id,
          roles,
          profileType: wsToken.profile_type || 'workspace',
          expiresIn: '15m',
        }),
        refresh_token: nextRefresh,
        token_type: 'Bearer',
        expires_in: '15m',
        session_ttl_days: sessionTtlDays,
      });
      return;
    }

    // 2. Fallback to Personal sessions
    const session = await db.one(
      `SELECT s.*, u.phone FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.refresh_token_hash = $1`,
      [hash],
    );
    if (!session || session.revoked_at || new Date(session.expires_at) < new Date()) {
      throw unauthorized('invalid_refresh_token', 'Session expired, sign in again');
    }
    const refreshToken = newRefreshToken();
    const expires = new Date(Date.now() + env.REFRESH_TOKEN_TTL_DAYS * 86_400_000);
    await db.query(
      'UPDATE sessions SET refresh_token_hash = $1, expires_at = $2, last_used_at = NOW() WHERE id = $3',
      [sha256(refreshToken), expires, session.id],
    );
    res.json({
      success: true,
      access_token: signAccessToken({ id: session.user_id, phone: session.phone }, session.id),
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: env.ACCESS_TOKEN_TTL,
    });
  },
);

authRouter.post('/logout', requireAuth, async (req, res) => {
  if (req.auth.sessionId) {
    await db.query('UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL', [req.auth.sessionId]);
  }
  if (req.auth.deviceId) {
    await db.query(
      'UPDATE refresh_tokens SET revoked_at = NOW() WHERE device_id = $1 AND revoked_at IS NULL',
      [req.auth.deviceId],
    );
  }
  res.json({ success: true });
});

authRouter.get('/me', requireAuth, async (req, res) => {
  const user = await db.one(
    `SELECT ${USER_COLUMNS}, workspace_id, employee_no, email, work_phone, title,
            department_id, account_status, presence_status, presence_note, presence_until, profile_type
     FROM users WHERE id = $1`,
    [req.auth.userId],
  );
  if (!user) throw unauthorized('user_missing', 'Account no longer exists');
  const roleRows = await db.many('SELECT role FROM user_roles WHERE user_id = $1', [user.id]);
  const base = serializeUser(user, { self: true });
  res.json({
    success: true,
    user: {
      ...base,
      workspace_id: user.workspace_id || null,
      employee_no: user.employee_no || null,
      email: user.email || null,
      work_phone: user.work_phone || null,
      title: user.title || '',
      department_id: user.department_id || null,
      account_status: user.account_status || 'active',
      presence_status: user.presence_status || 'available',
      presence_note: user.presence_note || '',
      presence_until: user.presence_until || null,
      profile_type: user.profile_type || 'personal',
      roles: roleRows.map((r) => r.role),
    },
  });
});

authRouter.get('/sessions', requireAuth, async (req, res) => {
  const rows = await db.many(
    `SELECT id, device_name, created_at, last_used_at, (id = $2) AS is_current
     FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW() ORDER BY last_used_at DESC`,
    [req.auth.userId, req.auth.sessionId],
  );
  res.json({ success: true, sessions: rows });
});
