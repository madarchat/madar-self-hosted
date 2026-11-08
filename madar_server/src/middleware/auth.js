import { verifyAccessToken } from '../lib/tokens.js';
import { unauthorized } from '../lib/errors.js';
import { db } from '../db/pool.js';
import { resolveEffectivePolicy } from '../services/policyEngine.js';

export async function requireAuth(req, _res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return next(unauthorized('missing_token'));
  try {
    const payload = verifyAccessToken(token);
    if (payload.mfa_pending) {
      return next(unauthorized('mfa_required', 'يجب إتمام التحقق بخطوتين (TOTP) أولاً'));
    }
    if (payload.did) {
      const device = await db.one(
        `SELECT d.id, d.status, d.workspace_id, d.last_seen_at, u.account_status
         FROM devices d
         JOIN users u ON u.id = d.user_id
         WHERE d.id = $1 AND d.user_id = $2`,
        [payload.did, Number(payload.sub)],
      );
      if (!device || device.status !== 'active') {
        return next(unauthorized('device_revoked', 'الجهاز غير نشط أو تم إلغاء تفويضه'));
      }
      if (device.account_status === 'suspended' || device.account_status === 'offboarded') {
        return next(unauthorized('account_inactive', 'تم إيقاف حساب مساحة العمل'));
      }

      const wsId = payload.wid || device.workspace_id;
      const resolved = await resolveEffectivePolicy(wsId, Number(payload.sub), 'workspace');
      const idleTimeoutMin = Number(resolved.policies['auth.idle_timeout_minutes'] ?? 0);
      if (idleTimeoutMin > 0 && device.last_seen_at) {
        const idleMs = Date.now() - new Date(device.last_seen_at).getTime();
        if (idleMs > idleTimeoutMin * 60_000) {
          return next(unauthorized('idle_timeout_exceeded', 'انتهت صلاحية الجلسة بسبب عدم النشاط (auth.idle_timeout_minutes)'));
        }
      }

      await db.query('UPDATE devices SET last_seen_at = NOW() WHERE id = $1', [device.id]);

      req.auth = {
        userId: Number(payload.sub),
        deviceId: payload.did,
        workspaceId: wsId,
        roles: Array.isArray(payload.roles) ? payload.roles : [],
        profileType: payload.profile_type || 'workspace',
      };
      req.effectivePolicy = resolved;
      return next();
    }
    if (payload.sid) {
      const session = await db.one('SELECT 1 FROM sessions WHERE id = $1 AND revoked_at IS NULL', [payload.sid]);
      if (!session) return next(unauthorized('session_revoked'));
    }
    req.auth = {
      userId: Number(payload.sub),
      sessionId: payload.sid,
      profileType: payload.profile_type || 'personal',
    };
    return next();
  } catch (err) {
    return next(unauthorized(err.name === 'TokenExpiredError' ? 'token_expired' : 'invalid_token'));
  }
}

/** Resolves the user id from a raw token (used by the WebSocket handshake). */
export async function userIdFromToken(token) {
  if (!token) return null;
  try {
    const payload = verifyAccessToken(token);
    if (payload.mfa_pending) return null;
    if (payload.did) {
      const device = await db.one(
        `SELECT d.id
         FROM devices d
         JOIN users u ON u.id = d.user_id
         WHERE d.id = $1 AND d.user_id = $2 AND d.status = 'active'
           AND u.account_status NOT IN ('suspended', 'offboarded')`,
        [payload.did, Number(payload.sub)],
      );
      if (!device) return null;
      return Number(payload.sub);
    }
    if (payload.sid) {
      const session = await db.one('SELECT 1 FROM sessions WHERE id = $1 AND revoked_at IS NULL', [payload.sid]);
      if (!session) return null;
    }
    return Number(payload.sub);
  } catch {
    return null;
  }
}
