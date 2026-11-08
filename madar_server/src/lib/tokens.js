import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

export function signAccessToken(user, sessionId) {
  return jwt.sign({ sub: String(user.id), sid: sessionId, phone: user.phone }, env.JWT_SECRET, {
    expiresIn: env.ACCESS_TOKEN_TTL,
    issuer: 'madar',
  });
}

export function signWorkspaceAccessToken({
  userId,
  workspaceId,
  deviceId,
  roles = [],
  profileType = 'workspace',
  expiresIn = '15m',
}) {
  return jwt.sign(
    {
      sub: String(userId),
      wid: String(workspaceId),
      did: String(deviceId),
      roles,
      profile_type: profileType,
    },
    env.JWT_SECRET,
    {
      expiresIn,
      issuer: 'madar',
    },
  );
}

export function signMfaPreAuthToken({ userId, workspaceId, deviceId, enrollmentTokenId = null }) {
  return jwt.sign(
    {
      sub: String(userId),
      wid: String(workspaceId),
      did: deviceId ? String(deviceId) : null,
      eid: enrollmentTokenId ? String(enrollmentTokenId) : null,
      mfa_pending: true,
    },
    env.JWT_SECRET,
    {
      expiresIn: '10m',
      issuer: 'madar',
    },
  );
}

export function verifyAccessToken(token) {
  return jwt.verify(token, env.JWT_SECRET, { issuer: 'madar' });
}

export function newRefreshToken() {
  return crypto.randomBytes(48).toString('base64url');
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function hmacHex(value) {
  return crypto.createHmac('sha256', env.JWT_SECRET).update(value).digest('hex');
}

export function generateOtp() {
  if (env.OTP_FIXED_DEV_CODE && !env.IS_PROD) return env.OTP_FIXED_DEV_CODE;
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

export function hashOtp(phone, code) {
  return hmacHex(`${phone}:${code}`);
}

export function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
