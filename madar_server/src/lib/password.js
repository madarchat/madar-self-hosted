import crypto from 'node:crypto';
import { env } from '../config/env.js';

const ARGON2_MEMORY = env.IS_PROD ? 65536 : 19456; // KiB (64 MiB prod, 19 MiB dev/test per OWASP)
const ARGON2_PASSES = env.IS_PROD ? 3 : 2;
const ARGON2_PARALLELISM = 1;
const ARGON2_TAG_LEN = 32;

const SCRYPT_N = env.IS_PROD ? 32768 : 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 64;

/**
 * Hashes a plaintext password using Argon2id (NFR-09) with a 16-byte cryptographic salt.
 * Falls back to scrypt only if running on a runtime without native crypto.argon2Sync.
 */
export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  if (typeof crypto.argon2Sync === 'function') {
    const derived = crypto.argon2Sync('argon2id', {
      message: String(password),
      nonce: salt,
      parallelism: ARGON2_PARALLELISM,
      tagLength: ARGON2_TAG_LEN,
      memory: ARGON2_MEMORY,
      passes: ARGON2_PASSES,
    });
    return `$argon2id$v=19$m=${ARGON2_MEMORY},t=${ARGON2_PASSES},p=${ARGON2_PARALLELISM}$${salt.toString('base64url')}$${Buffer.from(derived).toString('base64url')}`;
  }

  const derived = crypto.scryptSync(String(password), salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

/**
 * Verifies a plaintext password against a stored Argon2id ($argon2id$...) or legacy scrypt hash string.
 */
export function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string') return false;

  if (storedHash.startsWith('$argon2id$')) {
    if (typeof crypto.argon2Sync !== 'function') return false;
    // Format: $argon2id$v=19$m=19456,t=2,p=1$<salt_b64url>$<hash_b64url>
    const parts = storedHash.split('$');
    if (parts.length !== 6) return false;
    const paramsStr = parts[3];
    const salt = Buffer.from(parts[4], 'base64url');
    const expected = Buffer.from(parts[5], 'base64url');
    const paramMap = Object.fromEntries(
      paramsStr.split(',').map((kv) => {
        const [k, v] = kv.split('=');
        return [k.trim(), parseInt(v, 10)];
      }),
    );
    const memory = paramMap.m || ARGON2_MEMORY;
    const passes = paramMap.t || ARGON2_PASSES;
    const parallelism = paramMap.p || ARGON2_PARALLELISM;
    try {
      const derived = Buffer.from(
        crypto.argon2Sync('argon2id', {
          message: String(password),
          nonce: salt,
          parallelism,
          tagLength: expected.length,
          memory,
          passes,
        }),
      );
      return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
    } catch {
      return false;
    }
  }

  const parts = storedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = parseInt(parts[1], 10);
  const r = parseInt(parts[2], 10);
  const p = parseInt(parts[3], 10);
  const salt = Buffer.from(parts[4], 'base64url');
  const expected = Buffer.from(parts[5], 'base64url');
  try {
    const derived = crypto.scryptSync(String(password), salt, expected.length, {
      N,
      r,
      p,
      maxmem: 64 * 1024 * 1024,
    });
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

export function validatePasswordComplexity(password, minLength = 10) {
  const str = String(password || '');
  if (str.length < minLength) {
    return { valid: false, reason: `كلمة المرور يجب ألا تقل عن ${minLength} أحرف` };
  }
  return { valid: true };
}
