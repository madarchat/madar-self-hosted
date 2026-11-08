import crypto from 'node:crypto';
import { DEFAULT_PHONE_HASH_SALT, env } from '../config/env.js';

const SALT = env.PHONE_HASH_SALT || DEFAULT_PHONE_HASH_SALT;

/** Normalizes E.164 and returns the first 32 hex chars of SHA-256(salt || phone). */
export function phoneDiscoveryHash(phone) {
  const normalized = String(phone || '').replace(/\s/g, '');
  return crypto.createHash('sha256').update(`${SALT}:${normalized}`, 'utf8').digest('hex').slice(0, 32);
}
