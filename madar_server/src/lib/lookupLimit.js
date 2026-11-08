import crypto from 'node:crypto';
import { env } from '../config/env.js';
import { redis } from './redis.js';

const memory = new Map();

export function resetLookupLimits() {
  memory.clear();
}

/** Last IPv4 octet dropped, IPv6 trimmed. Used only inside hashes and operator alerts. */
export function maskIp(ip) {
  const value = String(ip || '').trim();
  if (!value) return 'unknown';
  if (value.includes('.')) {
    const parts = value.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
  }
  if (value.includes(':')) {
    const parts = value.split(':').filter(Boolean);
    return `${parts.slice(0, 3).join(':')}::`;
  }
  return 'unknown';
}

export function hashIp(ip) {
  const material = `${env.PHONE_HASH_SALT || 'madar-lookup'}:${String(ip || '')}`;
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, 32);
}

function limitsOf(overrides = {}) {
  return {
    windowMs: overrides.windowMs ?? env.LOOKUP_WINDOW_MS,
    userLimit: overrides.userLimit ?? env.LOOKUP_USER_LIMIT,
    ipLimit: overrides.ipLimit ?? env.LOOKUP_IP_LIMIT,
    deviceLimit: overrides.deviceLimit ?? env.LOOKUP_DEVICE_LIMIT,
    minIntervalMs: overrides.minIntervalMs ?? env.LOOKUP_MIN_INTERVAL_MS,
  };
}

function memoryHit(key, windowMs) {
  const now = Date.now();
  const slot = memory.get(key);
  if (!slot || slot.resetAt <= now) {
    memory.set(key, { count: 1, resetAt: now + windowMs });
    return { count: 1, retryAfter: Math.max(1, Math.ceil(windowMs / 1000)) };
  }
  slot.count += 1;
  return { count: slot.count, retryAfter: Math.max(1, Math.ceil((slot.resetAt - now) / 1000)) };
}

async function hit(key, windowMs) {
  if (!redis) return memoryHit(key, windowMs);
  const count = await redis.incr(key);
  if (count === 1) await redis.pexpire(key, windowMs);
  const ttl = await redis.pttl(key);
  const wait = ttl > 0 ? ttl : windowMs;
  return { count, retryAfter: Math.max(1, Math.ceil(wait / 1000)) };
}

async function pace(key, minIntervalMs) {
  if (minIntervalMs <= 0) return { allowed: true, retryAfter: 0 };
  if (!redis) {
    const now = Date.now();
    const slot = memory.get(key);
    if (slot && slot.resetAt > now) {
      return { allowed: false, retryAfter: Math.max(1, Math.ceil((slot.resetAt - now) / 1000)) };
    }
    memory.set(key, { count: 1, resetAt: now + minIntervalMs });
    return { allowed: true, retryAfter: 0 };
  }
  const ok = await redis.set(key, '1', 'PX', minIntervalMs, 'NX');
  if (ok) return { allowed: true, retryAfter: 0 };
  const ttl = await redis.pttl(key);
  return { allowed: false, retryAfter: Math.max(1, Math.ceil((ttl > 0 ? ttl : minIntervalMs) / 1000)) };
}

/**
 * Layered lookup budget. A pace rejection does not consume the 10-minute counters.
 * @returns {Promise<{ limited: boolean, retryAfter: number, scope: string | null }>}
 */
export async function consumeLookup({ userId, ip, deviceId, limits } = {}) {
  const cfg = limitsOf(limits);
  const paced = await pace(`lookup:pace:${userId}`, cfg.minIntervalMs);
  if (!paced.allowed) return { limited: true, retryAfter: paced.retryAfter, scope: 'pace' };

  const checks = [
    [`lookup:user:${userId}`, cfg.userLimit],
    [`lookup:ip:${hashIp(ip)}`, cfg.ipLimit],
  ];
  if (deviceId) checks.push([`lookup:device:${deviceId}`, cfg.deviceLimit]);

  for (const [key, limit] of checks) {
    const row = await hit(key, cfg.windowMs);
    if (row.count > limit) return { limited: true, retryAfter: row.retryAfter, scope: key.split(':')[1] };
  }
  return { limited: false, retryAfter: 0, scope: null };
}

export function failureDelayMs(failCount) {
  const after = env.LOOKUP_FAIL_DELAY_AFTER;
  if (!Number.isFinite(failCount) || failCount < after) return 0;
  const steps = failCount - after + 1;
  return Math.min(env.LOOKUP_FAIL_DELAY_MS * steps, 5_000);
}
