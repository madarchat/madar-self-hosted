import crypto from 'node:crypto';
import { env } from '../config/env.js';
import { forbidden, notFound } from '../lib/errors.js';

function timingSafeCompare(a, b) {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length !== bufB.length || bufA.length === 0) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Control-Plane Isolation Guard.
 * Protects administrative endpoints (/api/v1/admin/* and policy mutation endpoints)
 * so that:
 * 1. Public edge/data-plane nodes can disable the Admin API completely (ADMIN_API_ENABLED=false), returning 404.
 * 2. When ADMIN_ALLOWED_IPS is configured, only requests from trusted management IPs are accepted.
 * 3. When ADMIN_PLANE_SECRET is configured, only the isolated Admin Console BFF or madarctl CLI
 *    presenting X-Madar-Control-Plane-Key is permitted to reach the Control Plane API.
 */
export function controlPlaneGuard(req, _res, next) {
  const enabledRaw = process.env.ADMIN_API_ENABLED ?? String(env.ADMIN_API_ENABLED ?? 'true');
  const isEnabled = ['1', 'true', 'yes'].includes(String(enabledRaw).toLowerCase());
  if (!isEnabled) {
    return next(
      notFound(
        'admin_plane_disabled',
        'واجهة مستوى التحكم الإداري معطلة على عقدة مستوى البيانات هذه (ADMIN_API_ENABLED=false)',
      ),
    );
  }

  const allowedIpsRaw = process.env.ADMIN_ALLOWED_IPS ?? env.ADMIN_ALLOWED_IPS ?? '';
  const allowedIps = String(allowedIpsRaw)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (allowedIps.length > 0) {
    const clientIp = String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
    if (!allowedIps.includes(clientIp)) {
      return next(
        forbidden(
          'admin_ip_restricted',
          `الوصول إلى مستوى التحكم الإداري مقيد بالشبكة الإدارية المسموحة فقط (IP: ${clientIp})`,
        ),
      );
    }
  }

  const planeSecret =
    process.env.ADMIN_PLANE_SECRET ??
    process.env.CONTROL_PLANE_KEY ??
    env.ADMIN_PLANE_SECRET ??
    '';
  if (planeSecret) {
    const providedKey = req.get('x-madar-control-plane-key') || '';
    if (!timingSafeCompare(providedKey, planeSecret)) {
      return next(
        forbidden(
          'untrusted_control_plane',
          'مفتاح مستوى التحكم الإداري (X-Madar-Control-Plane-Key) مفقود أو غير صالح',
        ),
      );
    }
  }

  return next();
}
