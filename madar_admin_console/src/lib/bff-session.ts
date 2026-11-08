import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';

const COOKIE_NAME = 'madar_admin_sid';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// Derive a deterministic 32-byte AES-256-GCM key from server-side secrets
function getEncryptionKey(): Buffer {
  const rawSecret =
    process.env.SESSION_SECRET ||
    process.env.ADMIN_PLANE_SECRET ||
    process.env.CONTROL_PLANE_KEY ||
    'madar-isolated-bff-default-key-change-in-prod-2026';
  return crypto.createHash('sha256').update(rawSecret, 'utf8').digest();
}

export function getUpstreamBaseUrl(): string {
  return (
    process.env.MADAR_SERVER_URL ||
    process.env.MADAR_CORE_API_URL ||
    'http://127.0.0.1:5025'
  ).replace(/\/+$/, '');
}

export function getControlPlaneSecret(): string {
  return process.env.ADMIN_PLANE_SECRET || process.env.CONTROL_PLANE_KEY || '';
}

export interface BffSessionPayload {
  sid: string;
  jwt: string;
  csrfToken: string;
  user: Record<string, unknown> | null;
  expiresAt: number;
}

export function createSealedSession(
  jwt: string,
  user: Record<string, unknown> | null = null,
): { sealedCookie: string; session: BffSessionPayload } {
  const session: BffSessionPayload = {
    sid: crypto.randomBytes(16).toString('base64url'),
    jwt,
    csrfToken: crypto.randomBytes(24).toString('base64url'),
    user,
    expiresAt: Date.now() + SESSION_TTL_MS,
  };

  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(session), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const sealedCookie = `${iv.toString('base64url')}.${tag.toString('base64url')}.${encrypted.toString('base64url')}`;
  return { sealedCookie, session };
}

export function readSessionFromRequest(req: NextRequest): BffSessionPayload | null {
  const cookieVal = req.cookies.get(COOKIE_NAME)?.value;
  if (!cookieVal) return null;

  const parts = cookieVal.split('.');
  if (parts.length !== 3) return null;

  try {
    const [ivB64, tagB64, encB64] = parts;
    const key = getEncryptionKey();
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(ivB64, 'base64url'),
    );
    decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encB64, 'base64url')),
      decipher.final(),
    ]).toString('utf8');

    const payload = JSON.parse(decrypted) as BffSessionPayload;
    if (!payload || !payload.jwt || Date.now() > payload.expiresAt) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

export function attachSessionCookie(res: NextResponse, sealedCookie: string): void {
  res.cookies.set({
    name: COOKIE_NAME,
    value: sealedCookie,
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
    secure: process.env.COOKIE_SECURE === 'true',
  });
}

export function clearSessionCookie(res: NextResponse): void {
  res.cookies.set({
    name: COOKIE_NAME,
    value: '',
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    maxAge: 0,
  });
}

export function verifyCsrfToken(provided: string | null, expected: string): boolean {
  if (!provided || !expected) return false;
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export async function forwardUpstream(
  method: string,
  upstreamPath: string,
  bodyObj?: unknown,
  jwt?: string | null,
): Promise<{ status: number; data: any; contentType: string; rawText?: string }> {
  const baseUrl = getUpstreamBaseUrl();
  const cpSecret = getControlPlaneSecret();

  const headers: Record<string, string> = {
    Accept: 'application/json, text/csv, */*',
  };
  if (cpSecret) {
    headers['X-Madar-Control-Plane-Key'] = cpSecret;
  }
  if (jwt) {
    headers.Authorization = `Bearer ${jwt}`;
  }

  const init: RequestInit = {
    method,
    headers,
    cache: 'no-store',
  };

  if (bodyObj !== undefined && method !== 'GET' && method !== 'HEAD') {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(bodyObj);
  }

  const res = await fetch(`${baseUrl}${upstreamPath}`, init);
  const contentType = res.headers.get('content-type') || 'application/json';
  if (contentType.includes('text/csv')) {
    const rawText = await res.text();
    return { status: res.status, data: rawText, contentType, rawText };
  }
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data, contentType };
}
