import crypto from 'node:crypto';
import { sha256 } from './tokens.js';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function base32Decode(str) {
  const clean = String(str || '').toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function generateTotpSecret(byteLength = 20) {
  return base32Encode(crypto.randomBytes(byteLength));
}

export function totpUri({ secret, accountName, issuer = 'Madar Workspace' }) {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

export function computeTotpCode(secretBase32, step = Math.floor(Date.now() / 30_000)) {
  const key = base32Decode(secretBase32);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hmac = crypto.createHmac('sha1', key).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}

export const generateTotpCode = computeTotpCode;

/**
 * Verifies a 6-digit RFC 6238 TOTP code with ±1 step window and replay protection.
 */
export function verifyTotpCode(secretBase32, code, lastUsedStep = null, nowMs = Date.now()) {
  const cleanCode = String(code || '').trim();
  if (!/^\d{6}$/.test(cleanCode)) return { valid: false, step: null, reason: 'invalid_format' };
  const currentStep = Math.floor(nowMs / 30_000);
  let replayDetected = false;
  for (const offset of [0, -1, 1]) {
    const candidateStep = currentStep + offset;
    const expected = computeTotpCode(secretBase32, candidateStep);
    if (expected === cleanCode) {
      if (lastUsedStep !== null && lastUsedStep !== undefined && candidateStep <= Number(lastUsedStep)) {
        replayDetected = true;
        continue;
      }
      return { valid: true, step: candidateStep };
    }
  }
  return {
    valid: false,
    step: null,
    reason: replayDetected ? 'replay_detected' : 'invalid_code',
  };
}

/**
 * Generates 10 single-use recovery codes (e.g. XXXX-XXXX) and their SHA-256 hashes.
 */
export function generateRecoveryCodes(count = 10) {
  const codes = [];
  const hashes = [];
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  for (let i = 0; i < count; i++) {
    let raw = '';
    for (let j = 0; j < 8; j++) {
      raw += chars[crypto.randomInt(0, chars.length)];
    }
    const formatted = `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
    codes.push(formatted);
    hashes.push(sha256(formatted.toUpperCase()));
  }
  return { codes, hashes };
}
