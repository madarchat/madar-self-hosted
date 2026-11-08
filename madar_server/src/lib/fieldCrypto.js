import crypto from 'node:crypto';
import { env } from '../config/env.js';

const AUTH_TAG_BYTES = 16;
const IV_BYTES = 12;

function resolveKey(keyId = env.MASTER_KEY_ID) {
  const raw = process.env.MASTER_ENCRYPTION_KEY || env.MASTER_ENCRYPTION_KEY || 'madar-dev-master-key';
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    return { key: Buffer.from(raw, 'hex'), keyId };
  }
  return {
    key: crypto.createHash('sha256').update(`${keyId}:${raw}`).digest(),
    keyId,
  };
}

/**
 * Encrypts a Buffer using AES-256-GCM.
 * Returns { ciphertext (with 16-byte GCM authTag appended), iv (12 bytes), keyId }.
 */
export function encryptBuffer(plainBuffer, requestedKeyId = env.MASTER_KEY_ID) {
  const buf = Buffer.isBuffer(plainBuffer) ? plainBuffer : Buffer.from(String(plainBuffer ?? ''), 'utf8');
  const { key, keyId } = resolveKey(requestedKeyId);
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: Buffer.concat([enc, tag]),
    iv,
    keyId,
  };
}

/**
 * Decrypts a Buffer encrypted by encryptBuffer.
 */
export function decryptBuffer(ciphertext, iv, keyId = env.MASTER_KEY_ID) {
  if (!ciphertext || !iv) return Buffer.alloc(0);
  const cipherBuf = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext);
  const ivBuf = Buffer.isBuffer(iv) ? iv : Buffer.from(iv);
  if (cipherBuf.length < AUTH_TAG_BYTES) {
    throw new Error('Ciphertext too short to contain GCM auth tag');
  }
  const { key } = resolveKey(keyId);
  const data = cipherBuf.subarray(0, cipherBuf.length - AUTH_TAG_BYTES);
  const tag = cipherBuf.subarray(cipherBuf.length - AUTH_TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivBuf);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

export function encryptField(plaintext, requestedKeyId = env.MASTER_KEY_ID) {
  return encryptBuffer(Buffer.from(String(plaintext ?? ''), 'utf8'), requestedKeyId);
}

export function decryptField(ciphertext, iv, keyId = env.MASTER_KEY_ID) {
  if (!ciphertext || !iv) return '';
  return decryptBuffer(ciphertext, iv, keyId).toString('utf8');
}
