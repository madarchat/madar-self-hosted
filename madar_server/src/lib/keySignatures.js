import crypto from 'node:crypto';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function decodeKey(value) {
  if (typeof value !== 'string' || value.length < 16) return null;
  try {
    const raw = Buffer.from(value, 'base64');
    return raw.length ? raw : null;
  } catch {
    return null;
  }
}

/** Verify a raw 32-byte Ed25519 public key over an exact message. */
export function verifyEd25519(publicKey, message, signature) {
  if (!Buffer.isBuffer(publicKey) || !Buffer.isBuffer(message) || !Buffer.isBuffer(signature)) return false;
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, message, key, signature);
  } catch {
    return false;
  }
}
