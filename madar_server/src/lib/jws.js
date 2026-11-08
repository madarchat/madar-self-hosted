import crypto from 'node:crypto';
import { db } from '../db/pool.js';
import { encryptField, decryptField } from './fieldCrypto.js';

function base64urlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64url');
}

function base64urlDecodeToBuffer(str) {
  return Buffer.from(String(str), 'base64url');
}

function exportRawEd25519PublicKeyB64(publicKeyObj) {
  const spki = publicKeyObj.export({ type: 'spki', format: 'der' });
  return spki.subarray(-32).toString('base64url');
}

function importEd25519PublicKey(pubKeyB64OrPem) {
  const trimmed = String(pubKeyB64OrPem || '').trim();
  if (trimmed.startsWith('-----BEGIN')) {
    return crypto.createPublicKey(trimmed);
  }
  // Raw 32-byte Ed25519 public key in base64 or base64url wrapped in RFC 8410 SPKI DER prefix
  const raw = trimmed.includes('-') || trimmed.includes('_')
    ? Buffer.from(trimmed, 'base64url')
    : Buffer.from(trimmed, 'base64');
  if (raw.length === 32) {
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    return crypto.createPublicKey({
      key: Buffer.concat([spkiPrefix, raw]),
      format: 'der',
      type: 'spki',
    });
  }
  return crypto.createPublicKey({ key: raw, format: 'der', type: 'spki' });
}

/**
 * Signs a JSON payload using Ed25519 (RFC 8037 EdDSA JWS compact serialization).
 */
export function signEd25519Jws(payload, privateKeyPem, kid) {
  const header = { alg: 'EdDSA', typ: 'JWT', ...(kid ? { kid } : {}) };
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, Buffer.from(signingInput, 'utf8'), privateKey);
  return `${signingInput}.${base64urlEncode(signature)}`;
}

/**
 * Verifies an EdDSA JWS compact token against an Ed25519 public key.
 */
export function verifyEd25519Jws(jwsCompact, publicKeyB64OrPem) {
  const parts = String(jwsCompact || '').split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWS compact format');
  }
  const [encodedHeader, encodedPayload, encodedSig] = parts;
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const pubKey = importEd25519PublicKey(publicKeyB64OrPem);
  const sigBuf = base64urlDecodeToBuffer(encodedSig);
  const ok = crypto.verify(null, Buffer.from(signingInput, 'utf8'), pubKey, sigBuf);
  if (!ok) {
    throw new Error('JWS signature verification failed');
  }
  const header = JSON.parse(base64urlDecodeToBuffer(encodedHeader).toString('utf8'));
  const payload = JSON.parse(base64urlDecodeToBuffer(encodedPayload).toString('utf8'));
  return { header, payload };
}

/**
 * Verifies a detached Ed25519 signature from a client device.
 */
export function verifyDeviceSignature(publicKeyB64OrPem, message, signatureB64) {
  try {
    const pubKey = importEd25519PublicKey(publicKeyB64OrPem);
    const msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
    const sigStr = String(signatureB64 || '').trim();
    const sigBuf = sigStr.includes('-') || sigStr.includes('_')
      ? Buffer.from(sigStr, 'base64url')
      : Buffer.from(sigStr, 'base64');
    return crypto.verify(null, msgBuf, pubKey, sigBuf);
  } catch {
    return false;
  }
}

/**
 * Ensures an active Ed25519 signing key exists for the given workspace.
 * Returns { kid, publicKeyEd25519, privateKeyPem }.
 */
export async function ensureWorkspaceSigningKey(workspaceId, client = db) {
  const q = client.one
    ? (sql, params) => client.one(sql, params)
    : async (sql, params) => (await client.query(sql, params)).rows[0] || null;

  const existing = await q(
    `SELECT kid, public_key_ed25519, private_ciphertext, private_iv, key_id
     FROM policy_signing_keys
     WHERE workspace_id = $1 AND active = TRUE
     ORDER BY created_at DESC LIMIT 1`,
    [workspaceId],
  );

  if (existing) {
    const privateKeyPem = decryptField(existing.private_ciphertext, existing.private_iv, existing.key_id);
    return {
      kid: existing.kid,
      publicKeyEd25519: existing.public_key_ed25519,
      privateKeyPem,
    };
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyEd25519 = exportRawEd25519PublicKeyB64(publicKey);
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const kid = `psk-${crypto.randomBytes(6).toString('hex')}`;
  const enc = encryptField(privateKeyPem);

  const exec = client.query.bind(client);
  await exec(
    `INSERT INTO policy_signing_keys (kid, workspace_id, public_key_ed25519, private_ciphertext, private_iv, key_id, active)
     VALUES ($1, $2, $3, $4, $5, $6, TRUE)`,
    [kid, workspaceId, publicKeyEd25519, enc.ciphertext, enc.iv, enc.keyId],
  );

  return { kid, publicKeyEd25519, privateKeyPem };
}

/**
 * Rotates the active Ed25519 signing key for a workspace while preserving old keys for historical verification.
 */
export async function rotateWorkspaceSigningKey(workspaceId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyEd25519 = exportRawEd25519PublicKeyB64(publicKey);
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const kid = `psk-${crypto.randomBytes(6).toString('hex')}`;
  const enc = encryptField(privateKeyPem);

  await db.tx(async (client) => {
    await client.query(
      'UPDATE policy_signing_keys SET active = FALSE WHERE workspace_id = $1 AND active = TRUE',
      [workspaceId],
    );
    await client.query(
      `INSERT INTO policy_signing_keys (kid, workspace_id, public_key_ed25519, private_ciphertext, private_iv, key_id, active)
       VALUES ($1, $2, $3, $4, $5, $6, TRUE)`,
      [kid, workspaceId, publicKeyEd25519, enc.ciphertext, enc.iv, enc.keyId],
    );
    await client.query(
      'UPDATE workspace SET policy_signing_pub = $2 WHERE id = $1',
      [workspaceId, publicKeyEd25519],
    );
  });

  return { kid, publicKeyEd25519 };
}

