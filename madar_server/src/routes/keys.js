import { Router } from 'express';
import { db } from '../db/pool.js';
import { validate, z, idParam } from '../lib/validate.js';
import { badRequest, conflict, forbidden, notFound } from '../lib/errors.js';
import { requireAuth } from '../middleware/auth.js';
import { decodeKey, verifyEd25519 } from '../lib/keySignatures.js';

export const keysRouter = Router();
keysRouter.use(requireAuth);

const prekeySchema = z.object({
  key_id: z.coerce.number().int().positive(),
  public_key: z.string().min(16).max(512),
});

function prekeyList(value) {
  let current = value;
  if (typeof current === 'string') {
    try {
      current = JSON.parse(current);
    } catch {
      current = [];
    }
  }
  return Array.isArray(current) ? current : [];
}

/** A bundle is readable by the account itself and by people who already share a thread. */
async function mayReadBundle(me, target) {
  if (Number(me) === Number(target)) return true;
  const row = await db.one(
    `SELECT 1 FROM thread_members mine
     JOIN thread_members theirs ON theirs.thread_id = mine.thread_id AND theirs.user_id = $2
     WHERE mine.user_id = $1
     LIMIT 1`,
    [me, target],
  );
  return !!row;
}

keysRouter.post(
  '/bundle',
  validate({
    body: z.object({
      identity_key: z.string().min(16).max(512),
      signing_key: z.string().min(16).max(512),
      signed_prekey_id: z.coerce.number().int().positive().default(1),
      signed_prekey: z.string().min(16).max(512),
      signed_prekey_sig: z.string().min(16).max(1024),
      one_time_prekeys: z.array(prekeySchema).max(100).default([]),
      rotation_sig: z.string().min(16).max(256).optional(),
      confirm_replace: z.boolean().optional(),
    }),
  }),
  async (req, res) => {
    const me = req.auth.userId;
    const {
      identity_key, signing_key, signed_prekey_id, signed_prekey, signed_prekey_sig,
      one_time_prekeys, rotation_sig, confirm_replace,
    } = req.body;
    const identityRaw = decodeKey(identity_key);
    const signingRaw = decodeKey(signing_key);
    const prekeyRaw = decodeKey(signed_prekey);
    const signatureRaw = decodeKey(signed_prekey_sig);
    if (!identityRaw || !signingRaw || !prekeyRaw || !signatureRaw || !verifyEd25519(signingRaw, prekeyRaw, signatureRaw)) {
      throw badRequest('invalid_key_signature', 'The signed prekey signature does not match the signing key');
    }

    const existing = await db.one(
      'SELECT identity_key, signing_key, one_time_prekeys, identity_generation FROM user_key_bundles WHERE user_id = $1',
      [me],
    );
    let generation = existing?.identity_generation || 1;
    let previous = null;
    let storedPrekeys = one_time_prekeys;
    if (existing && existing.identity_key !== identity_key) {
      const previousSigning = decodeKey(existing.signing_key);
      const rotation = decodeKey(rotation_sig);
      const rotated = previousSigning && rotation && verifyEd25519(previousSigning, identityRaw, rotation);
      if (!rotated && confirm_replace !== true) {
        throw conflict('identity_pinned', 'This account already has encryption keys');
      }
      generation += 1;
      previous = existing.identity_key;
    } else if (existing && existing.signing_key && existing.signing_key !== signing_key) {
      throw badRequest('signing_key_mismatch', 'The signing key does not match the published identity');
    } else if (existing) {
      const current = prekeyList(existing.one_time_prekeys);
      const seen = new Set(current.map((item) => Number(item.key_id)));
      storedPrekeys = current.concat(one_time_prekeys.filter((item) => !seen.has(Number(item.key_id))));
    }

    await db.query(
      `INSERT INTO user_key_bundles (
         user_id, identity_key, signing_key, signed_prekey_id, signed_prekey, signed_prekey_sig,
         one_time_prekeys, identity_generation, previous_identity_key, updated_at
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         identity_key = EXCLUDED.identity_key,
         signing_key = EXCLUDED.signing_key,
         signed_prekey_id = EXCLUDED.signed_prekey_id,
         signed_prekey = EXCLUDED.signed_prekey,
         signed_prekey_sig = EXCLUDED.signed_prekey_sig,
         one_time_prekeys = EXCLUDED.one_time_prekeys,
         identity_generation = EXCLUDED.identity_generation,
         previous_identity_key = COALESCE(EXCLUDED.previous_identity_key, user_key_bundles.previous_identity_key),
         updated_at = NOW()`,
      [me, identity_key, signing_key, signed_prekey_id, signed_prekey, signed_prekey_sig, JSON.stringify(storedPrekeys), generation, previous],
    );
    res.json({ success: true, identity_generation: generation, one_time_remaining: storedPrekeys.length });
  },
);

keysRouter.get('/bundle/:userId', validate({ params: idParam('userId') }), async (req, res) => {
  const me = req.auth.userId;
  const targetId = req.paramsParsed.userId;
  if (!(await mayReadBundle(me, targetId))) {
    throw forbidden('key_bundle_unavailable', 'Encryption keys are available after you are connected');
  }

  const published = await db.tx(async (client) => {
    const { rows } = await client.query('SELECT * FROM user_key_bundles WHERE user_id = $1 FOR UPDATE', [targetId]);
    const row = rows[0];
    if (!row) return null;
    let oneTime = prekeyList(row.one_time_prekeys);
    let consumed = null;
    const skipOneTime = req.query.one_time === '0';
    if (oneTime.length > 0 && targetId !== me && !skipOneTime) {
      consumed = oneTime[0];
      oneTime = oneTime.slice(1);
      await client.query('UPDATE user_key_bundles SET one_time_prekeys = $2::jsonb, updated_at = NOW() WHERE user_id = $1', [
        targetId,
        JSON.stringify(oneTime),
      ]);
    }
    return { row, consumed };
  });
  if (!published) throw notFound('key_bundle_not_found', 'User has not published encryption keys yet');

  const { row, consumed } = published;
  res.json({
    success: true,
    bundle: {
      user_id: targetId,
      identity_key: row.identity_key,
      signing_key: row.signing_key || null,
      signed_prekey_id: row.signed_prekey_id,
      signed_prekey: row.signed_prekey,
      signed_prekey_sig: row.signed_prekey_sig,
      identity_generation: row.identity_generation || 1,
      one_time_prekey: consumed,
    },
  });
});
