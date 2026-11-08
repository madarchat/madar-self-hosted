import { db } from '../db/pool.js';
import { phoneDiscoveryHash } from './phoneHash.js';

export async function syncUserPhoneHash(userId, phone) {
  if (!userId || !phone) return;
  const phone_hash = phoneDiscoveryHash(phone);
  await db.query(
    `INSERT INTO user_phone_hashes (user_id, phone_hash, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (user_id) DO UPDATE SET phone_hash = EXCLUDED.phone_hash, updated_at = NOW()`,
    [userId, phone_hash],
  );
}
