import crypto from 'node:crypto';
import { db } from '../db/pool.js';

export const GENESIS_HASH = '0'.repeat(64);

/**
 * Canonical SHA-256 hash computation for a tamper-evident audit_log row.
 * row_hash = SHA-256(prev_hash || id || workspace_id || actor_user_id || action || target_type || target_id || canonical_json(metadata_json) || created_at_iso)
 */
export function computeAuditRowHash({
  prevHash,
  id,
  workspaceId,
  actorUserId,
  action,
  targetType,
  targetId,
  metadataJson,
  createdAtIso,
}) {
  const canonicalMeta = canonicalJson(metadataJson ?? {});
  const payload = [
    String(prevHash || GENESIS_HASH),
    String(id),
    String(workspaceId),
    String(actorUserId ?? ''),
    String(action),
    String(targetType),
    String(targetId ?? ''),
    canonicalMeta,
    String(createdAtIso),
  ].join('|');
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

function canonicalJson(val) {
  if (val === undefined) return 'null';
  if (val === null || typeof val !== 'object') return JSON.stringify(val);
  if (Array.isArray(val)) return `[${val.map((item) => canonicalJson(item)).join(',')}]`;
  const keys = Object.keys(val)
    .filter((k) => val[k] !== undefined && typeof val[k] !== 'function')
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(val[k])}`).join(',')}}`;
}

/**
 * Appends an immutable, hash-chained entry to audit_log.
 * Uses an advisory lock per workspace inside a transaction to serialize hash chaining.
 */
export async function appendAuditLog(
  {
    workspaceId,
    actorUserId = null,
    actorDeviceId = null,
    action,
    targetType,
    targetId = null,
    metadata = {},
    ipHash = null,
  },
  externalClient = null,
) {
  const run = async (client) => {
    const lockKey = crypto.createHash('md5').update(String(workspaceId)).digest().readInt32BE(0);
    await client.query('SELECT pg_advisory_xact_lock($1)', [lockKey]);

    const prevRes = await client.query(
      'SELECT row_hash FROM audit_log WHERE workspace_id = $1 ORDER BY id DESC LIMIT 1',
      [workspaceId],
    );
    const prevHash = prevRes.rows[0]?.row_hash || GENESIS_HASH;
    const createdAt = new Date();
    const createdAtIso = createdAt.toISOString();

    const seqRes = await client.query("SELECT nextval(pg_get_serial_sequence('audit_log', 'id')) AS id");
    const nextId = Number(seqRes.rows[0].id);

    const rowHash = computeAuditRowHash({
      prevHash,
      id: nextId,
      workspaceId,
      actorUserId,
      action,
      targetType,
      targetId,
      metadataJson: metadata,
      createdAtIso,
    });

    const ins = await client.query(
      `INSERT INTO audit_log (
         id, workspace_id, actor_user_id, actor_device_id, action, target_type, target_id,
         metadata_json, ip_hash, prev_hash, row_hash, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12)
       RETURNING *`,
      [
        nextId,
        workspaceId,
        actorUserId,
        actorDeviceId,
        action,
        targetType,
        targetId !== null && targetId !== undefined ? String(targetId) : null,
        JSON.stringify(metadata ?? {}),
        ipHash,
        prevHash,
        rowHash,
        createdAtIso,
      ],
    );
    return ins.rows[0];
  };

  if (externalClient) {
    return run(externalClient);
  }
  return db.tx(run);
}

/**
 * Verifies the cryptographic integrity of the entire audit_log hash chain for a workspace.
 */
export async function verifyAuditChain(workspaceId) {
  const rows = await db.many(
    'SELECT * FROM audit_log WHERE workspace_id = $1 ORDER BY id ASC',
    [workspaceId],
  );
  let expectedPrev = GENESIS_HASH;
  let checkedCount = 0;

  for (const row of rows) {
    checkedCount += 1;
    if (row.prev_hash !== expectedPrev) {
      return {
        valid: false,
        checked_count: checkedCount,
        checkedCount,
        broken_at_id: row.id,
        reason: 'prev_hash_mismatch',
        expected_hash: expectedPrev,
        actual_hash: row.prev_hash,
      };
    }
    const recomputed = computeAuditRowHash({
      prevHash: row.prev_hash,
      id: row.id,
      workspaceId: row.workspace_id,
      actorUserId: row.actor_user_id,
      action: row.action,
      targetType: row.target_type,
      targetId: row.target_id,
      metadataJson: row.metadata_json,
      createdAtIso: new Date(row.created_at).toISOString(),
    });
    if (recomputed !== row.row_hash) {
      return {
        valid: false,
        checked_count: checkedCount,
        checkedCount,
        broken_at_id: row.id,
        reason: 'row_hash_tampered',
        expected_hash: recomputed,
        actual_hash: row.row_hash,
      };
    }
    expectedPrev = row.row_hash;
  }

  return {
    valid: true,
    checked_count: checkedCount,
    checkedCount,
    head_hash: expectedPrev,
  };
}
