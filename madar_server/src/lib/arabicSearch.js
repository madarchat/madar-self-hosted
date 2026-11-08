import { db } from '../db/pool.js';

/**
 * Arabic text normalizer per MADAR-SRS-SAD-1.0 Section 12.6:
 * - NFKC normalization
 * - Strip Arabic diacritics (Tashkeel) and Tatweel
 * - Unify Alef variants (أ/إ/آ/ٱ -> ا)
 * - Unify Alef Maqsura (ى -> ي)
 * - Unify Taa Marbuta (ة -> ه)
 * - Convert Eastern Arabic numerals (٠-٩ -> 0-9)
 */
export function normalizeArabic(text) {
  return String(text || '')
    .normalize('NFKC')
    .replace(/[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED]/g, '') // Strip Tashkeel
    .replace(/\u0640/g, '')                                            // Strip Tatweel
    .replace(/[\u0622\u0623\u0625\u0671]/g, '\u0627')                  // Unify Alef
    .replace(/\u0649/g, '\u064A')                                      // ى -> ي
    .replace(/\u0629/g, '\u0647')                                      // ة -> ه
    .replace(/[\u0660-\u0669]/g, (d) => String(d.charCodeAt(0) - 0x0660))
    .toLowerCase()
    .trim();
}

/**
 * Upserts a document into the Arabic full-text search index (search_docs).
 */
export async function indexSearchDoc(
  { docType, docId, workspaceId, channelId = null, text, title = null, body = null },
  client = db,
) {
  const combinedText = [title, body, text].filter(Boolean).join(' ');
  const normalized = normalizeArabic(combinedText);
  if (!normalized) return;
  const exec = client.query.bind(client);
  await exec(
    `INSERT INTO search_docs (doc_type, doc_id, workspace_id, channel_id, title, normalized_ar)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (doc_type, doc_id)
     DO UPDATE SET
       title = COALESCE(EXCLUDED.title, search_docs.title),
       normalized_ar = EXCLUDED.normalized_ar,
       channel_id = EXCLUDED.channel_id,
       updated_at = NOW()`,
    [docType, docId, workspaceId, channelId, title, normalized],
  );
}

export async function removeSearchDoc(docType, docId, client = db) {
  const exec = client.query.bind(client);
  await exec('DELETE FROM search_docs WHERE doc_type = $1 AND doc_id = $2', [docType, docId]);
}

/**
 * Searches workspace documents (messages, broadcasts, decisions, followups, references)
 * respecting user channel membership and Arabic normalization.
 */
export async function searchWorkspace({
  workspaceId,
  userId = null,
  query,
  docTypes = null,
  channelId = null,
  limit = 30,
}) {
  const normalizedQuery = normalizeArabic(query);
  if (!normalizedQuery) return [];

  const tokens = normalizedQuery
    .split(/\s+/)
    .map((t) => t.replace(/[^\p{L}\p{N}_-]/gu, ''))
    .filter(Boolean);

  const tsQueryStr = tokens.map((t) => `${t}:*`).join(' & ');
  const params = [workspaceId, userId, `%${normalizedQuery}%`];
  let filterSql = '';

  if (Array.isArray(docTypes) && docTypes.length > 0) {
    params.push(docTypes);
    filterSql += ` AND sd.doc_type = ANY($${params.length}::varchar[])`;
  }
  if (channelId) {
    params.push(channelId);
    filterSql += ` AND sd.channel_id = $${params.length}::uuid`;
  }

  let matchSql = 'sd.normalized_ar LIKE $3';
  if (tsQueryStr) {
    params.push(tsQueryStr);
    matchSql = `(sd.tsv @@ to_tsquery('simple', $${params.length}) OR sd.normalized_ar LIKE $3)`;
  }

  params.push(Math.min(Math.max(Number(limit) || 30, 1), 100));
  const limitParam = `$${params.length}`;

  const rows = await db.many(
    `SELECT sd.doc_type, sd.doc_id, sd.channel_id, sd.title, sd.normalized_ar, sd.created_at
     FROM search_docs sd
     LEFT JOIN channel_members cm ON cm.channel_id = sd.channel_id AND ($2::bigint IS NULL OR cm.user_id = $2)
     LEFT JOIN channels ch ON ch.id = sd.channel_id
     WHERE sd.workspace_id = $1
       AND ${matchSql}
       AND (
         sd.channel_id IS NULL
         OR $2::bigint IS NULL
         OR cm.user_id IS NOT NULL
         OR ch.kind IN ('public_channel', 'broadcast_feed')
       )
       ${filterSql}
     ORDER BY sd.created_at DESC
     LIMIT ${limitParam}`,
    params,
  );

  return rows;
}
