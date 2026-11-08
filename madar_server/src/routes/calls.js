import { Router } from 'express';
import { db } from '../db/pool.js';
import { validate, z } from '../lib/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { serializeCall } from '../lib/serialize.js';
import { buildIceConfig } from '../realtime/ice.js';
import { declineCallById } from '../realtime/calls.js';

export const callsRouter = Router();
callsRouter.use(requireAuth);

/**
 * ICE servers the client should use. Points at this server's built-in STUN service and,
 * when enabled, the self-hosted TURN relay with short-lived HMAC credentials.
 */
callsRouter.get('/ice-config', async (req, res) => {
  const iceConfig = await buildIceConfig(req.auth.userId);
  res.json({ success: true, ...iceConfig });
});

callsRouter.get(
  '/',
  validate({ query: z.object({ limit: z.coerce.number().int().min(1).max(200).default(60), before: z.string().datetime().optional() }) }),
  async (req, res) => {
    const me = req.auth.userId;
    const { limit, before } = req.queryParsed;
    const params = [me, limit];
    let where = '(c.caller_id = $1 OR c.callee_id = $1)';
    if (before) { params.push(before); where += ` AND c.started_at < $${params.length}`; }
    const rows = await db.many(
      `SELECT c.*, cu.name AS caller_name, cu.avatar_url AS caller_avatar_url,
              ce.name AS callee_name, ce.avatar_url AS callee_avatar_url
       FROM calls c
       LEFT JOIN users cu ON cu.id = c.caller_id
       LEFT JOIN users ce ON ce.id = c.callee_id
       WHERE ${where} ORDER BY c.started_at DESC LIMIT $2`,
      params,
    );
    res.json({ success: true, calls: rows.map(serializeCall) });
  },
);

callsRouter.post(
  '/:id/decline',
  validate({ params: z.object({ id: z.string().min(1).max(64) }) }),
  async (req, res) => {
    const declined = await declineCallById(req.auth.userId, req.paramsParsed.id);
    res.json({ success: true, declined });
  },
);

callsRouter.delete('/', async (req, res) => {
  await db.query('DELETE FROM calls WHERE (caller_id = $1 OR callee_id = $1) AND status <> $2', [req.auth.userId, 'ringing']);
  res.json({ success: true });
});
