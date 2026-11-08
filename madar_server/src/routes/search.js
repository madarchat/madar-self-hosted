import { Router } from 'express';
import { db } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { attachPolicyContext } from '../middleware/policyGuard.js';
import { searchWorkspace, normalizeArabic } from '../lib/arabicSearch.js';
import { ensureDefaultWorkspace } from '../services/policyEngine.js';

export const searchRouter = Router();
searchRouter.use(requireAuth, attachPolicyContext);

/**
 * GET /api/v1/search — Unified Arabic full-text search across messages, broadcasts, decisions, followups, references & directory (SRCH-01..03).
 */
searchRouter.get('/', async (req, res) => {
  const q = String(req.query.q || '').trim();
  const typeParam = req.query.type ? String(req.query.type).trim() : null;
  const channelId = req.query.channel_id ? String(req.query.channel_id).trim() : null;
  const limit = Math.min(Math.max(Number(req.query.limit) || 30, 1), 100);

  if (!q) {
    res.json({ success: true, query: '', results: [], grouped: {} });
    return;
  }

  const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
  const requestedTypes = typeParam
    ? typeParam.split(',').map((t) => t.trim()).filter(Boolean)
    : ['message', 'broadcast', 'decision', 'followup', 'reference'];

  // Determine channels the user is a member of (or public channels)
  const memberChannels = await db.many(
    `SELECT c.id
     FROM channels c
     LEFT JOIN channel_members cm ON cm.channel_id = c.id AND cm.user_id = $2
     WHERE c.workspace_id = $1
       AND (cm.user_id IS NOT NULL OR c.kind IN ('public_channel', 'broadcast_feed'))`,
    [wsId, req.auth.userId],
  );
  const accessibleChannelIds = memberChannels.map((c) => c.id);
  const effectiveChannelFilter = channelId
    ? accessibleChannelIds.includes(channelId)
      ? [channelId]
      : []
    : accessibleChannelIds;

  const docTypes = requestedTypes.filter((t) =>
    ['message', 'broadcast', 'decision', 'followup', 'reference'].includes(t),
  );

  let docs = [];
  if (docTypes.length > 0) {
    docs = await searchWorkspace({
      workspaceId: wsId,
      userId: req.auth.userId,
      query: q,
      docTypes,
      channelId: channelId || null,
      limit,
    });
    // Filter channel-scoped docs by membership
    const channelSet = new Set(accessibleChannelIds);
    docs = docs.filter((d) => !d.channel_id || channelSet.has(d.channel_id));
  }

  const grouped = {
    decisions: docs.filter((d) => d.doc_type === 'decision'),
    broadcasts: docs.filter((d) => d.doc_type === 'broadcast'),
    followups: docs.filter((d) => d.doc_type === 'followup'),
    references: docs.filter((d) => d.doc_type === 'reference'),
    messages: docs.filter((d) => d.doc_type === 'message'),
    employees: [],
  };

  if (!typeParam || requestedTypes.includes('employee')) {
    const scope = req.effectivePolicy?.policies?.['directory.scope'] || 'all';
    if (scope !== 'none') {
      const normQ = normalizeArabic(q);
      const emps = await db.many(
        `SELECT id, name, title, email, employee_no, department_id, avatar_url, presence_status
         FROM users
         WHERE (workspace_id = $1 OR workspace_id IS NULL) AND account_status = 'active'
         LIMIT 200`,
        [wsId],
      );
      grouped.employees = emps.filter((e) => {
        const hay = normalizeArabic([e.name, e.title, e.email, e.employee_no].filter(Boolean).join(' '));
        return hay.includes(normQ);
      });
    }
  }

  res.json({
    success: true,
    query: q,
    normalized_query: normalizeArabic(q),
    results: docs,
    grouped,
  });
});
