import { Router } from 'express';
import { db } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { attachPolicyContext } from '../middleware/policyGuard.js';
import { decryptField } from '../lib/fieldCrypto.js';
import { ensureDefaultWorkspace } from '../services/policyEngine.js';
import { notFound } from '../lib/errors.js';

export const hubRouter = Router();
hubRouter.use(requireAuth, attachPolicyContext);

async function hydrateHubItem(item) {
  let detail = null;

  if (item.source_type === 'broadcast') {
    const b = await db.one('SELECT * FROM broadcasts WHERE id = $1', [item.source_id]);
    if (b) {
      const ver = await db.one(
        'SELECT title FROM broadcast_versions WHERE broadcast_id = $1 AND version_no = $2',
        [b.id, b.current_version],
      );
      detail = {
        broadcast_id: b.id,
        ref_no: b.ref_no,
        title: ver?.title || '',
        priority: b.priority,
        ack_type: b.ack_type,
        quiz_json: b.quiz_json
          ? { question: b.quiz_json.question, options: b.quiz_json.options }
          : null,
        ack_deadline: b.ack_deadline,
        current_version: b.current_version,
      };
    }
  } else if (item.source_type === 'followup') {
    const f = await db.one(
      `SELECT f.*, c.name AS channel_name, u.name AS owner_name
       FROM followups f
       LEFT JOIN channels c ON c.id = f.channel_id
       LEFT JOIN users u ON u.id = f.owner_id
       WHERE f.id = $1`,
      [item.source_id],
    );
    if (f) {
      detail = {
        followup_id: f.id,
        channel_id: f.channel_id,
        channel_name: f.channel_name,
        title: f.title,
        status: f.status,
        due_at: f.due_at,
        owner_id: f.owner_id,
        owner_name: f.owner_name,
      };
    }
  } else if (item.source_type === 'mention') {
    const m = await db.one(
      `SELECT cm.*, c.name AS channel_name, u.name AS sender_name
       FROM channel_messages cm
       LEFT JOIN channels c ON c.id = cm.channel_id
       LEFT JOIN users u ON u.id = cm.sender_id
       WHERE cm.id = $1`,
      [item.source_id],
    );
    if (m) {
      const text = decryptField(m.body_ciphertext, m.body_iv, m.key_id);
      detail = {
        message_id: m.id,
        channel_id: m.channel_id,
        channel_name: m.channel_name,
        sender_id: m.sender_id,
        sender_name: m.sender_name,
        snippet: text.slice(0, 200),
      };
    }
  } else if (item.source_type === 'decision') {
    const d = await db.one(
      `SELECT d.*, c.name AS channel_name, u.name AS decided_by_name
       FROM decisions d
       LEFT JOIN channels c ON c.id = d.channel_id
       LEFT JOIN users u ON u.id = d.decided_by
       WHERE d.id = $1`,
      [item.source_id],
    );
    if (d) {
      detail = {
        decision_id: d.id,
        channel_id: d.channel_id,
        channel_name: d.channel_name,
        title: d.title,
        status: d.status,
        decided_by_name: d.decided_by_name,
        decided_at: d.decided_at,
      };
    }
  }

  return {
    id: item.id,
    section: item.section,
    source_type: item.source_type,
    source_id: item.source_id,
    priority: item.priority,
    due_at: item.due_at,
    created_at: item.created_at,
    detail,
  };
}

/**
 * GET /api/v1/hub — Attention Hub grouped into requires_action, followups, announcements (HUB-01..04).
 */
hubRouter.get('/', async (req, res) => {
  const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;

  // Auto-escalate overdue open followups into requires_action
  await db.query(
    `UPDATE hub_items
     SET section = 'requires_action', priority = GREATEST(priority, 90)
     WHERE user_id = $1
       AND workspace_id = $2
       AND source_type = 'followup'
       AND resolved_at IS NULL
       AND due_at IS NOT NULL
       AND due_at < NOW()`,
    [req.auth.userId, wsId],
  );

  // Auto-resolve any hub_items whose underlying followup is already done or broadcast is retracted/acked
  await db.query(
    `UPDATE hub_items hi
     SET resolved_at = NOW()
     FROM followups f
     WHERE hi.source_type = 'followup'
       AND hi.source_id = f.id
       AND hi.user_id = $1
       AND hi.resolved_at IS NULL
       AND f.status = 'done'`,
    [req.auth.userId],
  );

  const rows = await db.many(
    `SELECT * FROM hub_items
     WHERE user_id = $1 AND workspace_id = $2 AND resolved_at IS NULL
     ORDER BY priority DESC, due_at ASC NULLS LAST, created_at DESC
     LIMIT 150`,
    [req.auth.userId, wsId],
  );

  const hydrated = await Promise.all(rows.map(hydrateHubItem));
  const validItems = hydrated.filter((i) => i.detail !== null);

  const requires_action = validItems.filter((i) => i.section === 'requires_action');
  const followups = validItems.filter((i) => i.section === 'followups');
  const announcements = validItems.filter((i) => i.section === 'announcements');

  res.json({
    success: true,
    counts: {
      requires_action: requires_action.length,
      followups: followups.length,
      announcements: announcements.length,
      total: validItems.length,
    },
    sections: {
      requires_action,
      followups,
      announcements,
    },
  });
});

/**
 * POST /api/v1/hub/:id/resolve — Dismiss/resolve an announcement or mention hub item (HUB-03).
 */
hubRouter.post('/:id/resolve', async (req, res) => {
  const updated = await db.one(
    `UPDATE hub_items
     SET resolved_at = NOW()
     WHERE id = $1 AND user_id = $2
     RETURNING *`,
    [req.params.id, req.auth.userId],
  );
  if (!updated) throw notFound('hub_item_not_found', 'عنصر مركز الاهتمام غير موجود');
  res.json({ success: true, item: updated });
});
