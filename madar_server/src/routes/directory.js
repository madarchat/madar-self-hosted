import { Router } from 'express';
import { db } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { attachPolicyContext } from '../middleware/policyGuard.js';
import { validate, z } from '../lib/validate.js';
import { normalizeArabic } from '../lib/arabicSearch.js';
import { ensureDefaultWorkspace } from '../services/policyEngine.js';
import { sendToUsers } from '../realtime/ws.js';

export const directoryRouter = Router();
directoryRouter.use(requireAuth, attachPolicyContext);

function buildDepartmentTree(departments) {
  const byId = new Map();
  for (const d of departments) {
    byId.set(d.id, { ...d, children: [] });
  }
  const roots = [];
  for (const node of byId.values()) {
    if (node.parent_id && byId.has(node.parent_id)) {
      byId.get(node.parent_id).children.push(node);
    } else {
      roots.push(node);
    }
  }
  return roots;
}

function projectEmployeeFields(emp, visibleFields) {
  const allowed = new Set(
    Array.isArray(visibleFields)
      ? visibleFields
      : ['name', 'title', 'department', 'email', 'employee_no', 'work_phone'],
  );
  const out = {
    id: emp.id,
    employee_no: emp.employee_no || `EMP-${emp.id}`,
    avatar_url: emp.avatar_url || null,
    presence_status: emp.presence_status || 'available',
    presence_note: emp.presence_note || '',
    presence_until: emp.presence_until || null,
    account_status: emp.account_status || 'active',
  };

  if (allowed.has('name')) out.name = emp.name || '';
  if (allowed.has('title')) out.title = emp.title || '';
  if (allowed.has('department')) {
    out.department_id = emp.department_id || null;
    out.department_name = emp.department_name || null;
    out.department_code = emp.department_code || null;
  }
  if (allowed.has('email')) out.email = emp.email || null;
  if (allowed.has('work_phone')) out.work_phone = emp.work_phone || emp.phone || null;

  return out;
}

/**
 * GET /api/v1/directory — Organizational directory & department hierarchy (DIR-01..05, TC-POL-19, TC-POL-20).
 */
directoryRouter.get('/', async (req, res) => {
  const wsId = req.auth.workspaceId || (await ensureDefaultWorkspace()).id;
  const policies = req.effectivePolicy?.policies || {};
  const scope = policies['directory.scope'] || 'all';
  const visibleFields = policies['directory.visible_fields'] || [
    'name',
    'title',
    'department',
    'email',
    'employee_no',
    'work_phone',
  ];

  if (scope === 'none') {
    res.json({
      success: true,
      scope: 'none',
      visible_fields: visibleFields,
      departments: [],
      department_tree: [],
      employees: [],
    });
    return;
  }

  const caller = await db.one('SELECT id, department_id FROM users WHERE id = $1', [req.auth.userId]);
  const { q, department_id, status } = req.query;

  let deptRows = await db.many(
    `SELECT d.*,
            u.name AS head_user_name,
            (SELECT COUNT(*)::int FROM users m WHERE m.department_id = d.id AND m.account_status = 'active') AS member_count
     FROM departments d
     LEFT JOIN users u ON u.id = d.head_user_id
     WHERE d.workspace_id = $1
     ORDER BY d.sort_order ASC, d.name ASC`,
    [wsId],
  );

  const params = [wsId];
  const conditions = [
    "(u.workspace_id = $1 OR (u.workspace_id IS NULL AND u.profile_type = 'workspace'))",
    "u.account_status <> 'offboarded'",
  ];

  if (scope === 'same_department') {
    if (!caller?.department_id) {
      res.json({
        success: true,
        scope: 'same_department',
        visible_fields: visibleFields,
        departments: [],
        department_tree: [],
        employees: [],
      });
      return;
    }
    params.push(caller.department_id);
    conditions.push(`u.department_id = $${params.length}`);
    deptRows = deptRows.filter((d) => d.id === caller.department_id);
  } else if (department_id) {
    params.push(String(department_id));
    conditions.push(`u.department_id = $${params.length}`);
  }

  if (status) {
    params.push(String(status));
    conditions.push(`u.presence_status = $${params.length}`);
  }

  let employees = await db.many(
    `SELECT u.id, u.name, u.title, u.email, u.work_phone, u.phone, u.employee_no,
            u.department_id, u.avatar_url, u.presence_status, u.presence_note, u.presence_until,
            u.account_status,
            d.name AS department_name, d.code AS department_code
     FROM users u
     LEFT JOIN departments d ON d.id = u.department_id
     WHERE ${conditions.join(' AND ')}
     ORDER BY u.name ASC, u.id ASC`,
    params,
  );

  if (q && String(q).trim()) {
    const normQ = normalizeArabic(String(q).trim());
    employees = employees.filter((emp) => {
      const hay = normalizeArabic(
        [emp.name, emp.title, emp.department_name, emp.email, emp.work_phone, emp.employee_no]
          .filter(Boolean)
          .join(' '),
      );
      return hay.includes(normQ);
    });
  }

  const projected = employees.map((emp) => projectEmployeeFields(emp, visibleFields));

  res.json({
    success: true,
    scope,
    visible_fields: visibleFields,
    departments: deptRows,
    department_tree: buildDepartmentTree(deptRows),
    employees: projected,
  });
});

/**
 * PATCH /api/v1/presence — Update work presence status (DIR-05).
 */
export const presenceRouter = Router();
presenceRouter.use(requireAuth, attachPolicyContext);

presenceRouter.patch(
  '/',
  validate({
    body: z.object({
      status: z.enum(['available', 'in_meeting', 'do_not_disturb', 'on_leave']),
      note: z.string().trim().max(120).optional(),
      until: z.string().datetime().nullable().optional(),
    }),
  }),
  async (req, res) => {
    const { status, note, until } = req.body;
    const updated = await db.one(
      `UPDATE users
       SET presence_status = $2,
           presence_note = COALESCE($3, presence_note),
           presence_until = $4,
           last_seen_at = NOW(),
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, workspace_id, presence_status, presence_note, presence_until`,
      [req.auth.userId, status, note ?? '', until ? new Date(until) : null],
    );

    if (updated?.workspace_id) {
      const peers = await db.many(
        "SELECT id FROM users WHERE workspace_id = $1 AND account_status = 'active'",
        [updated.workspace_id],
      );
      sendToUsers(
        peers.map((p) => p.id),
        'presence',
        {
          user_id: updated.id,
          status: updated.presence_status,
          note: updated.presence_note,
          until: updated.presence_until,
        },
      );
    }

    res.json({
      success: true,
      presence: {
        user_id: updated.id,
        status: updated.presence_status,
        note: updated.presence_note,
        until: updated.presence_until,
      },
    });
  },
);
