import fs from 'node:fs';
import path from 'node:path';
import { env, ROOT_DIR } from '../config/env.js';
import { db } from '../db/pool.js';
import { ensureWorkspaceSigningKey, signEd25519Jws } from '../lib/jws.js';
import { badRequest } from '../lib/errors.js';

function resolveCatalogPath() {
  const candidates = [
    process.env.POLICY_CATALOG_PATH,
    path.resolve(ROOT_DIR, 'specs/policy-catalog.json'),
    path.resolve(ROOT_DIR, '../specs/policy-catalog.json'),
  ].filter(Boolean);
  return candidates.find((p) => fs.existsSync(p)) || candidates[candidates.length - 1];
}
let cachedCatalog = null;

export function loadPolicyCatalog() {
  if (cachedCatalog) return cachedCatalog;
  const raw = fs.readFileSync(resolveCatalogPath(), 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed.keys && Array.isArray(parsed.policies)) {
    parsed.keys = {};
    for (const item of parsed.policies) {
      parsed.keys[item.key] = item;
    }
  }
  cachedCatalog = parsed;
  return cachedCatalog;
}

const POLICY_ALIASES = [
  ['media.max_mb', 'chat.max_attachment_mb'],
  ['media.allowed_types', 'chat.allowed_mime_categories'],
  ['chat.voice_notes', 'chat.allow_voice_notes'],
  ['device.max_devices', 'device.max_per_user'],
  ['retention.days', 'retention.message_days'],
  ['presence.custom_note', 'presence.allow_custom_status'],
  ['dlp.allow_copy', 'dlp.allow_copy_paste'],
  ['security.screenshot_block', 'dlp.prevent_screenshots'],
];

function applyPolicyEntryWithAliases(effective, sources, lockedKeys, key, value, sourceLabel, isLocked) {
  effective[key] = value;
  sources[key] = sourceLabel;
  if (isLocked) lockedKeys.add(key);

  for (const [a, b] of POLICY_ALIASES) {
    if (key === a) {
      effective[b] = value;
      sources[b] = sourceLabel;
      if (isLocked) lockedKeys.add(b);
    } else if (key === b) {
      effective[a] = value;
      sources[a] = sourceLabel;
      if (isLocked) lockedKeys.add(a);
    }
  }
}

export function getPolicySpecMap() {
  const catalog = loadPolicyCatalog();
  const map = new Map();
  for (const item of catalog.policies) {
    map.set(item.key, item);
  }
  return map;
}

export function getServerDefaults(profileType = 'workspace') {
  const catalog = loadPolicyCatalog();
  const defaults = {};
  const field = profileType === 'personal' ? 'personal_default' : 'workspace_default';
  for (const item of catalog.policies) {
    defaults[item.key] = structuredClone(item[field]);
  }
  return defaults;
}

/**
 * Validates a policy key and value against specs/policy-catalog.json.
 */
export function validatePolicyEntry(policyKey, value) {
  const map = getPolicySpecMap();
  const spec = map.get(policyKey);
  if (!spec) {
    throw badRequest('unknown_policy_key', `مفتاح السياسة غير معروف في الكتالوج: ${policyKey}`);
  }
  switch (spec.type) {
    case 'bool':
      if (typeof value !== 'boolean') {
        throw badRequest('invalid_policy_value', `السياسة ${policyKey} تتطلب قيمة منطقية (boolean)`);
      }
      break;
    case 'int':
      if (typeof value !== 'number' || !Number.isInteger(value)) {
        throw badRequest('invalid_policy_value', `السياسة ${policyKey} تتطلب عدداً صحيحاً (int)`);
      }
      if (spec.min !== undefined && value < spec.min) {
        throw badRequest('invalid_policy_value', `قيمة ${policyKey} أقل من الحد الأدنى (${spec.min})`);
      }
      if (spec.max !== undefined && value > spec.max) {
        throw badRequest('invalid_policy_value', `قيمة ${policyKey} أكبر من الحد الأعلى (${spec.max})`);
      }
      break;
    case 'enum':
      if (!spec.enum_values?.includes(value)) {
        throw badRequest('invalid_policy_value', `قيمة ${policyKey} يجب أن تكون إحدى القيم: ${spec.enum_values.join(', ')}`);
      }
      break;
    case 'enum[]':
    case 'string[]':
      if (!Array.isArray(value)) {
        throw badRequest('invalid_policy_value', `السياسة ${policyKey} تتطلب مصفوفة قيم`);
      }
      if (spec.type === 'enum[]' && spec.enum_values) {
        for (const item of value) {
          if (!spec.enum_values.includes(item)) {
            throw badRequest('invalid_policy_value', `العنصر ${item} غير صالح في ${policyKey}`);
          }
        }
      }
      break;
    default:
      break;
  }
  return spec;
}

/**
 * Ensures a default workspace exists (used during setup or initial discovery).
 */
export async function ensureDefaultWorkspace(client = db) {
  const qOne = client.one
    ? (sql, params) => client.one(sql, params)
    : async (sql, params) => (await client.query(sql, params)).rows[0] || null;
  const exec = client.query.bind(client);

  let ws = await qOne('SELECT * FROM workspace ORDER BY created_at ASC LIMIT 1', []);
  if (!ws) {
    const res = await exec(
      `INSERT INTO workspace (name, deployment_profile, setup_completed)
       VALUES ($1, $2, FALSE)
       RETURNING *`,
      [env.WORKSPACE_DEFAULT_NAME || 'مساحة عمل مدار', env.DEPLOYMENT_PROFILE || 'workspace'],
    );
    ws = res.rows[0];
    await exec(
      'INSERT INTO policy_versions (workspace_id, summary) VALUES ($1, $2)',
      [ws.id, 'الإصدار الافتراضي الأولي للسياسات'],
    );
  }
  await ensureWorkspaceSigningKey(ws.id, client);
  return ws;
}

export function getPolicyCatalog() {
  return loadPolicyCatalog();
}

/**
 * Non-throwing validation helper used by admin routes.
 */
export function validatePolicyEntryValue(policyKey, value) {
  try {
    validatePolicyEntry(policyKey, value);
    return { valid: true };
  } catch (err) {
    return { valid: false, error: err.message || 'قيمة السياسة غير صالحة' };
  }
}

/**
 * Resolves the effective 4-layer policy object for a given user inside a workspace:
 * Layer 1: Server Defaults (specs/policy-catalog.json)
 * Layer 2: Workspace Policy (scope_type='workspace', scope_id=workspaceId)
 * Layer 3: Group / Department Policy (scope_type IN ('group','department'), ordered by priority ASC; lower number = higher priority)
 * Layer 4: User Override (scope_type='user', scope_id=String(userId))
 *
 * When a higher layer sets `locked = true`, no lower layer may override that policy_key.
 */
export async function resolveEffectivePolicy(workspaceId, userId = null, profileType = 'workspace') {
  const effective = getServerDefaults(profileType);
  const lockedKeys = new Set();
  const sources = {};
  for (const k of Object.keys(effective)) {
    sources[k] = 'default';
  }

  if (!workspaceId) {
    return { policies: effective, lockedKeys: [...lockedKeys], sources, version: 1 };
  }

  // Layer 2: Workspace-level policies
  const wsEntries = await db.many(
    `SELECT COALESCE(policy_key, key) AS policy_key, value_json, locked
     FROM policy_entries
     WHERE scope_type = 'workspace' AND scope_id = $1`,
    [String(workspaceId)],
  );
  for (const entry of wsEntries) {
    applyPolicyEntryWithAliases(
      effective,
      sources,
      lockedKeys,
      entry.policy_key,
      entry.value_json,
      'workspace',
      Boolean(entry.locked),
    );
  }

  if (userId) {
    const userRow = await db.one('SELECT department_id FROM users WHERE id = $1', [userId]);
    const deptId = userRow?.department_id || null;

    // Layer 3a: Direct department-scoped policy entries (scope_type='department')
    if (deptId) {
      const deptEntries = await db.many(
        `SELECT COALESCE(policy_key, key) AS policy_key, value_json, locked
         FROM policy_entries
         WHERE scope_type = 'department' AND scope_id = $1`,
        [String(deptId)],
      );
      for (const entry of deptEntries) {
        if (lockedKeys.has(entry.policy_key)) continue;
        applyPolicyEntryWithAliases(
          effective,
          sources,
          lockedKeys,
          entry.policy_key,
          entry.value_json,
          `department:${deptId}`,
          Boolean(entry.locked),
        );
      }
    }

    // Layer 3b: Policy groups matching user_id or user's department_id
    // Ordered ASC so higher priority integer is applied last and wins within Layer 3b
    const groupEntries = await db.many(
      `SELECT COALESCE(pe.policy_key, pe.key) AS policy_key, pe.value_json, pe.locked, pg.priority, pg.id AS group_id
       FROM policy_groups pg
       JOIN policy_group_members pgm ON pgm.group_id = pg.id
       JOIN policy_entries pe ON pe.scope_type = 'group' AND pe.scope_id = pg.id::text
       WHERE pg.workspace_id = $1
         AND (pgm.user_id = $2 OR ($3::uuid IS NOT NULL AND pgm.department_id = $3::uuid))
       ORDER BY pg.priority ASC, pg.created_at ASC`,
      [workspaceId, userId, deptId],
    );

    const groupLocks = new Set();
    for (const entry of groupEntries) {
      if (lockedKeys.has(entry.policy_key)) continue;
      applyPolicyEntryWithAliases(
        effective,
        sources,
        groupLocks,
        entry.policy_key,
        entry.value_json,
        `group:${entry.group_id}`,
        Boolean(entry.locked),
      );
    }
    for (const k of groupLocks) {
      lockedKeys.add(k);
    }

    // Layer 4: User-level overrides
    const userEntries = await db.many(
      `SELECT COALESCE(policy_key, key) AS policy_key, value_json
       FROM policy_entries
       WHERE scope_type = 'user' AND scope_id = $1`,
      [String(userId)],
    );
    for (const entry of userEntries) {
      if (lockedKeys.has(entry.policy_key)) continue;
      applyPolicyEntryWithAliases(
        effective,
        sources,
        lockedKeys,
        entry.policy_key,
        entry.value_json,
        'user',
        false,
      );
    }
  }

  const verRow = await db.one(
    'SELECT COALESCE(MAX(version), 1)::int AS version FROM policy_versions WHERE workspace_id = $1',
    [workspaceId],
  );

  return {
    policies: effective,
    lockedKeys: [...lockedKeys],
    sources,
    version: verRow?.version || 1,
  };
}

/**
 * Publishes a new policy version row in policy_versions and returns the version number.
 */
export async function publishPolicyVersion({ workspaceId, publishedBy, reason, diffJson = {} }) {
  const cleanReason = reason || 'تحديث سياسات مساحة العمل';
  const row = await db.one(
    `INSERT INTO policy_versions (workspace_id, summary, reason, diff_json, published_by, published_at)
     VALUES ($1, $2, $3, $4::jsonb, $5, NOW())
     RETURNING version`,
    [workspaceId, cleanReason.slice(0, 280), cleanReason, JSON.stringify(diffJson), publishedBy || null],
  );
  return Number(row.version);
}

/**
 * Builds and signs a JWS Policy Bundle (Ed25519) per Section 7.3.
 */
export async function buildSignedPolicyBundle(workspaceId, userId, profileType = 'workspace') {
  const resolved = await resolveEffectivePolicy(workspaceId, userId, profileType);
  const signingKey = await ensureWorkspaceSigningKey(workspaceId);
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    iss: env.PUBLIC_URL,
    sub: String(userId ?? 'anonymous'),
    wid: String(workspaceId),
    workspace_id: String(workspaceId),
    ver: resolved.version,
    version: resolved.version,
    iat: nowSec,
    exp: nowSec + 86_400,
    policies: resolved.policies,
    locked_keys: resolved.lockedKeys,
  };
  const jws = signEd25519Jws(payload, signingKey.privateKeyPem, signingKey.kid);
  return {
    version: resolved.version,
    kid: signingKey.kid,
    public_key_ed25519: signingKey.publicKeyEd25519,
    payload,
    jws,
  };
}

/**
 * Previews the impact of proposed policy changes before publishing (POL-03, POL-05).
 */
export async function previewPolicyImpact(workspaceId, arg2, arg3, arg4) {
  let scopeType = 'workspace';
  let scopeId = null;
  let entries = [];

  if (typeof arg2 === 'object' && arg2 !== null && !Array.isArray(arg2)) {
    scopeType = arg2.scopeType || arg2.scope_type || 'workspace';
    scopeId = arg2.scopeId || arg2.scope_id || null;
    entries = arg2.entries || arg2.changes || [];
  } else {
    scopeType = arg2 || 'workspace';
    scopeId = arg3 || null;
    entries = arg4 || [];
  }

  const targetScopeId = scopeType === 'workspace' ? String(workspaceId) : String(scopeId || workspaceId);
  const specMap = getPolicySpecMap();

  let affectedUsersCount = 0;
  let affectedDevicesCount = 0;

  if (scopeType === 'workspace') {
    const uCnt = await db.one(
      'SELECT COUNT(*)::int AS c FROM users WHERE workspace_id = $1 OR workspace_id IS NULL',
      [workspaceId],
    );
    const dCnt = await db.one(
      "SELECT COUNT(*)::int AS c FROM devices WHERE workspace_id = $1 AND status = 'active'",
      [workspaceId],
    );
    affectedUsersCount = uCnt?.c || 0;
    affectedDevicesCount = dCnt?.c || 0;
  } else if (scopeType === 'department') {
    const uCnt = await db.one(
      'SELECT COUNT(*)::int AS c FROM users WHERE department_id = $1::uuid',
      [targetScopeId],
    );
    const dCnt = await db.one(
      `SELECT COUNT(d.id)::int AS c
       FROM devices d
       JOIN users u ON u.id = d.user_id
       WHERE u.department_id = $1::uuid AND d.status = 'active'`,
      [targetScopeId],
    );
    affectedUsersCount = uCnt?.c || 0;
    affectedDevicesCount = dCnt?.c || 0;
  } else if (scopeType === 'group') {
    const uCnt = await db.one(
      `SELECT COUNT(DISTINCT u.id)::int AS c
       FROM users u
       JOIN policy_group_members pgm ON (pgm.user_id = u.id OR pgm.department_id = u.department_id)
       WHERE pgm.group_id = $1::uuid`,
      [targetScopeId],
    );
    const dCnt = await db.one(
      `SELECT COUNT(DISTINCT d.id)::int AS c
       FROM devices d
       JOIN users u ON u.id = d.user_id
       JOIN policy_group_members pgm ON (pgm.user_id = u.id OR pgm.department_id = u.department_id)
       WHERE pgm.group_id = $1::uuid AND d.status = 'active'`,
      [targetScopeId],
    );
    affectedUsersCount = uCnt?.c || 0;
    affectedDevicesCount = dCnt?.c || 0;
  } else if (scopeType === 'user') {
    affectedUsersCount = 1;
    const dCnt = await db.one(
      "SELECT COUNT(*)::int AS c FROM devices WHERE user_id = $1 AND status = 'active'",
      [Number(targetScopeId)],
    );
    affectedDevicesCount = dCnt?.c || 0;
  }

  const currentRows = await db.many(
    'SELECT COALESCE(policy_key, key) AS policy_key, value_json, locked FROM policy_entries WHERE scope_type = $1 AND scope_id = $2',
    [scopeType, targetScopeId],
  );
  const currentMap = new Map(currentRows.map((r) => [r.policy_key, r]));
  const defaults = getServerDefaults('workspace');

  const diff = entries.map((item) => {
    const pKey = item.policy_key || item.key;
    const spec = validatePolicyEntry(pKey, item.value);
    const existing = currentMap.get(pKey);
    const previousValue = existing ? existing.value_json : defaults[pKey];
    return {
      key: pKey,
      policy_key: pKey,
      previous_value: previousValue,
      new_value: item.value,
      locked: Boolean(item.locked),
      compliance_managed: Boolean(spec.compliance_managed),
      description_ar: spec.description_ar,
    };
  });

  return {
    scope_type: scopeType,
    scope_id: targetScopeId,
    affected_users_count: affectedUsersCount,
    affected_devices_count: affectedDevicesCount,
    changes: diff,
  };
}

/**
 * Applies a predefined policy preset (standard, regulated, defense) to a workspace.
 */
export async function applyPolicyPreset(workspaceId, preset = 'standard', updatedBy = null, client = db) {
  const exec = client.query.bind(client);
  if (preset !== 'regulated' && preset !== 'defense') {
    return;
  }

  const presetEntries = [
    ['auth.mfa_required', 'all', true],
    ['dlp.allow_copy_paste', false, true],
    ['dlp.allow_external_share', false, true],
    ['dlp.allow_screenshot', false, true],
    ['dlp.watermark_enabled', true, true],
    ['dlp.require_biometric_unlock', true, true],
    ['chat.allow_external_guests', false, true],
  ];

  if (preset === 'defense') {
    presetEntries.push(
      ['device.require_attestation', true, true],
      ['device.max_per_user', 1, true],
      ['chat.allow_message_delete', 'none', true],
      ['chat.allow_voice_notes', false, true],
    );
  }

  for (const [k, v, locked] of presetEntries) {
    await exec(
      `INSERT INTO policy_entries (
         workspace_id, scope_type, scope_id, key, policy_key, value_json, locked, updated_by
       ) VALUES ($1, 'workspace', $2, $3, $3, $4::jsonb, $5, $6)
       ON CONFLICT (workspace_id, scope_type, scope_id, key) DO UPDATE
       SET value_json = EXCLUDED.value_json, locked = EXCLUDED.locked, updated_at = NOW()`,
      [workspaceId, String(workspaceId), k, JSON.stringify(v), locked, updatedBy],
    );
  }
}


