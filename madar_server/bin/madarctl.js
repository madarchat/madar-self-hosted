#!/usr/bin/env node
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { db } from '../src/db/pool.js';
import { env } from '../src/config/env.js';
import {
  ensureDefaultWorkspace,
  loadPolicyCatalog,
  applyPolicyPreset,
} from '../src/services/policyEngine.js';
import {
  ensureWorkspaceSigningKey,
  rotateWorkspaceSigningKey,
  signEd25519Jws,
} from '../src/lib/jws.js';
import { verifyAuditChain, appendAuditLog } from '../src/lib/audit.js';
import { hashPassword } from '../src/lib/password.js';
import { sha256 } from '../src/lib/tokens.js';

/**
 * Programmatic runner for madarctl CLI (Section 13.7, ADM-10).
 */
export async function runMadarCtl(rawArgs = []) {
  const args = [...rawArgs];
  const cmd = args[0] || 'help';
  const sub = args[1] || '';

  if (cmd === 'doctor') {
    const dbOk = await db.healthcheck();
    const ws = dbOk ? await ensureDefaultWorkspace() : null;
    const key = ws ? await ensureWorkspaceSigningKey(ws.id) : null;
    const audit = ws ? await verifyAuditChain(ws.id) : { valid: false, checkedCount: 0 };
    const catalog = loadPolicyCatalog();
    return {
      command: 'doctor',
      ok: Boolean(dbOk && ws && key && audit.valid),
      database_connected: dbOk,
      workspace_id: ws?.id || null,
      workspace_name: ws?.name || null,
      signing_key_kid: key?.kid || null,
      policy_catalog_keys: Object.keys(catalog.keys || {}).length,
      audit_chain_valid: audit.valid,
      audit_entries_checked: audit.checkedCount,
      admin_api_enabled: env.ADMIN_API_ENABLED !== false,
    };
  }

  if (cmd === 'verify-audit' || (cmd === 'audit' && sub === 'verify')) {
    const ws = await ensureDefaultWorkspace();
    const verification = await verifyAuditChain(ws.id);
    return {
      command: 'audit verify',
      workspace_id: ws.id,
      ...verification,
    };
  }

  if (cmd === 'policy-list' || (cmd === 'policy' && sub === 'list')) {
    const ws = await ensureDefaultWorkspace();
    const catalog = loadPolicyCatalog();
    const overrides = await db.many(
      'SELECT scope_type, scope_id, key, value_json, locked FROM policy_entries WHERE workspace_id = $1 ORDER BY key ASC',
      [ws.id],
    );
    return {
      command: 'policy list',
      workspace_id: ws.id,
      catalog_count: Object.keys(catalog.keys || {}).length,
      overrides_count: overrides.length,
      overrides,
    };
  }

  if (cmd === 'rotate-keys' || (cmd === 'keys' && sub === 'rotate')) {
    const ws = await ensureDefaultWorkspace();
    const rotated = await rotateWorkspaceSigningKey(ws.id);
    await appendAuditLog({
      workspaceId: ws.id,
      actorUserId: null,
      action: 'signing_key.rotated.cli',
      targetType: 'workspace',
      targetId: ws.id,
      metadata: { kid: rotated.kid, public_key_ed25519: rotated.publicKeyEd25519 },
    });
    return {
      command: 'rotate-keys',
      workspace_id: ws.id,
      ...rotated,
    };
  }

  if (cmd === 'issue-enrollment') {
    const ws = await ensureDefaultWorkspace();
    const signingKey = await ensureWorkspaceSigningKey(ws.id);
    const maxUses = Number(args[1] || 5);
    const expiresHours = Number(args[2] || 72);
    const rawToken = `MADAR-ENR-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
    const tokenHash = sha256(rawToken);
    const expiresAt = new Date(Date.now() + expiresHours * 3_600_000);

    const jwsCompact = signEd25519Jws(
      {
        typ: 'madar.enrollment.v1',
        workspace_id: ws.id,
        token_hash: tokenHash,
        max_uses: maxUses,
        exp: Math.floor(expiresAt.getTime() / 1000),
      },
      signingKey.privateKeyPem,
      signingKey.kid,
    );

    const row = await db.one(
      `INSERT INTO enrollment_tokens (
         workspace_id, token_hash, jws_compact, max_uses, expires_at
       ) VALUES ($1, $2, $3, $4, $5)
       RETURNING id, max_uses, expires_at`,
      [ws.id, tokenHash, jwsCompact, maxUses, expiresAt],
    );

    const serverUrl = env.PUBLIC_URL || `http://localhost:${env.PORT}`;
    const qrUri = `madar://enroll?server=${encodeURIComponent(serverUrl)}&token=${encodeURIComponent(rawToken)}`;

    return {
      command: 'issue-enrollment',
      workspace_id: ws.id,
      enrollment_token: rawToken,
      qr_uri: qrUri,
      record: row,
    };
  }

  if (cmd === 'health') {
    const dbOk = await db.healthcheck();
    const ws = dbOk ? await ensureDefaultWorkspace() : null;
    return {
      command: 'health',
      status: dbOk ? 'ok' : 'degraded',
      database_connected: dbOk,
      workspace_id: ws?.id || null,
      setup_completed: Boolean(ws?.setup_completed),
    };
  }

  if (cmd === 'bootstrap' || cmd === 'setup' || cmd === 'init-workspace') {
    const ws = await ensureDefaultWorkspace();
    const signingKey = await ensureWorkspaceSigningKey(ws.id);
    const getFlag = (flag, fallback) => {
      const idx = args.indexOf(flag);
      return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
    };
    const preset = getFlag('--preset', args[1] && !args[1].startsWith('--') ? args[1] : 'standard');
    const name = getFlag('--name', ws.name);
    const adminUser = getFlag('--admin-user', null);
    const adminEmail = getFlag('--admin-email', null);
    const adminPass = getFlag('--admin-password', null);

    await applyPolicyPreset(ws.id, preset, null);
    await db.query(
      'UPDATE workspace SET name = $2, setup_completed = TRUE, policy_signing_pub = $3 WHERE id = $1',
      [ws.id, name, signingKey.publicKeyEd25519],
    );

    if (adminUser && adminPass) {
      const u = await db.one(
        `INSERT INTO users (workspace_id, employee_no, email, name, title, account_status, profile_type, last_seen_at)
         VALUES ($1, $2, $3, $4, 'SUPER_ADMIN', 'active', 'workspace', NOW())
         ON CONFLICT (workspace_id, employee_no) DO UPDATE SET email = EXCLUDED.email, account_status = 'active'
         RETURNING id, employee_no, email`,
        [ws.id, adminUser, adminEmail || `${adminUser.toLowerCase()}@madar.local`, adminUser],
      );
      await db.query(
        `INSERT INTO credentials (user_id, password_hash, must_change_password, password_changed_at)
         VALUES ($1, $2, FALSE, NOW())
         ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
        [u.id, hashPassword(adminPass)],
      );
      await db.query(
        "INSERT INTO user_roles (user_id, role) VALUES ($1, 'SUPER_ADMIN') ON CONFLICT DO NOTHING",
        [u.id],
      );
    }

    return {
      command: cmd,
      workspace_id: ws.id,
      workspace_name: name,
      preset,
      kid: signingKey.kid,
      public_key_ed25519: signingKey.publicKeyEd25519,
    };
  }

  return {
    command: 'help',
    available_commands: [
      'health',
      'doctor',
      'audit verify (or verify-audit)',
      'policy list (or policy-list)',
      'rotate-keys',
      'issue-enrollment [max_uses] [expires_hours]',
      'bootstrap [standard|regulated|defense]',
      'init-workspace [--name <name>] [--admin-user <id>] [--admin-email <email>] [--admin-password <pw>] [--preset <preset>]',
    ],
  };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  runMadarCtl(process.argv.slice(2))
    .then((res) => {
      console.log(JSON.stringify(res, null, 2));
      process.exit(0);
    })
    .catch((err) => {
      console.error('madarctl error:', err.message);
      process.exit(1);
    });
}
