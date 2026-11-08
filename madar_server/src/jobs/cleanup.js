import { db } from '../db/pool.js';
import { logger } from '../lib/logger.js';
import { syncAuthProviderById } from '../routes/admin.js';

async function syncDueAuthProviders() {
  const due = await db.many(
    `SELECT id FROM auth_providers
     WHERE enabled = TRUE
       AND kind IN ('ldap', 'oidc', 'saml')
       AND (
         last_synced_at IS NULL
         OR last_synced_at < NOW() - (sync_interval_minutes || ' minutes')::interval
       )`,
  );
  for (const p of due) {
    await syncAuthProviderById(p.id).catch((err) =>
      logger.warn({ err: err.message, providerId: p.id }, 'periodic directory sync failed'),
    );
  }
}

async function purgeAuthCodes() {
  await db.query(`DELETE FROM auth_codes WHERE created_at < NOW() - INTERVAL '1 day'`);
}

async function purgeSessions() {
  await db.query(`DELETE FROM sessions WHERE expires_at < NOW() - INTERVAL '7 days' OR revoked_at < NOW() - INTERVAL '7 days'`);
}

async function staleRingingCalls() {
  await db.query(`UPDATE calls SET status = 'missed', ended_at = NOW(), end_reason = 'stale'
                  WHERE status = 'ringing' AND started_at < NOW() - INTERVAL '5 minutes'`);
}

export function startCleanupJobs() {
  const run = () =>
    Promise.allSettled([
      purgeAuthCodes(),
      purgeSessions(),
      staleRingingCalls(),
      syncDueAuthProviders(),
    ]).then((results) => {
      for (const r of results) if (r.status === 'rejected') logger.warn({ err: r.reason?.message }, 'cleanup task failed');
    });
  run();
  const timer = setInterval(run, 60_000);
  timer.unref();
  return () => clearInterval(timer);
}
