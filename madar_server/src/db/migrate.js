import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureDatabase, getPool, closePool } from './pool.js';
import { logger } from '../lib/logger.js';
import { normalizePhone } from '../lib/phone.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

export async function runMigrations() {
  await ensureDatabase();
  const pool = getPool();

  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.schema_migrations (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);

  const done = new Set((await pool.query('SELECT name FROM public.schema_migrations')).rows.map((r) => r.name));
  const files = fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql')).sort();

  for (const file of files) {
    if (done.has(file)) continue;
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO public.schema_migrations (name) VALUES ($1)', [file]);
      await client.query('COMMIT');
      logger.info({ file }, 'migration applied');
    } catch (err) {
      await client.query('ROLLBACK');
      logger.error({ file, err }, 'migration failed');
      throw err;
    } finally {
      client.release();
    }
  }

  await backfillPhoneE164(pool);
}

function maskPhone(phone) {
  const value = String(phone || '');
  if (value.length < 6) return '****';
  return `${value.slice(0, 4)}…${value.slice(-2)}`;
}

/** Fill phone_e164 from numbers already stored. Invalid rows stay NULL and are logged by id. */
async function backfillPhoneE164(pool) {
  const { rows } = await pool.query(
    `SELECT id, phone FROM users WHERE phone_e164 IS NULL AND phone IS NOT NULL`,
  );
  let filled = 0;
  for (const row of rows) {
    const e164 = normalizePhone(row.phone);
    if (!e164) {
      logger.warn({ userId: row.id, phone: maskPhone(row.phone) }, 'phone_e164 left empty');
      continue;
    }
    try {
      const updated = await pool.query(
        `UPDATE users SET phone_e164 = $2 WHERE id = $1 AND phone_e164 IS NULL`,
        [row.id, e164],
      );
      if (updated.rowCount) filled += 1;
    } catch (err) {
      if (err.code === '23505') {
        logger.warn({ userId: row.id, phone: maskPhone(row.phone) }, 'phone_e164 already used by another account');
        continue;
      }
      throw err;
    }
  }
  if (rows.length) logger.info({ checked: rows.length, filled }, 'phone_e164 backfill');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMigrations()
    .then(() => closePool())
    .then(() => logger.info('migrations up to date'))
    .catch((err) => {
      logger.error(err);
      process.exit(1);
    });
}
