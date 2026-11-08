import pg from 'pg';
import { env } from '../config/env.js';
import { logger } from '../lib/logger.js';

const { Pool, Client, types } = pg;

// Return BIGINT/COUNT as JS numbers (ids and counts stay within safe range for this app).
types.setTypeParser(20, (v) => (v === null ? null : Number(v)));

let pool = null;

function parseUrl(url) {
  const u = new URL(url);
  const isLocal = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === 'postgres';
  const sslParam = u.searchParams.get('sslmode') || u.searchParams.get('ssl');
  const useSsl = !isLocal || sslParam === 'require' || sslParam === 'true';
  return {
    host: u.hostname,
    port: u.port ? parseInt(u.port, 10) : 5432,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: u.pathname.replace(/^\//, ''),
    ssl: useSsl ? { rejectUnauthorized: false } : false,
  };
}

/** Creates the application database if it does not exist yet. */
export async function ensureDatabase() {
  const target = parseUrl(env.DATABASE_URL);

  // 1. If target database is already reachable, nothing to create
  try {
    const testClient = new Client({ ...target });
    await testClient.connect();
    await testClient.end();
    return;
  } catch (err) {
    logger.info({ err: err.message }, 'target database not directly reachable yet; attempting to create via admin connection');
  }

  // 2. Try creating via default "postgres" database
  try {
    const admin = new Client({ ...target, database: 'postgres' });
    await admin.connect();
    try {
      const { rows } = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [target.database]);
      if (rows.length === 0) {
        logger.info({ database: target.database }, 'creating database');
        await admin.query(`CREATE DATABASE "${target.database.replace(/"/g, '""')}"`);
      }
    } finally {
      await admin.end();
    }
  } catch (err) {
    logger.warn({ err: err.message }, 'could not auto-create database via admin connection; continuing with target database');
  }
}

export function getPool() {
  if (!pool) {
    const target = parseUrl(env.DATABASE_URL);
    pool = new Pool({
      ...target,
      max: env.DB_POOL_MAX,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });
    pool.on('error', (err) => logger.error({ err }, 'idle postgres client error'));
  }
  return pool;
}

export const db = {
  query: (text, params) => getPool().query(text, params),
  async one(text, params) {
    const { rows } = await getPool().query(text, params);
    return rows[0] ?? null;
  },
  async many(text, params) {
    const { rows } = await getPool().query(text, params);
    return rows;
  },
  async tx(fn) {
    const client = await getPool().connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  },
  async healthcheck() {
    try {
      await getPool().query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  },
};

export async function closePool() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
