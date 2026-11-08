import http from 'node:http';
import { env, assertEnv } from './config/env.js';
import { logger } from './lib/logger.js';
import { runMigrations } from './db/migrate.js';
import { closePool } from './db/pool.js';
import { closeRedis } from './lib/redis.js';
import { createApp } from './app.js';
import { initRealtime } from './realtime/ws.js';
import { cleanupOrphanedCallsOnBoot } from './realtime/calls.js';
import { startStunServer } from './stun/server.js';
import { startCleanupJobs } from './jobs/cleanup.js';
import { initPush } from './services/push.js';

export async function startServer({ port = env.PORT, host = env.HOST, stun = env.STUN_ENABLED } = {}) {
  assertEnv();
  await runMigrations();
  await cleanupOrphanedCallsOnBoot();
  await initPush();

  const app = createApp();
  const server = http.createServer(app);
  const wss = initRealtime(server);
  const stopCleanup = startCleanupJobs();
  const stunServer = stun ? await startStunServer(env.STUN_PORT) : null;

  await new Promise((resolve) => server.listen(port, host, resolve));
  const address = server.address();
  logger.info(
    { url: env.PUBLIC_URL, port: address.port, api: env.API_PREFIX, ws: '/ws', stun: stun ? env.STUN_PORT : 'off', env: env.NODE_ENV },
    'madar-server ready',
  );

  const close = async () => {
    stopCleanup();
    stunServer?.close();
    for (const ws of wss.clients) ws.terminate();
    wss.close();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await closePool();
    await closeRedis();
  };
  return { app, server, wss, port: address.port, close };
}

const isMain =
  Boolean(process.env.PM2_HOME || process.env.pm_id !== undefined) ||
  (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop()));
if (isMain) {
  startServer()
    .then(({ close }) => {
      const shutdown = async (signal) => {
        logger.info({ signal }, 'shutting down');
        await close();
        process.exit(0);
      };
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
      process.on('unhandledRejection', (err) => {
        logger.fatal({ err }, 'unhandled rejection');
        if (env.IS_PROD) process.exit(1);
      });
      process.on('uncaughtException', (err) => {
        logger.fatal({ err }, 'uncaught exception');
        process.exit(1);
      });
    })
    .catch((err) => {
      logger.fatal({ err }, 'startup failed');
      process.exit(1);
    });
}
