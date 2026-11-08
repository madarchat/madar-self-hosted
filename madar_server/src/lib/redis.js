import Redis from 'ioredis';
import { env } from '../config/env.js';
import { logger } from './logger.js';

/** @type {Redis | null} */
export let redis = null;

/** @type {Redis | null} */
export let redisSub = null;

if (env.REDIS_URL && !env.IS_TEST) {
  try {
    redis = new Redis(env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: false,
    });
    redisSub = new Redis(env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: false,
    });

    redis.on('connect', () => logger.info('redis: connected to Upstash/Redis primary'));
    redis.on('error', (err) => logger.warn({ err: err.message }, 'redis: client error'));
    redisSub.on('error', (err) => logger.warn({ err: err.message }, 'redis: subscriber error'));
  } catch (err) {
    logger.warn({ err: err.message }, 'redis: failed to initialize, falling back to in-memory');
    redis = null;
    redisSub = null;
  }
}

export async function closeRedis() {
  await Promise.allSettled([
    redis ? redis.quit() : Promise.resolve(),
    redisSub ? redisSub.quit() : Promise.resolve(),
  ]);
}
