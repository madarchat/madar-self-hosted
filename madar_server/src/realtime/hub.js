import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { logger } from '../lib/logger.js';
import { redis, redisSub } from '../lib/redis.js';

const NODE_ID = crypto.randomUUID();
const PUBSUB_CHANNEL = 'madar:ws:fanout';
const ONLINE_SET_KEY = 'madar:online';

/**
 * Connection hub. Tracks every live socket per user (a user may have several devices),
 * answers presence questions and fans out server→client events across nodes via Redis Pub/Sub.
 */
class Hub extends EventEmitter {
  constructor() {
    super();
    /** @type {Map<number, Set<import('ws').WebSocket>>} */
    this.sockets = new Map();

    if (redisSub) {
      redisSub.subscribe(PUBSUB_CHANNEL).catch((err) => {
        logger.warn({ err: err.message }, 'redis: failed to subscribe to fanout channel');
      });
      redisSub.on('message', (channel, message) => {
        if (channel !== PUBSUB_CHANNEL) return;
        try {
          const pkt = JSON.parse(message);
          if (!pkt || pkt.nodeId === NODE_ID) return;
          if (pkt.userId) {
            this._sendLocal(pkt.userId, pkt.type, pkt.payload);
          } else if (Array.isArray(pkt.userIds)) {
            for (const id of pkt.userIds) this._sendLocal(id, pkt.type, pkt.payload);
          }
        } catch (err) {
          logger.warn({ err: err.message }, 'redis: invalid fanout packet');
        }
      });
    }
  }

  add(userId, ws) {
    let set = this.sockets.get(userId);
    const wasOnline = !!set && set.size > 0;
    if (!set) {
      set = new Set();
      this.sockets.set(userId, set);
    }
    set.add(ws);
    if (!wasOnline) {
      if (redis) redis.sadd(ONLINE_SET_KEY, String(userId)).catch(() => {});
      this.emit('online', userId);
    }
  }

  remove(userId, ws) {
    const set = this.sockets.get(userId);
    if (!set) return;
    set.delete(ws);
    if (set.size === 0) {
      this.sockets.delete(userId);
      if (redis) redis.srem(ONLINE_SET_KEY, String(userId)).catch(() => {});
      this.emit('offline', userId);
    }
  }

  isOnline(userId) {
    const set = this.sockets.get(Number(userId));
    return !!set && set.size > 0;
  }

  onlineIds() {
    return [...this.sockets.keys()];
  }

  _sendLocal(userId, type, payload = {}) {
    const set = this.sockets.get(Number(userId));
    if (!set) return 0;
    const frame = JSON.stringify({ t: type, ...payload, ts: Date.now() });
    let n = 0;
    for (const ws of set) {
      if (ws.readyState === ws.OPEN) {
        try {
          ws.send(frame);
          n++;
        } catch (err) {
          logger.warn({ err: err.message, userId }, 'ws send failed');
        }
      }
    }
    return n;
  }

  /** Sends an event to every device of a user (locally and across Redis Pub/Sub nodes). */
  send(userId, type, payload = {}) {
    const n = this._sendLocal(userId, type, payload);
    if (redis) {
      redis
        .publish(PUBSUB_CHANNEL, JSON.stringify({ nodeId: NODE_ID, userId: Number(userId), type, payload }))
        .catch(() => {});
    }
    return n;
  }

  sendMany(userIds, type, payload) {
    const uniqueIds = [...new Set(userIds.map(Number))];
    let n = 0;
    for (const id of uniqueIds) n += this._sendLocal(id, type, payload);
    if (redis && uniqueIds.length > 0) {
      redis
        .publish(PUBSUB_CHANNEL, JSON.stringify({ nodeId: NODE_ID, userIds: uniqueIds, type, payload }))
        .catch(() => {});
    }
    return n;
  }

  broadcast(type, payload, { except } = {}) {
    for (const id of this.sockets.keys()) {
      if (id !== except) this._sendLocal(id, type, payload);
    }
  }
}

export const hub = new Hub();
