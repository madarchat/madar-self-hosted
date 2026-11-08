import crypto from 'node:crypto';
import { env, icePublicHost } from '../config/env.js';
import { logger } from '../lib/logger.js';

/**
 * Builds the RTCConfiguration.iceServers list for a user.
 *
 * - Primary (Cloud Edition): Cloudflare Realtime TURN (`CF_TURN_KEY_ID` + `CF_TURN_API_TOKEN`)
 *   which generates ephemeral global Anycast STUN + TURN credentials (UDP 3478, TCP 3478, TLS 5349).
 * - Fallback: Self-hosted STUN (served by this process) and optional Coturn (`TURN_SECRET`).
 */
export async function buildIceConfig(userId) {
  const host = icePublicHost();
  const iceServers = [];

  if (env.STUN_ENABLED) {
    iceServers.push({ urls: [`stun:${host}:${env.STUN_PORT}`] });
  }

  let turnExpiresAt = null;
  const ttl = env.TURN_CREDENTIAL_TTL_SECONDS || 86400;

  if (!env.IS_TEST && env.CF_TURN_KEY_ID && env.CF_TURN_API_TOKEN) {
    try {
      const res = await fetch(
        `https://rtc.live.cloudflare.com/v1/turn/keys/${env.CF_TURN_KEY_ID}/credentials/generate`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${env.CF_TURN_API_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ ttl }),
        },
      );
      if (res.ok) {
        const data = await res.json();
        if (data?.iceServers) {
          const cfEntries = Array.isArray(data.iceServers) ? data.iceServers : [data.iceServers];
          iceServers.push(...cfEntries);
          turnExpiresAt = new Date(Date.now() + ttl * 1000).toISOString();
        }
      } else {
        logger.warn({ status: res.status }, 'Cloudflare TURN credential generation returned non-OK status');
      }
    } catch (err) {
      logger.warn({ err: err.message }, 'Cloudflare TURN credential request failed, using fallback ICE');
    }
  } else if (env.TURN_ENABLED && env.TURN_SECRET) {
    const expiry = Math.floor(Date.now() / 1000) + ttl;
    const username = `${expiry}:${userId}`;
    const credential = crypto.createHmac('sha1', env.TURN_SECRET).update(username).digest('base64');
    iceServers.push({
      urls: [`turn:${host}:${env.TURN_PORT}?transport=udp`, `turn:${host}:${env.TURN_PORT}?transport=tcp`],
      username,
      credential,
    });
    turnExpiresAt = new Date(expiry * 1000).toISOString();
  }

  return {
    ice_servers: iceServers,
    ice_transport_policy: 'all',
    turn_expires_at: turnExpiresAt,
    ring_timeout_ms: env.CALL_RING_TIMEOUT_MS,
  };
}
