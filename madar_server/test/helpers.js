import WebSocket from 'ws';
import { db } from '../src/db/pool.js';
import { signAccessToken, newRefreshToken, sha256 } from '../src/lib/tokens.js';

export function api(base, prefix) {
  const call = async (method, path, { token, body, form } = {}) => {
    const headers = {};
    if (token) headers.authorization = `Bearer ${token}`;
    let payload;
    if (form) payload = form;
    else if (body !== undefined) {
      headers['content-type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    const res = await fetch(`${base}${prefix}${path}`, { method, headers, body: payload });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, json };
  };
  return {
    get: (p, o) => call('GET', p, o),
    post: (p, o) => call('POST', p, o),
    patch: (p, o) => call('PATCH', p, o),
    del: (p, o) => call('DELETE', p, o),
  };
}

export async function login(client, phone, name) {
  let user = await db.one('SELECT * FROM users WHERE phone = $1', [phone]);
  let isNew = false;
  if (!user) {
    isNew = true;
    user = await db.one(
      `INSERT INTO users (phone, name, profile_type, account_status)
       VALUES ($1, $2, 'workspace', 'active')
       RETURNING *`,
      [phone, name || 'Employee'],
    );
  }
  const refresh = newRefreshToken();
  const sessionId = crypto.randomUUID();
  const session = await db.one(
    `INSERT INTO sessions (id, user_id, refresh_token_hash, device_name, expires_at)
     VALUES ($1, $2, $3, 'test', NOW() + INTERVAL '30 days')
     RETURNING id`,
    [sessionId, user.id, sha256(refresh)],
  );
  const token = signAccessToken(user, session.id);
  if (name) {
    const form = new FormData();
    form.append('name', name);
    form.append('note', `I am ${name}`);
    await client.patch('/users/me', { token, form });
  }
  return { token, refresh, user: { id: user.id, phone: user.phone, name: user.name }, isNew };
}

/** Tiny WS client that buffers frames and lets tests await a frame of a given type. */
export function connectWs(wsBase, token) {
  const ws = new WebSocket(`${wsBase}/ws?token=${encodeURIComponent(token)}`);
  const frames = [];
  const waiters = [];
  ws.on('message', (raw) => {
    const frame = JSON.parse(raw.toString());
    const idx = waiters.findIndex((w) => w.pred(frame));
    if (idx >= 0) {
      const [w] = waiters.splice(idx, 1);
      clearTimeout(w.timer);
      w.resolve(frame);
      return;
    }
    frames.push(frame);
  });
  const ready = new Promise((resolve, reject) => {
    ws.once('open', resolve);
    ws.once('error', reject);
  });
  return {
    ws,
    ready,
    frames,
    send: (frame) => ws.send(JSON.stringify(frame)),
    next(type, timeoutMs = 4000) {
      const pred = (f) => f.t === type;
      const existing = frames.findIndex(pred);
      if (existing >= 0) return Promise.resolve(frames.splice(existing, 1)[0]);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timeout waiting for ${type}`)), timeoutMs);
        waiters.push({ pred, resolve, timer });
      });
    },
    close: () => new Promise((resolve) => { ws.once('close', resolve); ws.close(); }),
  };
}

export const wait = (ms) => new Promise((r) => setTimeout(r, ms));

/** 1x1 PNG. */
export const PNG_BYTES = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
);
