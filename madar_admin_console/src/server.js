import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, '../public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
};

function parseCookies(cookieHeader = '') {
  const out = {};
  for (const part of String(cookieHeader).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

function readJsonBody(req, maxBytes = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function setSecurityHeaders(res) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  );
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(payload));
}

/**
 * Creates the isolated Madar Admin Console Control-Plane BFF Server.
 * Zero direct database access: communicates with madar_server strictly via HTTP REST APIs
 * using X-Madar-Control-Plane-Key and manages browser sessions via HttpOnly cookies + CSRF tokens.
 */
export function createAdminConsoleServer(options = {}) {
  const upstreamBaseUrl = (
    options.coreApiUrl ||
    options.upstreamUrl ||
    process.env.MADAR_SERVER_URL ||
    process.env.MADAR_CORE_API_URL ||
    'http://127.0.0.1:5025'
  ).replace(/\/+$/, '');
  const controlPlaneSecret =
    options.controlPlaneSecret ??
    process.env.ADMIN_PLANE_SECRET ??
    process.env.CONTROL_PLANE_KEY ??
    '';
  const sessionTtlMs = options.sessionTtlMs || 8 * 60 * 60 * 1000;

  // Ephemeral AES-256-GCM key to encrypt upstream JWTs at rest in BFF memory
  const memKey = crypto.randomBytes(32);
  /** @type {Map<string, { iv: string, tag: string, ciphertext: string, csrfToken: string, user: object|null, expiresAt: number }>} */
  const sessions = new Map();

  function sealToken(jwt) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', memKey, iv);
    const enc = Buffer.concat([cipher.update(String(jwt), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: enc.toString('base64'),
    };
  }

  function openToken(entry) {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      memKey,
      Buffer.from(entry.iv, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(entry.tag, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(entry.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  }

  function createSession(jwt, user = null) {
    const sid = crypto.randomBytes(24).toString('base64url');
    const csrfToken = crypto.randomBytes(24).toString('base64url');
    const sealed = sealToken(jwt);
    sessions.set(sid, {
      ...sealed,
      csrfToken,
      user,
      expiresAt: Date.now() + sessionTtlMs,
    });
    return { sid, csrfToken };
  }

  function getSession(req) {
    const cookies = parseCookies(req.headers.cookie);
    const sid = cookies.madar_admin_sid;
    if (!sid) return null;
    const entry = sessions.get(sid);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      sessions.delete(sid);
      return null;
    }
    return { sid, ...entry, jwt: openToken(entry) };
  }

  function setSessionCookie(res, sid, maxAgeSec = Math.floor(sessionTtlMs / 1000)) {
    const secureFlag = process.env.COOKIE_SECURE === 'true' ? '; Secure' : '';
    res.setHeader(
      'Set-Cookie',
      `madar_admin_sid=${encodeURIComponent(sid)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secureFlag}`,
    );
  }

  function clearSessionCookie(res) {
    res.setHeader(
      'Set-Cookie',
      'madar_admin_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
    );
  }

  async function forwardToUpstream(method, upstreamPath, bodyObj, jwt) {
    const headers = {
      Accept: 'application/json',
    };
    if (controlPlaneSecret) {
      headers['X-Madar-Control-Plane-Key'] = controlPlaneSecret;
    }
    if (jwt) {
      headers.Authorization = `Bearer ${jwt}`;
    }
    const fetchOpts = { method, headers };
    if (bodyObj !== undefined && method !== 'GET' && method !== 'HEAD') {
      headers['Content-Type'] = 'application/json';
      fetchOpts.body = JSON.stringify(bodyObj);
    }
    const res = await fetch(`${upstreamBaseUrl}${upstreamPath}`, fetchOpts);
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }

  const server = http.createServer(async (req, res) => {
    setSecurityHeaders(res);
    const parsedUrl = new URL(req.url || '/', 'http://localhost');
    const pathname = parsedUrl.pathname;

    try {
      // Health check of the isolated Admin Console BFF
      if ((pathname === '/health' || pathname === '/admin-api/health') && req.method === 'GET') {
        return sendJson(res, 200, {
          status: 'ok',
          service: 'madar-admin-console-bff',
          isolated: true,
          isolated_control_plane: true,
          zero_db_access: true,
          direct_db_access: false,
          upstream_url: upstreamBaseUrl,
        });
      }

      // Check setup status + current BFF session state
      if (pathname === '/admin-api/setup-status' && req.method === 'GET') {
        const discovery = await forwardToUpstream('GET', '/.well-known/madar-workspace.json', undefined, null);
        const session = getSession(req);
        return sendJson(res, 200, {
          setup_completed: Boolean(discovery.data?.setup_completed),
          workspace: discovery.data || null,
          authenticated: Boolean(session),
          csrf_token: session?.csrfToken || null,
          user: session?.user || null,
        });
      }

      // Check current BFF session state
      if (pathname === '/admin-api/session' && req.method === 'GET') {
        const session = getSession(req);
        if (!session) {
          return sendJson(res, 200, { authenticated: false });
        }
        return sendJson(res, 200, {
          authenticated: true,
          csrf_token: session.csrfToken,
          user: session.user,
        });
      }

      // Login via workspace credentials -> exchanges with madar_server and stores JWT in HttpOnly BFF session
      if (pathname === '/admin-api/session/login' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const loginPayload = {
          device_name: 'Madar Admin Console BFF',
          platform: 'web',
          device_pub_key: 'admin-console-bff-session',
          attestation_token: 'admin-console-bff-verified',
          ...body,
        };
        const upstream = await forwardToUpstream('POST', '/api/v1/auth/workspace/login', loginPayload, null);
        if (upstream.status >= 200 && upstream.status < 300 && upstream.data?.access_token) {
          const { sid, csrfToken } = createSession(upstream.data.access_token, upstream.data.user || null);
          setSessionCookie(res, sid);
          const safeResponse = { ...upstream.data };
          delete safeResponse.access_token;
          delete safeResponse.refresh_token;
          return sendJson(res, 200, {
            authenticated: true,
            csrf_token: csrfToken,
            ...safeResponse,
          });
        }
        return sendJson(res, upstream.status, upstream.data);
      }

      // Bind an existing administrative JWT into an HttpOnly BFF session (e.g. from madarctl bootstrap)
      if (pathname === '/admin-api/session/token' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const token = String(body.token || '').trim();
        if (!token) {
          return sendJson(res, 400, {
            error: { code: 'missing_token', message: 'رمز الجلسة مطلوب' },
          });
        }
        const { sid, csrfToken } = createSession(token, body.user || null);
        setSessionCookie(res, sid);
        return sendJson(res, 200, {
          authenticated: true,
          csrf_token: csrfToken,
        });
      }

      // Logout and destroy BFF session
      if (pathname === '/admin-api/session/logout' && req.method === 'POST') {
        const session = getSession(req);
        if (session) {
          sessions.delete(session.sid);
        }
        clearSessionCookie(res);
        return sendJson(res, 200, { authenticated: false });
      }

      // BFF Proxy Gateway to madar_server (/admin-api/proxy/...)
      if (pathname.startsWith('/admin-api/proxy/')) {
        const rawSubpath = pathname.slice('/admin-api/proxy'.length);
        const normalizedSubpath = rawSubpath.startsWith('/api/v1/')
          ? rawSubpath
          : rawSubpath.startsWith('/admin/')
          ? `/api/v1${rawSubpath}`
          : `/api/v1/admin${rawSubpath}`;
        const upstreamPath = normalizedSubpath + parsedUrl.search;
        const session = getSession(req);
        const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method || '');

        // Enforce CSRF validation on mutating requests whenever a session exists
        if (session && isMutating) {
          const csrfHeader = req.headers['x-madar-csrf'] || '';
          if (csrfHeader !== session.csrfToken) {
            return sendJson(res, 403, {
              error: {
                code: 'csrf_validation_failed',
                message: 'فشل التحقق من رمز الحماية CSRF (X-Madar-CSRF)',
              },
            });
          }
        }

        const body = isMutating ? await readJsonBody(req) : undefined;
        const upstream = await forwardToUpstream(
          req.method || 'GET',
          upstreamPath,
          body,
          session?.jwt || null,
        );

        // If Day-0 Setup (/api/v1/admin/setup) returned an initial admin token, bind it into an HttpOnly session automatically
        if (
          upstreamPath.startsWith('/api/v1/admin/setup') &&
          upstream.status >= 200 &&
          upstream.status < 300 &&
          upstream.data?.access_token
        ) {
          const { sid, csrfToken } = createSession(
            upstream.data.access_token,
            upstream.data.admin_user || null,
          );
          setSessionCookie(res, sid);
          const safeData = { ...upstream.data, csrf_token: csrfToken };
          delete safeData.access_token;
          return sendJson(res, upstream.status, safeData);
        }

        return sendJson(res, upstream.status, upstream.data);
      }

      // Serve static files from madar_admin_console/public
      const relPath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      const safePath = path.normalize(relPath).replace(/^(\.\.(\/|\\|$))+/, '');
      const fullPath = path.join(PUBLIC_DIR, safePath);

      if (!fullPath.startsWith(PUBLIC_DIR) || !fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
        return sendJson(res, 404, { error: { code: 'not_found', message: 'المسار غير موجود في لوحة التحكم المعزولة' } });
      }

      const ext = path.extname(fullPath).toLowerCase();
      res.statusCode = 200;
      res.setHeader('Content-Type', MIME_TYPES[ext] || 'application/octet-stream');
      fs.createReadStream(fullPath).pipe(res);
    } catch (err) {
      sendJson(res, 502, {
        error: {
          code: 'bff_gateway_error',
          message: err.message || 'خطأ في بوابة لوحة التحكم المعزولة',
        },
      });
    }
  });

  if (options.port !== undefined) {
    const host = options.host || '127.0.0.1';
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(options.port, host, () => {
        const addr = server.address();
        const actualPort = typeof addr === 'object' && addr ? addr.port : options.port;
        resolve({
          server,
          port: actualPort,
          close: () =>
            new Promise((resClose) => {
              server.close(() => resClose());
            }),
        });
      });
    });
  }

  return server;
}

// Start standalone server if invoked directly
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.ADMIN_CONSOLE_PORT || 4100);
  const host = process.env.ADMIN_CONSOLE_HOST || '127.0.0.1';
  const srv = createAdminConsoleServer();
  srv.listen(port, host, () => {
    console.log(`[madar-admin-console] Isolated Control-Plane BFF listening on http://${host}:${port}`);
  });
}
