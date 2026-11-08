import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { env } from './config/env.js';
import { logger, requestLoggerMiddleware } from './lib/logger.js';
import { errorHandler, notFound, tooMany } from './lib/errors.js';
import { authRouter } from './routes/auth.js';
import { usersRouter } from './routes/users.js';
import { threadsRouter } from './routes/threads.js';
import { callsRouter } from './routes/calls.js';
import { keysRouter } from './routes/keys.js';
import { mediaRouter } from './routes/media.js';
import { registerPersonalExtensions } from './core/extensionRegistry.js';
import { getDiscoveryPayload, handleEnrollment } from './routes/workspace_auth.js';
import { policyRouter } from './routes/policy.js';
import { devicesRouter } from './routes/devices.js';
import { directoryRouter, presenceRouter } from './routes/directory.js';
import { broadcastsRouter } from './routes/broadcasts.js';
import { hubRouter } from './routes/hub.js';
import { searchRouter } from './routes/search.js';
import { channelsRouter, decisionsRouter, followupsRouter } from './routes/channels.js';
import { adminRouter } from './routes/admin.js';
import { relayRouter } from './routes/relay.js';
import { controlPlaneGuard } from './middleware/controlPlaneGuard.js';
import { hub } from './realtime/hub.js';
import { sniffContentType } from './lib/media.js';

function allowedOrigin(origin) {
  if (!env.IS_PROD || !origin) return true;
  if (env.CORS_ORIGINS.includes(origin)) return true;
  try {
    return origin === new URL(env.PUBLIC_URL).origin;
  } catch {
    return false;
  }
}

export function createApp() {
  const app = express();
  app.set('trust proxy', env.TRUST_PROXY);
  app.disable('x-powered-by');

  app.use(
    helmet({
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      contentSecurityPolicy: false,
    }),
  );
  app.use(cors({ origin: (origin, callback) => callback(null, allowedOrigin(origin)) }));
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));
  app.use(requestLoggerMiddleware());

  // Sovereign Workspace Discovery Document (ENR-01)
  app.get('/.well-known/madar-workspace.json', getDiscoveryPayload);

  // Uploaded media. Served with long cache headers since filenames are content-unique UUIDs.
  app.use('/media', express.static(env.UPLOAD_DIR, {
    maxAge: '30d',
    immutable: true,
    index: false,
    dotfiles: 'deny',
    setHeaders(res, filePath) {
      const sniffed = sniffContentType(filePath);
      if (sniffed) res.setHeader('Content-Type', sniffed);
    },
  }));

  app.get('/health', (_req, res) => {
    const body = {
      status: 'ok',
      service: 'madar-server',
      version: '2.0.0',
      deployment_profile: process.env.DEPLOYMENT_PROFILE || env.DEPLOYMENT_PROFILE,
      admin_plane_enabled: Boolean(
        ['1', 'true', 'yes'].includes(String(process.env.ADMIN_API_ENABLED ?? env.ADMIN_API_ENABLED).toLowerCase()),
      ),
      time: new Date().toISOString(),
    };
    if (!env.IS_PROD) {
      body.environment = env.NODE_ENV;
      body.online_users = hub.onlineIds().length;
      body.r2_enabled = env.R2_ENABLED;
      body.api_domain = env.API_CUSTOM_DOMAIN || null;
      body.cdn_domain = env.CDN_CUSTOM_DOMAIN || env.R2_PUBLIC_URL || null;
    }
    res.json(body);
  });

  const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: env.IS_TEST ? 10_000 : 300,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_req, _res, next) => next(tooMany('rate_limited', 'Too many requests. Try again later.')),
  });

  const api = express.Router();
  api.use(apiLimiter);

  // Core Shared & Workspace Routers
  api.get('/workspace/public-info', getDiscoveryPayload);
  api.get('/server/info', getDiscoveryPayload);
  api.post(['/enroll', '/enroll/exchange'], handleEnrollment);
  api.use('/auth', authRouter);
  api.use('/users', usersRouter);
  api.use('/threads', threadsRouter);
  api.use('/calls', callsRouter);
  api.use('/keys', keysRouter);
  api.use('/media', mediaRouter);
  api.use('/policy', policyRouter);
  api.use('/devices', devicesRouter);
  api.use('/directory', directoryRouter);
  api.use('/presence', presenceRouter);
  api.use('/broadcasts', broadcastsRouter);
  api.use('/hub', hubRouter);
  api.use('/search', searchRouter);
  api.use('/channels', channelsRouter);
  api.use('/decisions', decisionsRouter);
  api.use('/followups', followupsRouter);
  api.use('/relay', relayRouter);

  // Control Plane API (Protected by controlPlaneGuard; consumed by isolated madar_admin_console BFF & madarctl)
  api.use('/admin', controlPlaneGuard, adminRouter);

  // Personal Profile Extension Routers are isolated & return 404 in self-hosted workspace mode
  registerPersonalExtensions(api);

  app.use(env.API_PREFIX, api);
  app.use('/v1', relayRouter);

  app.use((req, _res, next) => next(notFound('route_not_found', `No route for ${req.method} ${req.path}`)));
  app.use(errorHandler(logger));
  return app;
}
