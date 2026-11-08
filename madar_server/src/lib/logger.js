import pino from 'pino';
import { env } from '../config/env.js';

let transport;
if (env.LOG_ENABLE && env.IS_DEV && !env.IS_TEST) {
  try {
    await import('pino-pretty');
    transport = {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'yyyy-mm-dd HH:MM:ss',
        ignore: 'pid,hostname',
      },
    };
  } catch {
    transport = undefined;
  }
}

if (!env.LOG_ENABLE) {
  const noop = () => {};
  console.log = noop;
  console.info = noop;
  console.debug = noop;
  console.warn = noop;
  console.error = noop;
}

export const logger = pino({
  level: env.LOG_ENABLE ? (env.LOG_LEVEL || (env.IS_TEST ? 'warn' : 'info')) : 'silent',
  transport: env.LOG_ENABLE ? transport : undefined,
});

/**
 * Mask sensitive data keys in objects before logging (passwords, tokens, secrets).
 */
export function maskSensitive(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(maskSensitive);

  const sensitiveKeys = [
    'password', 'token', 'access_token', 'refresh_token', 'secret', 'turn_secret', 'authorization',
    'code', 'dev_code', 'otp', 'session_info', 'play_integrity_token', 'recaptcha_token', 'ios_secret', 'ios_receipt',
  ];
  const masked = {};
  for (const [key, val] of Object.entries(obj)) {
    if (sensitiveKeys.includes(key.toLowerCase())) {
      masked[key] = typeof val === 'string' && val.length > 8 ? `${val.slice(0, 4)}***${val.slice(-4)}` : '***';
    } else if (typeof val === 'object' && val !== null) {
      masked[key] = maskSensitive(val);
    } else {
      masked[key] = val;
    }
  }
  return masked;
}

/**
 * Dev-only logger functions formatted in English for Windows console compatibility.
 */
logger.dev = (tag, message, data) => {
  if (!env.LOG_ENABLE) return;
  const dataStr = data !== undefined ? ` | Data: ${JSON.stringify(maskSensitive(data))}` : '';
  logger.info(`[DEV][${tag}] ${message}${dataStr}`);
};

logger.devWarn = (tag, message, data) => {
  if (!env.LOG_ENABLE) return;
  const dataStr = data !== undefined ? ` | Data: ${JSON.stringify(maskSensitive(data))}` : '';
  logger.warn(`[DEV][WARN][${tag}] ${message}${dataStr}`);
};

logger.devError = (tag, message, error) => {
  if (!env.LOG_ENABLE) return;
  const errDetails = error?.stack || error?.message || (typeof error === 'object' ? JSON.stringify(error) : error) || '';
  logger.error(`[ERROR][${tag}] ${message}${errDetails ? ` | Details: ${errDetails}` : ''}`);
};

/**
 * Express middleware to trace all incoming HTTP requests and responses.
 */
export function requestLoggerMiddleware() {
  return (req, res, next) => {
    if (!env.LOG_ENABLE) return next();

    const start = Date.now();
    const url = req.originalUrl || req.url;
    const method = req.method;

    // Log incoming request
    const bodyInfo = req.body && Object.keys(req.body).length > 0
      ? ` | Body: ${JSON.stringify(maskSensitive(req.body))}`
      : '';
    const queryInfo = req.query && Object.keys(req.query).length > 0
      ? ` | Query: ${JSON.stringify(maskSensitive(req.query))}`
      : '';

    logger.info(`--> [HTTP REQ] ${method} ${url}${queryInfo}${bodyInfo}`);

    // Capture response status on finish
    res.on('finish', () => {
      const duration = Date.now() - start;
      const status = res.statusCode;
      const statusLabel = status >= 500 ? 'SERVER ERROR' : status >= 400 ? 'CLIENT ERROR' : 'OK';

      if (status >= 400) {
        logger.warn(`<-- [HTTP RES] ${status} ${statusLabel} ${method} ${url} (${duration}ms)`);
      } else {
        logger.info(`<-- [HTTP RES] ${status} ${statusLabel} ${method} ${url} (${duration}ms)`);
      }
    });

    next();
  };
}
