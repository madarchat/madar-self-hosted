import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, '../..');

const initialEnv = process.env.APP_ENV || process.env.NODE_ENV;
if (initialEnv === 'production' && fs.existsSync(path.join(ROOT_DIR, '.env.production'))) {
  dotenv.config({ path: path.join(ROOT_DIR, '.env.production'), quiet: true });
}
dotenv.config({ path: path.join(ROOT_DIR, '.env'), quiet: true });

const int = (v, d) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : d;
};
const bool = (v, d) => (v === undefined ? d : ['1', 'true', 'yes'].includes(String(v).toLowerCase()));

const APP_ENV = process.env.APP_ENV || process.env.NODE_ENV || 'development';
const NODE_ENV = process.env.NODE_ENV || APP_ENV;
const PORT = int(process.env.PORT, 5025);

export const env = {
  APP_ENV,
  NODE_ENV,
  IS_DEV: APP_ENV === 'development' || APP_ENV === 'dev',
  IS_PROD: APP_ENV === 'production' || NODE_ENV === 'production',
  IS_TEST: APP_ENV === 'test' || NODE_ENV === 'test',
  PORT,
  HOST: process.env.HOST || '0.0.0.0',
  TRUST_PROXY: process.env.TRUST_PROXY === 'false' ? false : int(process.env.TRUST_PROXY, 1),
  PUBLIC_URL: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
  API_PREFIX: process.env.API_PREFIX || '/api/v1',
  CORS_ORIGINS: (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean),

  DEPLOYMENT_PROFILE: (process.env.DEPLOYMENT_PROFILE || 'workspace').toLowerCase(),
  ADMIN_API_ENABLED: bool(process.env.ADMIN_API_ENABLED, true),
  ADMIN_PLANE_SECRET: process.env.ADMIN_PLANE_SECRET || process.env.CONTROL_PLANE_KEY || '',
  ADMIN_ALLOWED_IPS: process.env.ADMIN_ALLOWED_IPS || '',
  MASTER_ENCRYPTION_KEY:
    process.env.MASTER_ENCRYPTION_KEY ||
    process.env.MADAR_MASTER_KEY ||
    (NODE_ENV === 'production' ? '' : '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
  MASTER_KEY_ID: process.env.MASTER_KEY_ID || 'mk-v1',
  WORKSPACE_DEFAULT_NAME: process.env.WORKSPACE_DEFAULT_NAME || 'مساحة عمل مدار',

  DATABASE_URL:
    process.env.DATABASE_URL ||
    `postgresql://${process.env.DB_USER || 'postgres'}:${process.env.DB_PASSWORD || 'madar-local-change-me'}@${
      process.env.DB_HOST || 'localhost'
    }:${int(process.env.DB_PORT, 5432)}/${process.env.DB_NAME || 'madar'}`,
  DB_POOL_MAX: int(process.env.DB_POOL_MAX, 20),

  JWT_SECRET: process.env.JWT_SECRET || (NODE_ENV === 'production' ? '' : 'madar-dev-secret-change-me'),
  ACCESS_TOKEN_TTL: process.env.ACCESS_TOKEN_TTL || '1h',
  REFRESH_TOKEN_TTL_DAYS: int(process.env.REFRESH_TOKEN_TTL_DAYS, 60),

  OTP_TTL_SECONDS: int(process.env.OTP_TTL_SECONDS, 300),
  OTP_MAX_ATTEMPTS: int(process.env.OTP_MAX_ATTEMPTS, 5),
  OTP_DEV_ECHO: bool(process.env.OTP_DEV_ECHO, NODE_ENV === 'test'),
  OTP_FIXED_DEV_CODE: process.env.OTP_FIXED_DEV_CODE || '',
  SMS_PROVIDER: process.env.SMS_PROVIDER || 'console',
  OTP_QUOTA_WINDOW_MS: int(process.env.OTP_QUOTA_WINDOW_MS, 15 * 60 * 1000),
  OTP_PHONE_LIMIT: int(process.env.OTP_PHONE_LIMIT, NODE_ENV === 'test' ? 100 : 50),
  OTP_IP_LIMIT: int(process.env.OTP_IP_LIMIT, NODE_ENV === 'test' ? 200 : 200),
  OTP_DEVICE_LIMIT: int(process.env.OTP_DEVICE_LIMIT, NODE_ENV === 'test' ? 100 : 50),

  UPLOAD_DIR: process.env.UPLOAD_DIR || path.join(ROOT_DIR, 'uploads'),
  MAX_UPLOAD_MB: int(process.env.MAX_UPLOAD_MB, 100),
  MOMENT_TTL_HOURS: int(process.env.MOMENT_TTL_HOURS, 24),

  // Redis (L2 Cache & Multi-Node WebSocket Pub/Sub)
  REDIS_URL: process.env.REDIS_URL || '',

  // S3 / MinIO / R2 Compatible Encrypted Media Storage
  R2_ENABLED: bool(process.env.R2_ENABLED, false),
  R2_ACCOUNT_ID: process.env.R2_ACCOUNT_ID || '',
  R2_API_TOKEN: process.env.R2_API_TOKEN || '',
  R2_ACCESS_KEY_ID: process.env.R2_ACCESS_KEY_ID || '',
  R2_SECRET_ACCESS_KEY: process.env.R2_SECRET_ACCESS_KEY || '',
  R2_BUCKET_NAME: process.env.R2_BUCKET_NAME || 'madar-media',
  R2_ENDPOINT: process.env.R2_ENDPOINT || '',
  R2_PUBLIC_URL: process.env.R2_PUBLIC_URL || process.env.R2_PUBLIC_CDN_URL || '',
  PHONE_HASH_SALT: process.env.PHONE_HASH_SALT || '',
  API_CUSTOM_DOMAIN: process.env.API_CUSTOM_DOMAIN || '',
  CDN_CUSTOM_DOMAIN: process.env.CDN_CUSTOM_DOMAIN || '',

  // Realtime calls (Coturn / Built-in STUN)
  CALL_RING_TIMEOUT_MS: int(process.env.CALL_RING_TIMEOUT_MS, 45_000),
  STUN_ENABLED: bool(process.env.STUN_ENABLED, true),
  STUN_PORT: int(process.env.STUN_PORT, 3478),
  ICE_PUBLIC_HOST: process.env.ICE_PUBLIC_HOST || '',
  CF_TURN_KEY_ID: process.env.CF_TURN_KEY_ID || '',
  CF_TURN_API_TOKEN: process.env.CF_TURN_API_TOKEN || '',
  TURN_ENABLED: bool(process.env.TURN_ENABLED, false),
  TURN_PORT: int(process.env.TURN_PORT, 3478),
  TURN_SECRET: process.env.TURN_SECRET || '',
  TURN_CREDENTIAL_TTL_SECONDS: int(process.env.TURN_CREDENTIAL_TTL_SECONDS, 86400),

  // Firebase Cloud Messaging & Identity Toolkit (Optional — self-hosted uses madar-relay by default)
  FIREBASE_SERVICE_ACCOUNT: process.env.FIREBASE_SERVICE_ACCOUNT || '',
  FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID || '',
  FIREBASE_WEB_API_KEY: process.env.FIREBASE_WEB_API_KEY || '',
  FIREBASE_IOS_API_KEY: process.env.FIREBASE_IOS_API_KEY || '',
  FIREBASE_IOS_BUNDLE_ID: process.env.FIREBASE_IOS_BUNDLE_ID || 'app.madar.protosoftdev',
  FIREBASE_AUTH_DOMAIN: process.env.FIREBASE_AUTH_DOMAIN || '',
  FIREBASE_STORAGE_BUCKET: process.env.FIREBASE_STORAGE_BUCKET || '',
  FIREBASE_MESSAGING_SENDER_ID: process.env.FIREBASE_MESSAGING_SENDER_ID || '',
  FIREBASE_WEB_APP_ID: process.env.FIREBASE_WEB_APP_ID || '',

  LOG_ENABLE: bool(process.env.LOG_ENABLE, true),
  LOG_LEVEL: process.env.LOG_LEVEL || (NODE_ENV === 'test' ? 'warn' : 'info'),

  // Phone lookup limits
  LOOKUP_WINDOW_MS: int(process.env.LOOKUP_WINDOW_MS, 10 * 60 * 1000),
  LOOKUP_USER_LIMIT: int(process.env.LOOKUP_USER_LIMIT, 10),
  LOOKUP_IP_LIMIT: int(process.env.LOOKUP_IP_LIMIT, 30),
  LOOKUP_DEVICE_LIMIT: int(process.env.LOOKUP_DEVICE_LIMIT, 10),
  LOOKUP_MIN_INTERVAL_MS: int(process.env.LOOKUP_MIN_INTERVAL_MS, NODE_ENV === 'test' ? 0 : 2000),
  LOOKUP_FAIL_DELAY_AFTER: int(process.env.LOOKUP_FAIL_DELAY_AFTER, 5),
  LOOKUP_FAIL_DELAY_MS: int(process.env.LOOKUP_FAIL_DELAY_MS, 400),
  LOOKUP_ALERT_FAILS: int(process.env.LOOKUP_ALERT_FAILS, 8),
  LOOKUP_ALERT_ACCOUNTS: int(process.env.LOOKUP_ALERT_ACCOUNTS, 4),
  LOOKUP_ALERT_RATE_LIMITS: int(process.env.LOOKUP_ALERT_RATE_LIMITS, 3),

  INVITE_BASE_URL: process.env.INVITE_BASE_URL || 'https://app.protosoftdev.online',
  INVITE_TOKEN_KEY: process.env.INVITE_TOKEN_KEY || '',
  INVITE_OPEN_WINDOW_MS: int(process.env.INVITE_OPEN_WINDOW_MS, 10 * 60 * 1000),
  INVITE_OPEN_USER_LIMIT: int(process.env.INVITE_OPEN_USER_LIMIT, 20),
  INVITE_OPEN_IP_LIMIT: int(process.env.INVITE_OPEN_IP_LIMIT, 60),
  INVITE_OPEN_DEVICE_LIMIT: int(process.env.INVITE_OPEN_DEVICE_LIMIT, 20),
  INVITE_OPEN_MIN_INTERVAL_MS: int(process.env.INVITE_OPEN_MIN_INTERVAL_MS, NODE_ENV === 'test' ? 0 : 1000),
  INVITE_WAVE_WINDOW_MS: int(process.env.INVITE_WAVE_WINDOW_MS, 24 * 60 * 60 * 1000),
  INVITE_WAVE_USER_LIMIT: int(process.env.INVITE_WAVE_USER_LIMIT, 10),
  INVITE_WAVE_IP_LIMIT: int(process.env.INVITE_WAVE_IP_LIMIT, 30),
  INVITE_WAVE_DEVICE_LIMIT: int(process.env.INVITE_WAVE_DEVICE_LIMIT, 10),
  INVITE_ALERT_INVALID: int(process.env.INVITE_ALERT_INVALID, 12),
  INVITE_ALERT_WAVES: int(process.env.INVITE_ALERT_WAVES, 8),
};

const WEAK_JWT = new Set([
  '',
  'secret',
  'changeme',
  'madar-dev-secret-change-me',
  'change-me-to-a-long-random-secret',
]);

const DEV_MARKER = 'madar-local-change-me';

export const DEFAULT_PHONE_HASH_SALT = 'madar-personal-contact-discovery-v1';

export function productionProblems(config = env) {
  if (!config.IS_PROD) return [];
  const problems = [];
  const jwt = String(config.JWT_SECRET || '');
  if (jwt.length < 32 || WEAK_JWT.has(jwt)) {
    problems.push('JWT_SECRET must be a unique secret of at least 32 characters');
  }
  if (config.DEPLOYMENT_PROFILE === 'workspace') {
    const masterKey = String(config.MASTER_ENCRYPTION_KEY || process.env.MADAR_MASTER_KEY || '');
    if (masterKey.length < 32) {
      problems.push('MADAR_MASTER_KEY / MASTER_ENCRYPTION_KEY must be configured in production');
    }
  } else {
    if (config.OTP_DEV_ECHO) problems.push('OTP_DEV_ECHO must be false');
    if (config.OTP_FIXED_DEV_CODE) problems.push('OTP_FIXED_DEV_CODE must be empty');
    const salt = String(config.PHONE_HASH_SALT || '');
    if (salt.length < 16 || salt === DEFAULT_PHONE_HASH_SALT) {
      problems.push('PHONE_HASH_SALT must be a unique secret of at least 16 characters');
    }
    const r2Secret = String(config.R2_SECRET_ACCESS_KEY || '');
    const r2Ready =
      config.R2_ENABLED &&
      config.R2_ACCESS_KEY_ID &&
      r2Secret &&
      !r2Secret.includes(DEV_MARKER) &&
      (config.R2_ENDPOINT || config.R2_ACCOUNT_ID) &&
      String(config.R2_PUBLIC_URL || '').startsWith('https://');
    if (!r2Ready) problems.push('R2_ENABLED with access keys, endpoint, and an https R2_PUBLIC_URL is required');
    const turnSecret = String(config.TURN_SECRET || '');
    if ((!turnSecret || turnSecret.includes(DEV_MARKER)) && !config.CF_TURN_API_TOKEN) {
      problems.push('TURN_SECRET or CF_TURN_API_TOKEN is required');
    }
    if (!config.FIREBASE_SERVICE_ACCOUNT) problems.push('FIREBASE_SERVICE_ACCOUNT must point at the Admin SDK JSON');
  }
  if (!String(config.PUBLIC_URL || '').startsWith('https://')) {
    problems.push('PUBLIC_URL must start with https://');
  }
  const databaseUrl = String(config.DATABASE_URL || '');
  const databaseConfigured = config.databaseConfigured ?? Boolean(process.env.DATABASE_URL);
  if (
    !databaseConfigured ||
    !databaseUrl ||
    databaseUrl.includes('postgres123') ||
    databaseUrl.includes(DEV_MARKER) ||
    /@(localhost|127\.0\.0\.1)([:/]|$)/.test(databaseUrl)
  ) {
    problems.push('DATABASE_URL must be an explicit production connection string');
  }
  const redisUrl = String(config.REDIS_URL || '');
  if (!/^rediss?:\/\/\S+$/.test(redisUrl) || redisUrl.includes(DEV_MARKER)) {
    problems.push('REDIS_URL must be a redis:// or rediss:// URL');
  }
  return problems;
}

export function assertEnv() {
  const problems = [...productionProblems()];
  if (env.IS_PROD && env.FIREBASE_SERVICE_ACCOUNT && env.DEPLOYMENT_PROFILE !== 'workspace') {
    let file = path.isAbsolute(env.FIREBASE_SERVICE_ACCOUNT)
      ? env.FIREBASE_SERVICE_ACCOUNT
      : path.join(ROOT_DIR, env.FIREBASE_SERVICE_ACCOUNT);
    if (!fs.existsSync(file)) {
      const candidates = [
        '/run/secrets/firebase.json',
        path.join(ROOT_DIR, 'src/config', path.basename(env.FIREBASE_SERVICE_ACCOUNT)),
        path.join(ROOT_DIR, 'src/config/samu-dhahabiya-logistics-firebase-adminsdk-fbsvc-78827f44f4.json'),
        '/app/src/config/samu-dhahabiya-logistics-firebase-adminsdk-fbsvc-78827f44f4.json',
      ];
      const match = candidates.find((c) => fs.existsSync(c));
      if (match) {
        env.FIREBASE_SERVICE_ACCOUNT = match;
        file = match;
      }
    }
    if (!fs.existsSync(file)) problems.push('FIREBASE_SERVICE_ACCOUNT file is missing');
  }
  if (!env.IS_PROD && env.TURN_ENABLED && !env.TURN_SECRET && !env.CF_TURN_API_TOKEN) {
    problems.push('TURN_SECRET or CF_TURN_API_TOKEN is required when TURN_ENABLED=true');
  }
  if (problems.length) throw new Error(`Refusing to start: ${problems.join('; ')}`);
}

export function icePublicHost() {
  if (env.ICE_PUBLIC_HOST) return env.ICE_PUBLIC_HOST;
  try {
    return new URL(env.PUBLIC_URL).hostname;
  } catch {
    return 'localhost';
  }
}
