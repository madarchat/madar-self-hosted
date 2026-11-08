import { env } from '../config/env.js';
import { logger } from './logger.js';

/**
 * Firebase is only proof that the phone number belongs to the person holding it.
 * Madar still issues its own access and refresh tokens after this succeeds.
 *
 * Identity Toolkit requires an attestation: Play Integrity (Android), reCAPTCHA
 * (web or the iOS verifyApp handoff), or the iOS silent-push receipt.
 * The Admin SDK cannot send this SMS.
 */

const ENDPOINT = 'https://identitytoolkit.googleapis.com/v1/accounts:';

let transport = (url, options) => fetch(url, options);

/** Test hook. Production code leaves the global fetch in place. */
export function setFirebaseTransport(fn) {
  transport = fn;
}

export class FirebaseAuthError extends Error {
  constructor(firebaseCode, httpStatus, code, message) {
    super(message);
    this.firebaseCode = firebaseCode;
    this.httpStatus = httpStatus;
    this.code = code;
  }
}

const KNOWN = {
  INVALID_CODE: [400, 'invalid_code', 'Incorrect code'],
  INVALID_SESSION_INFO: [400, 'code_expired', 'Code expired, request a new one'],
  SESSION_EXPIRED: [400, 'code_expired', 'Code expired, request a new one'],
  TOO_MANY_ATTEMPTS_TRY_LATER: [429, 'too_many_attempts', 'Too many attempts, request a new code'],
  INVALID_PHONE_NUMBER: [400, 'invalid_phone', 'Firebase rejected this phone number'],
  QUOTA_EXCEEDED: [429, 'sms_quota', 'Firebase SMS quota is exhausted'],
  // A sideloaded app often cannot satisfy Play Integrity. The client retries with reCAPTCHA.
  Internal: [400, 'needs_recaptcha', 'Play Integrity was rejected for this number'],
  INTERNAL: [400, 'needs_recaptcha', 'Play Integrity was rejected for this number'],
  MISSING_CLIENT_IDENTIFIER: [400, 'needs_recaptcha', 'Firebase could not verify this app'],
  INVALID_APP_CREDENTIAL: [400, 'needs_recaptcha', 'Firebase rejected the app credential'],
  BILLING_NOT_ENABLED: [503, 'firebase_billing', 'Firebase phone authentication requires the Blaze plan'],
};

function fail(firebaseCode, fallbackMessage) {
  const known = KNOWN[firebaseCode];
  if (known) throw new FirebaseAuthError(firebaseCode, known[0], known[1], known[2]);
  throw new FirebaseAuthError(
    firebaseCode || 'FIREBASE_ERROR',
    502,
    'firebase_error',
    fallbackMessage || 'Firebase phone authentication failed',
  );
}

async function post(method, body, { locale, iosBundle, apiKey } = {}) {
  const key = apiKey || env.FIREBASE_WEB_API_KEY;
  if (!key) {
    throw new FirebaseAuthError('MISSING_API_KEY', 503, 'firebase_not_configured', 'FIREBASE_WEB_API_KEY is not set');
  }
  const headers = { 'content-type': 'application/json' };
  if (locale) headers['x-firebase-locale'] = locale;
  if (iosBundle) headers['x-ios-bundle-identifier'] = iosBundle;

  let response;
  try {
    response = await transport(`${ENDPOINT}${method}?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(20_000),
    });
  } catch (err) {
    logger.warn({ err: err.message, method }, 'firebase phone auth unreachable');
    throw new FirebaseAuthError('UNREACHABLE', 503, 'firebase_unreachable', 'Could not reach Firebase');
  }

  const payload = await response.json().catch(() => ({}));
  if (response.ok) return payload;

  const raw = String(payload?.error?.message || '');
  const firebaseCode = raw.split(/[\s:]/)[0] || 'FIREBASE_ERROR';
  logger.warn({ method, firebase: firebaseCode, status: response.status }, 'firebase phone auth rejected');
  fail(firebaseCode, raw || 'Firebase phone authentication failed');
}

/**
 * Asks Firebase to text a code. Returns the sessionInfo that verify must send back.
 * The SMS code itself never comes back to Madar.
 * A console test number is accepted with the phone alone. Any other number
 * without an attestation comes back as MISSING_CLIENT_IDENTIFIER.
 */
export async function sendFirebaseCode({
  phone,
  playIntegrityToken,
  recaptchaToken,
  iosReceipt,
  iosSecret,
  locale,
  clientPlatform,
}) {
  const iosClient = clientPlatform === 'ios' || Boolean(iosReceipt && iosSecret);
  const body = { phoneNumber: phone };
  if (playIntegrityToken) {
    body.playIntegrityToken = playIntegrityToken;
    body.clientType = 'CLIENT_TYPE_ANDROID';
  } else if (recaptchaToken) {
    body.recaptchaToken = recaptchaToken;
    body.clientType = iosClient ? 'CLIENT_TYPE_IOS' : 'CLIENT_TYPE_WEB';
  } else if (iosReceipt && iosSecret) {
    body.iosReceipt = iosReceipt;
    body.iosSecret = iosSecret;
    body.clientType = 'CLIENT_TYPE_IOS';
  }

  logger.info({ phone }, 'firebase: sending verification sms');
  const data = await post('sendVerificationCode', body, {
    locale,
    iosBundle: iosClient ? env.FIREBASE_IOS_BUNDLE_ID : undefined,
    apiKey: iosClient ? env.FIREBASE_IOS_API_KEY : undefined,
  });
  if (!data?.sessionInfo) fail('MISSING_SESSION_INFO', 'Firebase did not return a session');
  return data.sessionInfo;
}

/** Site key for the reCAPTCHA widget. Fetched at the moment it is shown; the stoken is short-lived. */
export async function fetchRecaptchaParams() {
  if (!env.FIREBASE_WEB_API_KEY) {
    throw new FirebaseAuthError('MISSING_API_KEY', 503, 'firebase_not_configured', 'FIREBASE_WEB_API_KEY is not set');
  }
  let response;
  try {
    response = await transport(
      `https://identitytoolkit.googleapis.com/v1/recaptchaParams?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY)}`,
      { method: 'GET', signal: AbortSignal.timeout(15_000) },
    );
  } catch (err) {
    logger.warn({ err: err.message }, 'firebase recaptcha params unreachable');
    throw new FirebaseAuthError('UNREACHABLE', 503, 'firebase_unreachable', 'Could not reach Firebase');
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload?.recaptchaSiteKey) {
    const raw = String(payload?.error?.message || '');
    fail(raw.split(/[\s:]/)[0] || 'RECAPTCHA_UNAVAILABLE', raw || 'reCAPTCHA is not available');
  }
  return {
    siteKey: payload.recaptchaSiteKey,
    stoken: payload.recaptchaStoken || '',
    authDomain: env.FIREBASE_AUTH_DOMAIN || '',
  };
}

/** Checks the SMS code. Returns the phone number Firebase says it verified. */
export async function verifyFirebaseCode({ sessionInfo, code }) {
  const data = await post('signInWithPhoneNumber', { sessionInfo, code });
  const phone = data?.phoneNumber;
  if (!phone) fail('PHONE_MISSING', 'Firebase did not confirm a phone number');
  return phone;
}
