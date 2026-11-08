import crypto from 'node:crypto';
import { env } from '../config/env.js';
import { logger } from './logger.js';

/**
 * Multi-adapter SMS delivery engine (Section 10.1.3 & ADM-02).
 * Supports:
 *  - 'madar_relay': dispatches OTP via Madar Cloud SMS Relay using TENANT_TOKEN
 *  - 'webhook': dispatches OTP via enterprise HTTP/SMPP Webhook with HMAC-SHA256 signature
 *  - 'console': logs OTP to structured server log (development/testing)
 *  - 'none': no-op when SMS is disabled in air-gapped environments
 */
const providers = {
  console: async ({ phone, code }) => {
    logger.info({ phone, code }, 'OTP code (console provider)');
    return { delivered: true, provider: 'console' };
  },
  none: async () => ({ delivered: true, provider: 'none' }),
  webhook: async ({ phone, code, config = {} }) => {
    const webhookUrl = config.sms_webhook_url || process.env.SMS_WEBHOOK_URL || '';
    const secret = config.sms_webhook_secret || process.env.SMS_WEBHOOK_SECRET || '';
    if (!webhookUrl) {
      logger.warn({ phone }, 'sms webhook provider selected but SMS_WEBHOOK_URL is not configured');
      return { delivered: false, provider: 'webhook', reason: 'missing_webhook_url' };
    }
    const payload = JSON.stringify({
      event: 'madar.otp.sms',
      phone,
      code,
      text: `رمز التحقق في مدار: ${code}`,
      ts: new Date().toISOString(),
    });
    const headers = { 'Content-Type': 'application/json' };
    if (secret) {
      const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
      headers['X-Madar-Signature'] = `sha256=${sig}`;
    }
    const res = await fetch(webhookUrl, { method: 'POST', headers, body: payload });
    if (!res.ok) {
      throw new Error(`SMS webhook failed with HTTP ${res.status}`);
    }
    return { delivered: true, provider: 'webhook', status: res.status };
  },
  madar_relay: async ({ phone, code, config = {} }) => {
    const relayUrl = (config.relay_url || process.env.MADAR_RELAY_URL || '').replace(/\/+$/, '');
    const tenantToken = config.tenant_token || process.env.TENANT_TOKEN || '';
    if (!relayUrl || !tenantToken) {
      logger.warn({ phone }, 'madar_relay SMS selected but relay_url or tenant_token is missing');
      return { delivered: false, provider: 'madar_relay', reason: 'missing_relay_credentials' };
    }
    const res = await fetch(`${relayUrl}/v1/sms`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tenantToken}`,
      },
      body: JSON.stringify({
        phone,
        code,
        template: 'otp_ar',
        ts: Date.now(),
      }),
    });
    if (!res.ok) {
      throw new Error(`Madar SMS Relay failed with HTTP ${res.status}`);
    }
    return { delivered: true, provider: 'madar_relay', status: res.status };
  },
};

export async function sendOtpSms(phone, code, runtimeConfig = {}) {
  const providerName = runtimeConfig.sms_provider || process.env.SMS_PROVIDER || env.SMS_PROVIDER || 'console';
  const provider = providers[providerName] || providers.console;
  return provider({ phone, code, config: runtimeConfig });
}
