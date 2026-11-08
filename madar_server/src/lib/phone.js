import { parsePhoneNumberFromString } from 'libphonenumber-js';

const MULTI_NUMBER = /[,;\n\r]/;

/**
 * One phone number, normalized to E.164, or null when the input is incomplete,
 * partial, or more than a single number.
 *
 * Callers that already know the country (the app, after the user picks a dial
 * code) may pass `defaultCountry`. API routes do not: a value without `+`
 * is rejected so the server never assumes a country.
 *
 * @param {unknown} input
 * @param {{ defaultCountry?: string }} [options]
 * @returns {string | null}
 */
export function normalizePhone(input, { defaultCountry } = {}) {
  if (typeof input !== 'string') return null;
  const raw = input.trim();
  if (!raw || raw.length > 40) return null;
  if (MULTI_NUMBER.test(raw)) return null;

  const compact = raw.replace(/[\s\-().]/g, '');
  if (!/^\+?[0-9]+$/.test(compact)) return null;

  const international = compact.startsWith('+');
  if (!international && !defaultCountry) return null;

  const parsed = parsePhoneNumberFromString(compact, international ? undefined : defaultCountry);
  if (!parsed?.isValid()) return null;
  return parsed.number;
}
