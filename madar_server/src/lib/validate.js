import { z } from 'zod';
import { badRequest } from './errors.js';
import { normalizePhone } from './phone.js';

/**
 * Validates req[source] with a zod schema and replaces it with the parsed value.
 * Usage: router.post('/x', validate({ body: schema }), handler)
 */
export function validate(schemas) {
  return (req, _res, next) => {
    for (const [source, schema] of Object.entries(schemas)) {
      const result = schema.safeParse(req[source] ?? {});
      if (!result.success) {
        const issues = result.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message }));
        return next(badRequest('validation_error', 'Invalid request', issues));
      }
      if (source === 'query' || source === 'params') {
        // Express 5 exposes query/params as getters; store the parsed copy separately.
        req[`${source}Parsed`] = result.data;
      } else {
        req[source] = result.data;
      }
    }
    next();
  };
}

export const idParam = (name = 'id') => z.object({ [name]: z.coerce.number().int().positive() });

/** JSON clients often send `null` for omitted optional ids; Zod coerce would turn that into 0 and fail `.positive()`. */
export const optionalPositiveInt = z.preprocess(
  (v) => (v === null || v === '' ? undefined : v),
  z.coerce.number().int().positive().optional(),
);

export const optionalNonNegativeInt = z.preprocess(
  (v) => (v === null || v === '' ? undefined : v),
  z.coerce.number().int().min(0).optional(),
);

/** Canonical E.164. No default country: the client sends an already-normalized number. */
export const phoneSchema = z.string().trim().transform((value, ctx) => {
  const e164 = normalizePhone(value);
  if (!e164) {
    ctx.addIssue({ code: 'custom', message: 'Phone must be a complete E.164 number' });
    return z.NEVER;
  }
  return e164;
});

/** One phone field. Extra keys (hashes, arrays of numbers) are rejected. */
export const lookupPhoneSchema = z.strictObject({
  phone: z.string().trim().min(1).max(40),
});

/** Explicit privacy toggles. An empty body is rejected so a profile save cannot flip them. */
export const privacyPatchSchema = z.object({
  allow_phone_discovery: z.boolean().optional(),
  show_phone_number: z.boolean().optional(),
}).refine(
  (value) => value.allow_phone_discovery !== undefined || value.show_phone_number !== undefined,
  { message: 'Choose a privacy setting' },
);

export { z };
