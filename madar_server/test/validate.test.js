import test from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { optionalPositiveInt, optionalNonNegativeInt } from '../src/lib/validate.js';

test('optionalPositiveInt accepts null reply_to_id from JSON clients', () => {
  const schema = z.object({ reply_to_id: optionalPositiveInt });
  const result = schema.safeParse({ reply_to_id: null });
  assert.equal(result.success, true);
  assert.equal(result.data.reply_to_id, undefined);
});

test('optionalNonNegativeInt accepts null duration_ms', () => {
  const schema = z.object({ duration_ms: optionalNonNegativeInt });
  const result = schema.safeParse({ duration_ms: null });
  assert.equal(result.success, true);
  assert.equal(result.data.duration_ms, undefined);
});
