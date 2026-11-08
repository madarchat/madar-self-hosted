/** Share a phone number with someone else only when they are allowed to see it and the owner opted in. */
export function sharePhone(row, { withPhone = true, self = false } = {}) {
  if (!row) return false;
  if (self) return true;
  return withPhone === true && row.show_phone_number === true;
}

/**
 * Lookup result. Missing, unnamed, discovery-off, self, and blocked rows
 * all become the same `{ found: false }` object. The lookup query sets
 * `row.blocked` when the account owner has blocked the searcher.
 */
export function presentLookup(row, me) {
  const named = typeof row?.name === 'string' && row.name.trim() !== '';
  const discoverable = Boolean(
    row?.id &&
    row.id !== me &&
    named &&
    row.allow_phone_discovery === true &&
    row.blocked !== true,
  );
  if (!discoverable) return { success: true, found: false };

  let relation = { status: 'none' };
  if (row.thread_id) relation = { status: 'connected', thread_id: row.thread_id };
  else if (row.wave_status === 'pending') {
    relation = {
      status: row.wave_sender === me ? 'wave_sent' : 'wave_received',
      wave_id: row.wave_id,
    };
  }

  return {
    success: true,
    found: true,
    person: {
      id: row.id,
      avatar_url: row.avatar_url || null,
      accent: row.accent || 'teal',
      relation,
    },
  };
}
