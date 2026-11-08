import { hub } from '../realtime/hub.js';
import { sharePhone } from './privacy.js';

export const USER_COLUMNS = 'id, phone, name, note, avatar_url, accent, last_seen_at, created_at, allow_phone_discovery, show_phone_number';
/** Same columns qualified with a table alias, e.g. userCols('u') → "u.id, u.phone, …" */
export const userCols = (alias) => USER_COLUMNS.split(', ').map((c) => `${alias}.${c}`).join(', ');

export function serializeUser(row, { withPhone = true, self = false } = {}) {
  if (!row) return null;
  return {
    id: row.id,
    phone: sharePhone(row, { withPhone, self }) ? row.phone : undefined,
    name: row.name,
    note: row.note || '',
    avatar_url: row.avatar_url || null,
    accent: row.accent || 'teal',
    is_online: hub.isOnline(row.id),
    last_seen_at: row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null,
    is_new_user: !row.name,
    ...(self
      ? {
          allow_phone_discovery: row.allow_phone_discovery === true,
          show_phone_number: row.show_phone_number === true,
        }
      : {}),
  };
}

export function serializeMessage(row) {
  if (!row) return null;
  const deleted = !!row.deleted_at;
  return {
    id: row.id,
    thread_id: row.thread_id,
    sender_id: row.sender_id,
    client_id: row.client_id || null,
    kind: deleted ? 'text' : row.kind,
    body: deleted ? null : row.body,
    media_url: deleted ? null : row.media_url,
    thumb_url: deleted ? null : row.thumb_url,
    media_mime: deleted ? null : row.media_mime,
    media_name: deleted ? null : row.media_name,
    media_size: deleted ? null : (row.media_size == null ? null : Number(row.media_size)),
    duration_ms: deleted ? null : row.duration_ms,
    reply_to_id: row.reply_to_id,
    moment_id: row.moment_id,
    created_at: new Date(row.created_at).toISOString(),
    edited_at: row.edited_at ? new Date(row.edited_at).toISOString() : null,
    is_deleted: deleted,
    sender_name: row.sender_name,
    sender_avatar_url: row.sender_avatar_url ?? null,
    read_by_count: row.read_by_count == null ? undefined : Number(row.read_by_count),
    is_e2ee: !!row.is_e2ee,
    e2ee_header: row.e2ee_header ?? null,
  };
}

export function serializeCall(row) {
  if (!row) return null;
  return {
    id: row.id,
    caller_id: row.caller_id,
    callee_id: row.callee_id,
    kind: row.kind,
    status: row.status,
    started_at: new Date(row.started_at).toISOString(),
    answered_at: row.answered_at ? new Date(row.answered_at).toISOString() : null,
    ended_at: row.ended_at ? new Date(row.ended_at).toISOString() : null,
    duration_s: row.duration_s ?? null,
    end_reason: row.end_reason ?? null,
    caller_name: row.caller_name,
    caller_avatar_url: row.caller_avatar_url ?? null,
    callee_name: row.callee_name,
    callee_avatar_url: row.callee_avatar_url ?? null,
  };
}

export function serializeMoment(row, viewerId) {
  if (!row) return null;
  return {
    id: row.id,
    user_id: row.user_id,
    media_url: row.media_url,
    thumb_url: row.thumb_url || null,
    media_kind: row.media_kind,
    caption: row.caption || null,
    bg_color: row.bg_color || null,
    created_at: new Date(row.created_at).toISOString(),
    expires_at: new Date(row.expires_at).toISOString(),
    view_count: row.view_count == null ? undefined : Number(row.view_count),
    viewed: row.viewed_by_me != null ? !!row.viewed_by_me : undefined,
    is_mine: viewerId != null ? row.user_id === viewerId : undefined,
  };
}
