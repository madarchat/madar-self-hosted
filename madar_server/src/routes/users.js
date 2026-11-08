import path from 'node:path';
import { Router } from 'express';
import { db } from '../db/pool.js';
import { validate, z, idParam, privacyPatchSchema } from '../lib/validate.js';
import { forbidden, notFound } from '../lib/errors.js';
import { requireAuth } from '../middleware/auth.js';
import { uploadAvatar, publicPath, removeFile } from '../lib/media.js';
import { serializeUser, USER_COLUMNS } from '../lib/serialize.js';
import { hub } from '../realtime/hub.js';
import { relationBetween } from '../services/relations.js';
import { blockRole, blocksFor, createBlock, removeBlock } from '../services/blocks.js';
import { sha256 } from '../lib/tokens.js';

export const usersRouter = Router();
usersRouter.use(requireAuth);

const ACCENTS = ['teal', 'amber', 'rose', 'violet', 'lime', 'sky'];

/** Update my profile (multipart/form-data: name, note, accent, avatar). */
usersRouter.patch(
  '/me',
  uploadAvatar.single('avatar'),
  validate({
    body: z.object({
      name: z.string().trim().min(1).max(80).optional(),
      note: z.string().trim().max(140).optional(),
      accent: z.enum(ACCENTS).optional(),
      remove_avatar: z.coerce.boolean().optional(),
    }),
  }),
  async (req, res) => {
    const { name, note, accent, remove_avatar } = req.body;
    const current = await db.one('SELECT avatar_url FROM users WHERE id = $1', [req.auth.userId]);
    if (!current) throw notFound('user_not_found');

    let avatarUrl = current.avatar_url;
    if (req.file) {
      avatarUrl = publicPath('avatars', req.file.filename);
    } else if (remove_avatar) {
      avatarUrl = null;
    }
    if (avatarUrl !== current.avatar_url && current.avatar_url) {
      removeFile('avatars', path.basename(current.avatar_url));
    }

    const user = await db.one(
      `UPDATE users SET
         name = COALESCE($2, name),
         note = COALESCE($3, note),
         accent = COALESCE($4, accent),
         avatar_url = $5,
         updated_at = NOW()
       WHERE id = $1 RETURNING ${USER_COLUMNS}`,
      [req.auth.userId, name ?? null, note ?? null, accent ?? null, avatarUrl],
    );

    // Let connected people know the profile changed so caches refresh.
    const peers = await db.many(
      `SELECT DISTINCT tm2.user_id FROM thread_members tm1
       JOIN thread_members tm2 ON tm1.thread_id = tm2.thread_id AND tm2.user_id <> tm1.user_id
       WHERE tm1.user_id = $1`,
      [req.auth.userId],
    );
    hub.sendMany(peers.map((p) => p.user_id), 'user.updated', { user: serializeUser(user, { withPhone: false }) });

    res.json({ success: true, user: serializeUser(user, { self: true }) });
  },
);

/** Privacy toggles. Profile edits do not pass through this route. */
usersRouter.patch(
  '/me/privacy',
  validate({ body: privacyPatchSchema }),
  async (req, res) => {
    const { allow_phone_discovery, show_phone_number } = req.body;
    const user = await db.one(
      `UPDATE users SET
         allow_phone_discovery = COALESCE($2, allow_phone_discovery),
         show_phone_number = COALESCE($3, show_phone_number),
         updated_at = NOW()
       WHERE id = $1 RETURNING ${USER_COLUMNS}`,
      [req.auth.userId, allow_phone_discovery ?? null, show_phone_number ?? null],
    );
    if (!user) throw notFound('user_not_found');
    res.json({ success: true, user: serializeUser(user, { self: true }) });
  },
);

usersRouter.post(
  '/me/push-token',
  validate({ body: z.object({ token: z.string().min(10).max(4096), platform: z.enum(['android', 'ios', 'web']).optional() }) }),
  async (req, res) => {
    await db.query('UPDATE users SET push_token = $2, device_platform = $3, updated_at = NOW() WHERE id = $1', [
      req.auth.userId, req.body.token, req.body.platform || null,
    ]);
    res.json({ success: true });
  },
);

// Deleting a workspace account is an administrative act, not a user one.
// Records may be under legal hold or retention policy, and offboarding has to
// be auditable — so it runs through the control plane, not this endpoint.
usersRouter.delete('/me', async (_req, _res) => {
  throw forbidden(
    'offboarding_is_administrative',
    'حذف حساب مساحة العمل يتم عبر إدارة المؤسسة (إنهاء الخدمة)، وليس من التطبيق.',
  );
});

usersRouter.get('/me/blocks', async (req, res) => {
  const rows = await blocksFor(req.auth.userId);
  res.json({
    success: true,
    blocks: rows.map((row) => ({
      id: row.id,
      name: row.name,
      avatar_url: row.avatar_url || null,
      accent: row.accent || 'teal',
      created_at: new Date(row.created_at).toISOString(),
    })),
  });
});

usersRouter.post(
  '/me/blocks',
  validate({ body: z.object({ user_id: z.coerce.number().int().positive() }) }),
  async (req, res) => {
    await createBlock(req.auth.userId, req.body.user_id);
    res.json({ success: true });
  },
);

usersRouter.delete('/me/blocks/:userId', validate({ params: idParam('userId') }), async (req, res) => {
  await removeBlock(req.auth.userId, req.paramsParsed.userId);
  res.json({ success: true });
});

/** Public profile of another user, including my relation to them. */
usersRouter.get('/:id', validate({ params: idParam() }), async (req, res) => {
  const { id } = req.paramsParsed;
  const user = await db.one(`SELECT ${USER_COLUMNS} FROM users WHERE id = $1`, [id]);
  if (!user) throw notFound('user_not_found');
  const relation = await relationBetween(req.auth.userId, id);
  const self = id === req.auth.userId;
  const role = self ? null : await blockRole(req.auth.userId, id);
  const body = {
    ...serializeUser(user, { withPhone: relation.status === 'connected', self }),
    relation,
  };
  if (role === 'blocker') body.blocked_by_me = true;
  res.json({ success: true, user: body });
});
