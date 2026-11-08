import crypto from 'node:crypto';
import { Router } from 'express';
import { validate, z } from '../lib/validate.js';
import { badRequest } from '../lib/errors.js';
import { requireAuth } from '../middleware/auth.js';
import { attachPolicyContext, assertAttachmentAllowed } from '../middleware/policyGuard.js';
import { createR2UploadUrl, r2Client } from '../lib/r2.js';
import { ALLOWED, uploadMessageMedia, publicPath, removeFile } from '../lib/media.js';
import { env } from '../config/env.js';

export const mediaRouter = Router();
mediaRouter.use(requireAuth, attachPolicyContext);

mediaRouter.post(
  '/presign',
  validate({
    body: z.object({
      kind: z.enum(['image', 'video', 'audio', 'file']).default('file'),
      content_type: z.string().max(120).default('application/octet-stream'),
      content_length: z.preprocess(
        (value) => (value === null || value === '' ? undefined : value),
        z.coerce.number().int().positive().max(env.MAX_UPLOAD_MB * 1024 * 1024).optional(),
      ),
      file_name: z.string().max(255).optional(),
    }),
  }),
  async (req, res) => {
    const contentType = String(req.body.content_type || 'application/octet-stream').toLowerCase();
    assertAttachmentAllowed(req.effectivePolicy?.policies, {
      sizeBytes: req.body.content_length || 0,
      mimeType: contentType,
    });
    if (!env.R2_ENABLED || !r2Client) {
      throw badRequest('r2_not_configured', 'Direct R2 upload is not enabled on this server');
    }
    if (!ALLOWED.has(contentType)) throw badRequest('unsupported_media_type', 'Unsupported file type');
    const ext = (req.body.file_name || '').split('.').pop()?.slice(0, 8) || 'bin';
    const key = `messages/${crypto.randomUUID()}.${ext.replace(/[^a-z0-9]/gi, '') || 'bin'}`;
    const { uploadUrl, publicUrl, key: objectKey } = await createR2UploadUrl({
      key,
      contentType,
      contentLength: req.body.content_length,
      expiresIn: 600,
    });
    res.json({
      success: true,
      upload_url: uploadUrl,
      public_url: publicUrl,
      object_key: objectKey,
      expires_in: 600,
    });
  },
);

/**
 * POST /api/v1/media/upload (and POST /api/v1/media) — Local/Sovereign attachment upload
 * enforcing chat.max_attachment_mb (TC-POL-13) and chat.allowed_mime_categories (TC-POL-14).
 */
async function handleMediaUpload(req, res) {
  const file = req.file || req.files?.file?.[0];
  const sizeBytes = file ? file.size : Number(req.body?.size_bytes || 0);
  const mimeType = file ? file.mimetype : String(req.body?.mime_type || 'application/octet-stream');

  try {
    assertAttachmentAllowed(req.effectivePolicy?.policies, { sizeBytes, mimeType });
  } catch (err) {
    if (file?.filename) removeFile('messages', file.filename);
    throw err;
  }

  if (!file && !req.body?.mime_type) {
    throw badRequest('missing_media', 'لم يتم إرفاق ملف');
  }

  const url = file ? publicPath('messages', file.filename) : `/media/messages/${crypto.randomUUID()}.bin`;
  res.status(201).json({
    success: true,
    media_url: url,
    mime_type: mimeType,
    size_bytes: sizeBytes,
  });
}

mediaRouter.post('/', uploadMessageMedia.single('file'), handleMediaUpload);
mediaRouter.post('/upload', uploadMessageMedia.single('file'), handleMediaUpload);

