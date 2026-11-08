import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import multer from 'multer';
import ffmpeg from 'fluent-ffmpeg';
import ffmpegPath from 'ffmpeg-static';
import { env } from '../config/env.js';
import { logger } from './logger.js';

if (ffmpegPath) ffmpeg.setFfmpegPath(ffmpegPath);

export const BUCKETS = {
  avatars: path.join(env.UPLOAD_DIR, 'avatars'),
  messages: path.join(env.UPLOAD_DIR, 'messages'),
  thumbs: path.join(env.UPLOAD_DIR, 'thumbs'),
  moments: path.join(env.UPLOAD_DIR, 'moments'),
};
for (const dir of Object.values(BUCKETS)) fs.mkdirSync(dir, { recursive: true });

export const ALLOWED = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic',
  'video/mp4', 'video/quicktime', 'video/webm', 'video/x-m4v',
  'audio/mpeg', 'audio/aac', 'audio/mp4', 'audio/m4a', 'audio/x-m4a', 'audio/wav', 'audio/ogg', 'audio/webm', 'audio/opus',
  'application/pdf', 'application/zip', 'application/octet-stream',
  'text/plain',
]);
const AUDIO_EXT = /\.(aac|mp3|wav|ogg|m4a|opus|webm)$/i;
const IMAGE_EXT = /\.(jpe?g|png|gif|webp|heic|heif)$/i;

export function kindFromMime(mime = '', name = '') {
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/') || AUDIO_EXT.test(name)) return 'audio';
  return 'file';
}

const MIME_EXT = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/gif': '.gif',
  'image/webp': '.webp',
  'image/heic': '.heic',
  'video/mp4': '.mp4',
  'video/quicktime': '.mov',
  'video/webm': '.webm',
  'video/x-m4v': '.m4v',
  'audio/mpeg': '.mp3',
  'audio/aac': '.aac',
  'audio/mp4': '.m4a',
  'audio/m4a': '.m4a',
  'audio/x-m4a': '.m4a',
  'audio/wav': '.wav',
  'audio/ogg': '.ogg',
  'audio/webm': '.webm',
  'audio/opus': '.opus',
  'application/pdf': '.pdf',
  'application/zip': '.zip',
  'text/plain': '.txt',
  'application/octet-stream': '.bin',
};

function makeStorage(bucketResolver) {
  return multer.diskStorage({
    destination: (req, file, cb) => cb(null, bucketResolver(file)),
    filename: (_req, file, cb) => {
      const fromMime = MIME_EXT[String(file.mimetype || '').toLowerCase()];
      const fromName = (path.extname(file.originalname || '') || '').toLowerCase().slice(0, 10);
      cb(null, `${crypto.randomUUID()}${fromMime || fromName || ''}`);
    },
  });
}

/** Magic-byte type, used when a file was stored with the wrong extension. */
export function sniffContentType(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(12);
    const n = fs.readSync(fd, buf, 0, 12, 0);
    if (n >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
    if (n >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return 'image/png';
    if (n >= 6 && buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) return 'image/gif';
    if (n >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  return null;
}

const fileFilter = (_req, file, cb) => {
  const name = file.originalname || '';
  if (ALLOWED.has(file.mimetype) || AUDIO_EXT.test(name) || IMAGE_EXT.test(name)) return cb(null, true);
  cb(new Error(`Unsupported file type: ${file.mimetype}`));
};

const limits = { fileSize: env.MAX_UPLOAD_MB * 1024 * 1024, files: 2 };

export const uploadAvatar = multer({ storage: makeStorage(() => BUCKETS.avatars), fileFilter, limits });
export const uploadMessageMedia = multer({
  storage: makeStorage((file) => (file.fieldname === 'thumb' ? BUCKETS.thumbs : BUCKETS.messages)),
  fileFilter,
  limits,
});
export const uploadMomentMedia = multer({
  storage: makeStorage((file) => (file.fieldname === 'thumb' ? BUCKETS.thumbs : BUCKETS.moments)),
  fileFilter,
  limits,
});

import { uploadFileToR2, deleteFromR2 } from './r2.js';

/** Public path (relative or R2 CDN URL) for a stored file, and mirrors to Cloudflare R2 when enabled. */
export function publicPath(bucket, filename) {
  if (!filename) return null;
  if (env.R2_ENABLED && BUCKETS[bucket]) {
    const localPath = path.join(BUCKETS[bucket], path.basename(filename));
    uploadFileToR2(localPath, `${bucket}/${path.basename(filename)}`).catch((err) => {
      logger.warn({ err: err.message, bucket, filename }, 'r2 background mirror failed');
    });
  }
  return `/media/${bucket}/${filename}`;
}

export async function generateVideoThumb(videoPath) {
  const name = `${crypto.randomUUID()}.jpg`;
  await new Promise((resolve, reject) => {
    ffmpeg(videoPath)
      .screenshots({ timestamps: ['00:00:00.500'], filename: name, folder: BUCKETS.thumbs, size: '480x?' })
      .on('end', resolve)
      .on('error', reject);
  });
  return name;
}

export async function tryVideoThumb(videoPath) {
  try {
    return await generateVideoThumb(videoPath);
  } catch (err) {
    logger.warn({ err: err.message }, 'thumbnail generation failed');
    return null;
  }
}

export function removeFile(bucket, filename) {
  if (!filename) return;
  const base = path.basename(filename);
  const p = path.join(BUCKETS[bucket], base);
  fs.promises.unlink(p).catch(() => {});
  if (env.R2_ENABLED) {
    deleteFromR2(`${bucket}/${base}`).catch(() => {});
  }
}
