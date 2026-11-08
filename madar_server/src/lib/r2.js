import fs from 'node:fs';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { env } from '../config/env.js';
import { logger } from './logger.js';

/** @type {S3Client | null} */
export let r2Client = null;

if (env.R2_ENDPOINT && env.R2_ACCESS_KEY_ID && env.R2_SECRET_ACCESS_KEY) {
  r2Client = new S3Client({
    region: 'auto',
    endpoint: env.R2_ENDPOINT,
    forcePathStyle: true,
    credentials: {
      accessKeyId: env.R2_ACCESS_KEY_ID,
      secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    },
  });
}

/**
 * Generates a pre-signed PUT URL for direct client-to-R2 encrypted blob uploads.
 */
export async function createR2UploadUrl({ key, contentType = 'application/octet-stream', contentLength, expiresIn = 600 }) {
  if (!r2Client) throw new Error('R2 client is not configured');
  const command = new PutObjectCommand({
    Bucket: env.R2_BUCKET_NAME,
    Key: key,
    ContentType: contentType,
    ...(contentLength ? { ContentLength: contentLength } : {}),
  });
  const uploadUrl = await getSignedUrl(r2Client, command, { expiresIn });
  const publicUrl = env.R2_PUBLIC_URL
    ? `${env.R2_PUBLIC_URL.replace(/\/$/, '')}/${key}`
    : await createR2DownloadUrl({ key, expiresIn: 7 * 86400 });
  return { uploadUrl, publicUrl, key };
}

/**
 * Generates a pre-signed GET URL for downloading a stored R2 object.
 */
export async function createR2DownloadUrl({ key, expiresIn = 86400 }) {
  if (env.R2_PUBLIC_URL) {
    return `${env.R2_PUBLIC_URL.replace(/\/$/, '')}/${key}`;
  }
  if (!r2Client) throw new Error('R2 client is not configured');
  const command = new GetObjectCommand({
    Bucket: env.R2_BUCKET_NAME,
    Key: key,
  });
  return getSignedUrl(r2Client, command, { expiresIn });
}

/**
 * Uploads a local file directly to Cloudflare R2 (when R2_ENABLED=true).
 */
export async function uploadFileToR2(localPath, key, contentType = 'application/octet-stream') {
  if (!env.R2_ENABLED) return null;
  try {
    const body = await fs.promises.readFile(localPath);
    if (env.R2_ACCOUNT_ID && env.R2_API_TOKEN) {
      const url = `https://api.cloudflare.com/client/v4/accounts/${env.R2_ACCOUNT_ID}/r2/buckets/${env.R2_BUCKET_NAME}/objects/${encodeURIComponent(key).replace(/%2F/g, '/')}`;
      const res = await fetch(url, {
        method: 'PUT',
        headers: {
          Authorization: `Bearer ${env.R2_API_TOKEN}`,
          'Content-Type': contentType,
        },
        body,
      });
      if (!res.ok) throw new Error(`Cloudflare R2 API HTTP ${res.status}`);
    } else if (r2Client) {
      await r2Client.send(
        new PutObjectCommand({
          Bucket: env.R2_BUCKET_NAME,
          Key: key,
          Body: body,
          ContentType: contentType,
        }),
      );
    } else {
      return null;
    }
    return env.R2_PUBLIC_URL ? `${env.R2_PUBLIC_URL.replace(/\/$/, '')}/${key}` : `/media/${key}`;
  } catch (err) {
    logger.warn({ err: err.message, key }, 'r2: upload failed, falling back to local disk');
    return null;
  }
}

export async function deleteFromR2(key) {
  if (!env.R2_ENABLED) return;
  try {
    if (env.R2_ACCOUNT_ID && env.R2_API_TOKEN) {
      const url = `https://api.cloudflare.com/client/v4/accounts/${env.R2_ACCOUNT_ID}/r2/buckets/${env.R2_BUCKET_NAME}/objects/${encodeURIComponent(key).replace(/%2F/g, '/')}`;
      await fetch(url, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${env.R2_API_TOKEN}` },
      });
    } else if (r2Client) {
      await r2Client.send(
        new DeleteObjectCommand({
          Bucket: env.R2_BUCKET_NAME,
          Key: key,
        }),
      );
    }
  } catch (err) {
    logger.warn({ err: err.message, key }, 'r2: delete failed');
  }
}
