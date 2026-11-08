export class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message || code);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export const badRequest = (code, message, details) => new HttpError(400, code, message, details);
export const unauthorized = (code = 'unauthorized', message = 'Authentication required') =>
  new HttpError(401, code, message);
export const forbidden = (code = 'forbidden', message = 'Not allowed') => new HttpError(403, code, message);
export const notFound = (code = 'not_found', message = 'Resource not found') => new HttpError(404, code, message);
export const conflict = (code = 'conflict', message = 'Conflict') => new HttpError(409, code, message);
export const tooMany = (code = 'rate_limited', message = 'Too many requests', retryAfter) => {
  const error = new HttpError(429, code, message);
  if (retryAfter) error.retryAfter = retryAfter;
  return error;
};

/** Express 5 error handler: consistent JSON envelope. */
export function errorHandler(logger) {
  // eslint-disable-next-line no-unused-vars
  return (err, req, res, _next) => {
    if (err instanceof HttpError) {
      if (err.retryAfter) res.set('Retry-After', String(err.retryAfter));
      return res.status(err.status).json({
        success: false,
        error: { code: err.code, message: err.message, details: err.details },
      });
    }
    if (err?.name === 'MulterError') {
      return res.status(400).json({ success: false, error: { code: 'upload_error', message: err.message } });
    }
    if (typeof err?.message === 'string' && err.message.startsWith('Unsupported file type:')) {
      return res.status(400).json({ success: false, error: { code: 'unsupported_media_type', message: err.message } });
    }
    if (err?.type === 'entity.too.large') {
      return res.status(413).json({ success: false, error: { code: 'payload_too_large', message: 'Payload too large' } });
    }
    logger.error({ err, path: req.path }, 'unhandled error');
    res.status(500).json({ success: false, error: { code: 'internal_error', message: 'Internal server error' } });
  };
}
