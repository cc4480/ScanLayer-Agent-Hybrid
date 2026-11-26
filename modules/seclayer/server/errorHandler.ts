import type { NextFunction, Request, Response } from 'express';

// The JSON error handler. Thrown route errors come out as structured JSON with no stack trace.
//
// It used to answer EVERYTHING with a 500, which was wrong for the errors a client causes on
// purpose or by accident: body-parser rejects a malformed JSON body or one over the size cap with
// an error that already carries the right 4xx status. Reporting those as server failures sent
// every typo'd request to the error log as if the app had broken, and told API clients (and the
// uptime monitor) the wrong thing. A 4xx raised that way is passed through with a fixed, safe
// message; anything else is still an opaque 500.
const CLIENT_ERRORS: Record<string, { status: number; message: string }> = {
  'entity.parse.failed': { status: 400, message: 'The request body is not valid JSON.' },
  'entity.too.large': { status: 413, message: 'The request body is too large.' },
  'encoding.unsupported': { status: 415, message: 'The request body encoding is not supported.' },
  'request.aborted': { status: 400, message: 'The request was aborted before it finished.' },
  'charset.unsupported': { status: 415, message: 'The request body charset is not supported.' },
};

export function jsonErrorHandler(err: any, req: Request, res: Response, next: NextFunction) {
  if (res.headersSent) return next(err);

  const known = typeof err?.type === 'string' ? CLIENT_ERRORS[err.type] : undefined;
  if (known) {
    // The client's mistake, not ours: no error-level log, and the parser's own message (which can
    // quote a fragment of the body) is never echoed.
    return res.status(known.status).json({ status: 'error', message: known.message });
  }

  console.error('[server] Unhandled route error:', err?.message || err);
  res.status(500).json({ status: 'error', message: 'An unexpected server error occurred.' });
}
