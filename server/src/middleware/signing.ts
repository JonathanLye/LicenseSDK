import { createHmac } from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { SHARED_SECRET, TIMESTAMP_TOLERANCE_MS } from '../config.js';

export function verifySignature(req: Request, res: Response, next: NextFunction): void {
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];

  if (!timestamp || !signature) {
    res.status(401).json({ error: 'Missing signature headers' });
    return;
  }

  const ts = Number(timestamp);
  if (isNaN(ts) || Math.abs(Date.now() - ts) > TIMESTAMP_TOLERANCE_MS) {
    res.status(403).json({ error: 'Request timestamp expired or invalid' });
    return;
  }

  const canonicalBody = JSON.stringify(req.body ?? {});
  const expected = createHmac('sha256', SHARED_SECRET)
    .update(`${timestamp}:${canonicalBody}`)
    .digest('hex');

  if (signature !== expected) {
    res.status(401).json({ error: 'Invalid signature' });
    return;
  }

  next();
}
