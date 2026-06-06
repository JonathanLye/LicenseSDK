import { createSign } from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { RSA_PRIVATE_KEY } from '../config.js';

const privateKey = Buffer.from(RSA_PRIVATE_KEY, 'base64').toString('utf8');

export function signResponse(_req: Request, res: Response, next: NextFunction): void {
  const originalJson = res.json.bind(res);

  res.json = function (body: unknown) {
    const canonical = JSON.stringify(body);
    const sign = createSign('sha256');
    sign.update(canonical);
    const signature = sign.sign(privateKey, 'base64');

    res.setHeader('X-Response-Signature', signature);
    return originalJson(body);
  };

  next();
}
