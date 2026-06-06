import type { Request, Response, NextFunction } from 'express';
import { ADMIN_SECRET } from '../config.js';

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}
