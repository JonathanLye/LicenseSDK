import 'dotenv/config';
import express from 'express';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PORT } from './config.js';
import { verifySignature } from './middleware/signing.js';
import { activateRouter } from './routes/activate.js';
import { verifyRouter } from './routes/verify.js';
import { heartbeatRouter } from './routes/heartbeat.js';
import { deactivateRouter } from './routes/deactivate.js';
import { adminRouter } from './routes/admin.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());

// Serve admin management UI (static files)
app.use('/admin', express.static(join(__dirname, 'admin-ui')));

// Health check (no auth)
app.get('/health', (_req, res) => res.json({ ok: true }));

// Public verification API — all require request signing
app.use('/api/v1/activate', verifySignature, activateRouter);
app.use('/api/v1/verify', verifySignature, verifyRouter);
app.use('/api/v1/heartbeat', verifySignature, heartbeatRouter);
app.use('/api/v1/deactivate', verifySignature, deactivateRouter);

// Admin API — requires X-Admin-Secret header
app.use('/api/v1/admin', adminRouter);

app.listen(PORT, () => {
  console.log(`License server running on port ${PORT}`);
});
