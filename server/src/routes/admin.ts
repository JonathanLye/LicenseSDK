import { Router } from 'express';
import { z } from 'zod';
import { supabase } from '../config.js';
import { requireAdmin } from '../middleware/admin.js';

export const adminRouter = Router();

adminRouter.use(requireAdmin);

// Issue a new license
const IssueLicenseBody = z.object({
  product_id: z.string().uuid(),
  license_key: z.string().min(8),
  type: z.enum(['single', 'volume', 'subscription']),
  max_activations: z.number().int().min(1).default(1),
  expires_at: z.string().datetime().nullable().default(null),
  metadata: z.record(z.unknown()).default({}),
});

adminRouter.post('/licenses', async (req, res) => {
  const parsed = IssueLicenseBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body', details: parsed.error.flatten() });
    return;
  }

  const { data, error } = await supabase.from('licenses').insert(parsed.data).select().single();
  if (error) {
    res.status(500).json({ error: error.message });
    return;
  }
  res.status(201).json(data);
});

// List licenses (with optional product_id filter)
adminRouter.get('/licenses', async (req, res) => {
  let query = supabase.from('licenses').select('*, activations(count)').order('created_at', { ascending: false });
  if (req.query.product_id) query = query.eq('product_id', req.query.product_id);
  const { data, error } = await query;
  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json(data);
});

// Revoke a license
adminRouter.post('/licenses/:id/revoke', async (req, res) => {
  const { error } = await supabase
    .from('licenses')
    .update({ status: 'revoked' })
    .eq('id', req.params.id);
  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json({ ok: true });
});

// List activations for a license
adminRouter.get('/licenses/:id/activations', async (req, res) => {
  const { data, error } = await supabase
    .from('activations')
    .select('*')
    .eq('license_id', req.params.id)
    .order('activated_at', { ascending: false });
  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json(data);
});

// Force-deactivate a specific activation (admin override)
adminRouter.post('/activations/:id/deactivate', async (req, res) => {
  const { error } = await supabase
    .from('activations')
    .update({ status: 'deactivated' })
    .eq('id', req.params.id);
  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json({ ok: true });
});

// Audit logs
adminRouter.get('/audit-logs', async (req, res) => {
  let query = supabase
    .from('audit_logs')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(200);
  if (req.query.license_id) query = query.eq('license_id', req.query.license_id);
  const { data, error } = await query;
  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json(data);
});

// Create product
adminRouter.post('/products', async (req, res) => {
  const { name, description } = req.body as { name?: string; description?: string };
  if (!name) { res.status(400).json({ error: 'name is required' }); return; }
  const { data, error } = await supabase.from('products').insert({ name, description }).select().single();
  if (error) { res.status(500).json({ error: error.message }); return; }
  res.status(201).json(data);
});

// List products
adminRouter.get('/products', async (req, res) => {
  const { data, error } = await supabase.from('products').select('*').order('created_at', { ascending: false });
  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json(data);
});
