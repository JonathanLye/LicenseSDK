import { Router } from 'express';
import { z } from 'zod';
import { supabase } from '../config.js';

export const heartbeatRouter = Router();

const HeartbeatBody = z.object({
  activation_id: z.string().uuid(),
});

heartbeatRouter.post('/', async (req, res) => {
  const parsed = HeartbeatBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body' });
    return;
  }

  const { activation_id } = parsed.data;

  const { error } = await supabase
    .from('activations')
    .update({ last_heartbeat: new Date().toISOString() })
    .eq('id', activation_id)
    .eq('status', 'active');

  if (error) {
    res.status(500).json({ error: 'Failed to update heartbeat' });
    return;
  }

  res.json({ ok: true });
});
