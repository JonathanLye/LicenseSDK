import { Router } from 'express';
import { z } from 'zod';
import { supabase } from '../config.js';
import { isSameMachine } from '../fingerprint.js';
import { writeAuditLog } from '../audit.js';
import type { FingerprintDetail } from '../types.js';

export const deactivateRouter = Router();

const DeactivateBody = z.object({
  license_key: z.string().min(1),
  activation_id: z.string().uuid(),
  fingerprint: z.object({
    motherboard:      z.string().nullish(),
    disk:             z.array(z.string()).nullish(),
    bios:             z.string().nullish(),
    volumeSerial:     z.string().nullish(),
    cpu:              z.string().nullish(),
    machineGuid:      z.string().nullish(),
    windowsProductId: z.string().nullish(),
    mac:              z.array(z.string()).nullish(),
  }),
});

deactivateRouter.post('/', async (req, res) => {
  const parsed = DeactivateBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body' });
    return;
  }

  const { license_key, activation_id, fingerprint } = parsed.data;
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0] ?? req.socket.remoteAddress ?? '';

  const { data: license } = await supabase
    .from('licenses')
    .select('id')
    .eq('license_key', license_key)
    .single();

  if (!license) {
    res.status(404).json({ error: 'License not found' });
    return;
  }

  const { data: activation } = await supabase
    .from('activations')
    .select('*')
    .eq('id', activation_id)
    .eq('license_id', license.id)
    .eq('status', 'active')
    .single();

  if (!activation) {
    res.status(404).json({ error: 'Activation not found' });
    return;
  }

  // Verify this machine owns the activation before allowing deactivation
  if (!isSameMachine(activation.fingerprint_detail as FingerprintDetail, fingerprint)) {
    await writeAuditLog({ licenseId: license.id, activationId: activation_id, eventType: 'reject', ipAddress: ip, success: false, detail: { reason: 'fingerprint_mismatch_on_deactivate' } });
    res.status(403).json({ error: 'Machine fingerprint mismatch' });
    return;
  }

  await supabase
    .from('activations')
    .update({ status: 'deactivated' })
    .eq('id', activation_id);

  await writeAuditLog({ licenseId: license.id, activationId: activation_id, eventType: 'deactivate', ipAddress: ip, success: true });

  res.json({ ok: true });
});
