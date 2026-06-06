import { Router } from 'express';
import { z } from 'zod';
import { supabase } from '../config.js';
import { isSameMachine } from '../fingerprint.js';
import { writeAuditLog } from '../audit.js';
import type { FingerprintDetail, Activation } from '../types.js';

export const verifyRouter = Router();

const VerifyBody = z.object({
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

verifyRouter.post('/', async (req, res) => {
  const parsed = VerifyBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body' });
    return;
  }

  const { license_key, activation_id, fingerprint } = parsed.data;
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0] ?? req.socket.remoteAddress ?? '';

  const { data: license } = await supabase
    .from('licenses')
    .select('*')
    .eq('license_key', license_key)
    .single();

  if (!license) {
    res.status(404).json({ error: 'License not found', valid: false });
    return;
  }

  if (license.status !== 'active') {
    await writeAuditLog({ licenseId: license.id, activationId: activation_id, eventType: 'verify', ipAddress: ip, success: false, detail: { reason: license.status } });
    res.status(403).json({ error: `License is ${license.status}`, valid: false });
    return;
  }

  if (license.expires_at && new Date(license.expires_at) < new Date()) {
    await writeAuditLog({ licenseId: license.id, activationId: activation_id, eventType: 'verify', ipAddress: ip, success: false, detail: { reason: 'expired' } });
    res.status(403).json({ error: 'License has expired', valid: false });
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
    await writeAuditLog({ licenseId: license.id, activationId: activation_id, eventType: 'verify', ipAddress: ip, success: false, detail: { reason: 'activation_not_found' } });
    res.status(403).json({ error: 'Activation not found or inactive', valid: false });
    return;
  }

  // Verify this machine still matches (catches hardware swap attacks)
  if (!isSameMachine(activation.fingerprint_detail as FingerprintDetail, fingerprint)) {
    await writeAuditLog({ licenseId: license.id, activationId: activation_id, eventType: 'verify', ipAddress: ip, success: false, detail: { reason: 'fingerprint_mismatch' } });
    res.status(403).json({ error: 'Machine fingerprint mismatch', valid: false });
    return;
  }

  // Update heartbeat
  await supabase
    .from('activations')
    .update({ last_heartbeat: new Date().toISOString() })
    .eq('id', activation_id);

  await writeAuditLog({ licenseId: license.id, activationId: activation_id, eventType: 'verify', ipAddress: ip, success: true });

  res.json({ valid: true, expires_at: license.expires_at, license_type: license.type });
});
