import { Router } from 'express';
import { z } from 'zod';
import { supabase } from '../config.js';
import { hashFingerprint, isSameMachine } from '../fingerprint.js';
import { writeAuditLog } from '../audit.js';
import type { FingerprintDetail, Activation } from '../types.js';

export const activateRouter = Router();

const ActivateBody = z.object({
  license_key: z.string().min(1),
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

activateRouter.post('/', async (req, res) => {
  const parsed = ActivateBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body', details: parsed.error.flatten() });
    return;
  }

  const { license_key, fingerprint } = parsed.data;
  const fingerprintHash = hashFingerprint(fingerprint);
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0] ?? req.socket.remoteAddress ?? '';

  // Load license
  const { data: license, error: licErr } = await supabase
    .from('licenses')
    .select('*')
    .eq('license_key', license_key)
    .single();

  if (licErr || !license) {
    await writeAuditLog({ eventType: 'reject', machineFingerprintHash: fingerprintHash, ipAddress: ip, success: false, detail: { reason: 'license_not_found', license_key } });
    res.status(404).json({ error: 'License not found' });
    return;
  }

  if (license.status === 'revoked') {
    await writeAuditLog({ licenseId: license.id, eventType: 'reject', machineFingerprintHash: fingerprintHash, ipAddress: ip, success: false, detail: { reason: 'revoked' } });
    res.status(403).json({ error: 'License has been revoked' });
    return;
  }

  if (license.status === 'expired' || (license.expires_at && new Date(license.expires_at) < new Date())) {
    await writeAuditLog({ licenseId: license.id, eventType: 'reject', machineFingerprintHash: fingerprintHash, ipAddress: ip, success: false, detail: { reason: 'expired' } });
    res.status(403).json({ error: 'License has expired' });
    return;
  }

  // Load active activations for this license
  const { data: activations } = await supabase
    .from('activations')
    .select('*')
    .eq('license_id', license.id)
    .eq('status', 'active');

  const existing = activations ?? [];

  // Check if this machine is already activated (fuzzy match)
  const alreadyActivated = existing.find((a: Activation) =>
    isSameMachine(a.fingerprint_detail as FingerprintDetail, fingerprint)
  );

  if (alreadyActivated) {
    // Update heartbeat and return success — idempotent re-activation
    await supabase
      .from('activations')
      .update({ last_heartbeat: new Date().toISOString() })
      .eq('id', alreadyActivated.id);

    await writeAuditLog({ licenseId: license.id, activationId: alreadyActivated.id, eventType: 'activate', machineFingerprintHash: fingerprintHash, ipAddress: ip, success: true, detail: { reactivation: true } });

    res.json({ activation_id: alreadyActivated.id, status: 'active', expires_at: license.expires_at });
    return;
  }

  // Check device limit
  if (existing.length >= license.max_activations) {
    await writeAuditLog({ licenseId: license.id, eventType: 'reject', machineFingerprintHash: fingerprintHash, ipAddress: ip, success: false, detail: { reason: 'device_limit', current: existing.length, max: license.max_activations } });
    res.status(403).json({ error: 'Maximum activation limit reached', max: license.max_activations });
    return;
  }

  // Create new activation
  const { data: activation, error: actErr } = await supabase
    .from('activations')
    .insert({
      license_id: license.id,
      machine_fingerprint_hash: fingerprintHash,
      fingerprint_detail: fingerprint,
      last_heartbeat: new Date().toISOString(),
    })
    .select()
    .single();

  if (actErr || !activation) {
    res.status(500).json({ error: 'Failed to create activation' });
    return;
  }

  await writeAuditLog({ licenseId: license.id, activationId: activation.id, eventType: 'activate', machineFingerprintHash: fingerprintHash, ipAddress: ip, success: true });

  res.status(201).json({ activation_id: activation.id, status: 'active', expires_at: license.expires_at });
});
