import { supabase } from './config.js';

interface AuditParams {
  licenseId?: string;
  activationId?: string;
  eventType: string;
  machineFingerprintHash?: string;
  ipAddress?: string;
  success: boolean;
  detail?: Record<string, unknown>;
}

export async function writeAuditLog(params: AuditParams): Promise<void> {
  await supabase.from('audit_logs').insert({
    license_id: params.licenseId ?? null,
    activation_id: params.activationId ?? null,
    event_type: params.eventType,
    machine_fingerprint_hash: params.machineFingerprintHash ?? null,
    ip_address: params.ipAddress ?? null,
    success: params.success,
    detail: params.detail ?? {},
  });
}
