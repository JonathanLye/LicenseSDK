export interface FingerprintDetail {
  motherboard?: string;
  disk?: string[];           // All physical disk serials
  bios?: string;
  volumeSerial?: string;
  cpu?: string;
  machineGuid?: string;
  windowsProductId?: string;
  mac?: string[];            // All physical MAC addresses
}

export interface License {
  id: string;
  product_id: string;
  license_key: string;
  type: 'single' | 'volume' | 'subscription';
  max_activations: number;
  expires_at: string | null;
  status: 'active' | 'revoked' | 'expired';
  metadata: Record<string, unknown>;
}

export interface Activation {
  id: string;
  license_id: string;
  machine_fingerprint_hash: string;
  fingerprint_detail: FingerprintDetail;
  activated_at: string;
  last_heartbeat: string | null;
  status: 'active' | 'deactivated';
}
