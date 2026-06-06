import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';

const required = (key: string): string => {
  const val = process.env[key];
  if (!val) throw new Error(`Missing required env var: ${key}`);
  return val;
};

export const PORT = Number(process.env.PORT ?? 3100);
export const SHARED_SECRET = required('SHARED_SECRET');
export const ADMIN_SECRET = required('ADMIN_SECRET');

export const supabase = createClient(
  required('SUPABASE_URL'),
  required('SUPABASE_SERVICE_ROLE_KEY'),
  { auth: { persistSession: false } }
);

// Fingerprint weights — must sum to 100 for intuitive threshold
export const FINGERPRINT_WEIGHTS = {
  motherboard:      32,
  disk:             28,   // string[] — any match scores
  bios:             18,
  volumeSerial:     10,
  cpu:              6,
  machineGuid:      4,
  windowsProductId: 1,
  mac:              1,    // string[] — any match scores
} as const;

export const FINGERPRINT_MATCH_THRESHOLD = 60;

// Reject requests older than this
export const TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000;
