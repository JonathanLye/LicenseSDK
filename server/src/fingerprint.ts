import { createHash } from 'crypto';
import { FINGERPRINT_WEIGHTS, FINGERPRINT_MATCH_THRESHOLD } from './config.js';
import type { FingerprintDetail } from './types.js';

/** Fields whose values are string arrays — any element match scores the weight. */
const ARRAY_FIELDS = new Set(['disk', 'mac']);

/**
 * Check whether a string or string-array field value from `stored`
 * matches the corresponding field in `incoming`.
 * For scalar fields: exact string match.
 * For array fields: any element in common between stored and incoming arrays.
 */
function fieldMatches(
  stored: string | string[] | undefined,
  incoming: string | string[] | undefined,
): boolean {
  if (stored === undefined || incoming === undefined) return false;
  if (stored === null || incoming === null) return false;

  const s = Array.isArray(stored) ? stored : [stored];
  const i = Array.isArray(incoming) ? incoming : [incoming];

  return s.some(sv => i.includes(sv));
}

export function hashFingerprint(detail: FingerprintDetail): string {
  // Canonical: sort keys, join as "key=value" pairs
  const canonical = Object.entries(FINGERPRINT_WEIGHTS)
    .map(([k]) => {
      const val = (detail as Record<string, unknown>)[k];
      const str = Array.isArray(val) ? (val as string[]).sort().join(',') : (val ?? '');
      return `${k}=${str}`;
    })
    .join('|');
  return createHash('sha256').update(canonical).digest('hex');
}

export function isSameMachine(stored: FingerprintDetail, incoming: FingerprintDetail): boolean {
  let matched = 0;
  for (const [source, weight] of Object.entries(FINGERPRINT_WEIGHTS)) {
    const s = (stored as Record<string, unknown>)[source] as string | string[] | undefined;
    const i = (incoming as Record<string, unknown>)[source] as string | string[] | undefined;

    if (ARRAY_FIELDS.has(source)) {
      // Array fields: any element in common scores the weight
      if (fieldMatches(s, i)) matched += weight;
    } else {
      // Scalar fields: exact match required
      if (s && i && String(s) === String(i)) matched += weight;
    }
  }
  return matched >= FINGERPRINT_MATCH_THRESHOLD;
}
