import { describe, it, expect, vi } from 'vitest';
import { createHmac } from 'crypto';

// Must use string literal in vi.mock factory — no top-level variable references (hoisting)
vi.mock('../config.js', () => ({
  SHARED_SECRET: 'test-secret-at-least-32-characters-long',
  TIMESTAMP_TOLERANCE_MS: 5 * 60 * 1000,
  FINGERPRINT_WEIGHTS: {
    motherboard:      32,
    disk:             28,
    bios:             18,
    volumeSerial:     10,
    cpu:              6,
    machineGuid:      4,
    windowsProductId: 1,
    mac:              1,
  },
  FINGERPRINT_MATCH_THRESHOLD: 60,
  supabase: {},
}));

const SECRET = 'test-secret-at-least-32-characters-long';

function makeSignature(timestamp: number, body: unknown): string {
  return createHmac('sha256', SECRET)
    .update(`${timestamp}:${JSON.stringify(body)}`)
    .digest('hex');
}

import { isSameMachine } from '../fingerprint.js';
import type { FingerprintDetail } from '../types.js';

describe('isSameMachine', () => {
  const base: FingerprintDetail = {
    motherboard:      'MB-SERIAL-001',
    disk:             ['DISK-SERIAL-001', 'DISK-SERIAL-002'],
    bios:             'BIOS-SERIAL-001',
    volumeSerial:     'ABCD1234',
    cpu:              'CPU-ID-001',
    machineGuid:      'GUID-001',
    windowsProductId: 'WIN-PROD-001',
    mac:              ['AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'],
  };

  it('returns true when all 8 fields match (100 weight)', () => {
    expect(isSameMachine(base, { ...base })).toBe(true);
  });

  it('returns true when only top-3 fields match (MB+disk+bios = 78)', () => {
    expect(isSameMachine(base, {
      motherboard: base.motherboard,
      disk:        base.disk,
      bios:        base.bios,
    })).toBe(true);
  });

  it('returns true when motherboard changed but remaining sum = 68', () => {
    const incoming: FingerprintDetail = { ...base, motherboard: 'CHANGED' };
    expect(isSameMachine(base, incoming)).toBe(true);
  });

  it('returns false when MB+disk lost (bios+volumeSerial+cpu+guid+win+macz = 40)', () => {
    const incoming: FingerprintDetail = {
      bios:             base.bios,
      volumeSerial:     base.volumeSerial,
      cpu:              base.cpu,
      machineGuid:      base.machineGuid,
      windowsProductId: base.windowsProductId,
      mac:              base.mac,
    };
    expect(isSameMachine(base, incoming)).toBe(false);
  });

  // ── Multi-candidate (array) matching ─────────────────────────

  it('scores disk when one of stored arrays matches one of incoming (any-match)', () => {
    // base.disk = [A, B]; incoming.disk = [B, C] → B matches → 28 points
    const incoming: FingerprintDetail = {
      ...base,
      disk: ['DISK-SERIAL-002', 'DISK-SERIAL-003'],  // 002 in common
      motherboard: 'CHANGED',                         // lose 32
    };
    // MB(0) + disk(28) + bios(18) + vol(10) + cpu(6) + guid(4) + win(1) + mac(1) = 68
    expect(isSameMachine(base, incoming)).toBe(true);
  });

  it('scores mac when one MAC matches (any-match)', () => {
    // mac = 1 weight, but useful for edge cases
    const incoming: FingerprintDetail = {
      ...base,
      mac:         ['11:22:33:44:55:66'],          // keep one
      motherboard: 'CHANGED',                       // -32
      bios:        'CHANGED',                       // -18
    };
    // 28(disk) + 10(vol) + 6(cpu) + 4(guid) + 1(win) + 1(mac) = 50 → false
    expect(isSameMachine(base, incoming)).toBe(false);
  });

  it('returns false when no fields match', () => {
    expect(isSameMachine(base, {
      motherboard: 'X', disk: ['X'], bios: 'X', volumeSerial: 'X',
      cpu: 'X', machineGuid: 'X', windowsProductId: 'X', mac: ['X'],
    })).toBe(false);
  });

  it('returns false when stored fields are empty', () => {
    expect(isSameMachine({}, { motherboard: 'MB-SERIAL-001' })).toBe(false);
  });
});

describe('request signing', () => {
  it('produces consistent HMAC-SHA256 signatures', () => {
    const ts = 1000000;
    const body = { license_key: 'XXXX-XXXX-XXXX-XXXX' };
    const sig1 = makeSignature(ts, body);
    const sig2 = makeSignature(ts, body);
    expect(sig1).toBe(sig2);
    expect(sig1).toHaveLength(64);
  });

  it('different timestamps produce different signatures', () => {
    const body = { license_key: 'XXXX' };
    expect(makeSignature(1000, body)).not.toBe(makeSignature(2000, body));
  });

  it('different bodies produce different signatures', () => {
    const ts = 1000000;
    expect(makeSignature(ts, { a: 1 })).not.toBe(makeSignature(ts, { a: 2 }));
  });
});
