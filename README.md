# LicenseSDK

Windows software licensing toolkit — hardware fingerprint-based activation, anti-tamper SDK, and management dashboard.

## Architecture

```
┌──────────┐     HMAC-SHA256     ┌──────────────┐     SQL     ┌──────────┐
│  Client  │ ──────────────────> │  API Server  │ ──────────> │ Supabase │
│ (App +   │ <────────────────── │  (Express)   │ <────────── │ (Postgres│
│  SDK)    │    JSON response     │              │            │  + RLS)  │
└──────────┘                     └──────────────┘            └──────────┘
```

- **SDK** — C# class library (net10.0-windows) embedded into client software
- **Server** — Express + TypeScript API for activation, verification, and management
- **Demo** — WPF desktop app for testing and integration reference

## Quick Start

### 1. Generate RSA keys

```bash
cd server
npm install
node scripts/gen-rsa.js
```

This creates:
- `.env-rsa` — append this line to your `.env`
- `sdk-fragments.txt` — paste the C# fragments into `sdk/LicenseSDK/Crypto/RsaVerifier.cs`

### 2. Configure environment

```bash
cp .env.example .env
cat .env-rsa >> .env   # add RSA private key
# Edit .env with your Supabase credentials
```

### 3. Run database migration

Execute `database/migrations/001_init.sql` in your Supabase SQL editor.

### 4. Start services

```bash
# Server
cd server
npm run dev

# SDK
dotnet build sdk/LicenseSDK

# Demo
dotnet build demo/LicenseDemo
dotnet run --project demo/LicenseDemo
```

### Admin Panel

Visit `http://localhost:3100/admin` after starting the server. Default admin secret is in `.env`.

## SDK Usage

```csharp
var license = new LicenseManager(new LicenseConfig
{
    ServerUrl    = "http://localhost:3100",
    SharedSecret = KeyProtector.Reveal(),
    ProductId    = "11111111-1111-1111-1111-111111111111",
});

// Activate
var result = await license.ActivateAsync("XXXX-XXXX-XXXX-XXXX");

// Verify
var status = await license.VerifyAsync();

// Deactivate
await license.DeactivateAsync();
```

## Features

### Fingerprint Matching
- 8 hardware sources with weighted scoring (motherboard, disks, BIOS, volume serial, CPU, machine GUID, Windows product ID, MAC addresses)
- Multi-candidate matching for disks and MACs (any match scores)
- OEM junk value filtering, tolerance for hardware changes

### Anti-Tamper
- All native API calls resolved at runtime via PE walking (zero import table entries)
- 30+ distributed check points with heartbeat cross-validation
- Debugger detection: PEB flags, NtQueryInformationProcess (3 methods), kernel32 API, window enumeration
- RE tool detection: 20+ tools via window class and process name
- Programmatic integrity verification via SHA-256

### Build-time Obfuscation
- Obfuscar: symbol renaming and string hiding
- BitMono: CallToCalli, AntiILdasm, AntiDe4dot, PE header manipulation

### Offline Support
- AES-256-GCM cache wrapped in DPAPI Machine Scope
- Graceful fallback with configurable grace period

## License

MIT
