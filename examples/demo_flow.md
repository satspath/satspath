# SatsPath Demo Flow

This document shows a complete example session using the SatsPath CLI.

## Setup

```bash
cd ~/Desktop/satspath
cargo build --release
```

## Step-by-step

### 1. Initialize

```bash
satspath init
```

Output:

```
Created .satspath/registry.json
Created .satspath/keys.json

SatsPath initialized at .satspath/
NOTE: .satspath/ is git-ignored and stays local to this machine.
```

### 2. Register

```bash
satspath register rodrigo@satspath.dev
```

Output:

```
Registered: rodrigo@satspath.dev
Identity pubkey: 02a1b2c3...
Fingerprint:     a1b2c3d4

Payment methods registered:
  - Lightning Address
  - Bitcoin on-chain (primary)
  - Bitcoin on-chain (secondary, privacy address)
  - Ark

Profile signed and stored in .satspath/registry.json
DEMO secret key stored in .satspath/keys.json (git-ignored)
```

### 3. Show

```bash
satspath show rodrigo@satspath.dev
```

Output:

```
Alias:           rodrigo@satspath.dev
Identity pubkey: 02a1b2c3...
Fingerprint:     a1b2c3d4
Signature valid: yes
Updated at:      1735000000

Methods:
  - Lightning Address [Lightning]
      Lightning Address: rodrigo@satspath.dev
  - Bitcoin (primary) [On-chain]
      Address: bc1qa1b2...
  - Bitcoin (secondary) [On-chain]
      Address: bc1qb3c4...
  - Ark [Ark]
      Server: ark.satspath.dev
```

### 4. Encode a payment request

```bash
satspath encode rodrigo@satspath.dev 21000 --memo "coffee"
```

Output:

```
Encoded SatsPath URI:
satspath:v1:eyJ2ZXJzaW9uIjoxLCJhbGlhcyI6InJvZHJpZ29Ac2F0c3BhdGguZGV2IiwiYW1vdW50X3NhdHMiOjIxMDAwLCJtZW1vIjoiY29mZmVlIiwicHJvZmlsZV9oaW50IjpudWxsfQ
```

### 5. Decode

```bash
satspath decode "satspath:v1:eyJ2ZXJzaW9uIjoxLCJhbGlhcyI6InJvZHJpZ29Ac2F0c3BhdGguZGV2IiwiYW1vdW50X3NhdHMiOjIxMDAwLCJtZW1vIjoiY29mZmVlIiwicHJvZmlsZV9oaW50IjpudWxsfQ"
```

Output:

```
Decoded payment request:
  Version:     1
  Alias:       rodrigo@satspath.dev
  Amount:      21000 sats
  Memo:        coffee
  Profile hint:(none)
```

### 6. Get a quote

```bash
satspath quote rodrigo@satspath.dev 21000
```

Output:

```
Resolving alias 'rodrigo@satspath.dev'...
Verifying signature...
Signature valid.
Checking payment rails for 21000 sats...

Route Quote:
  Selected rail:   Lightning
  Label:           Lightning Address
  Reason:          Amount (21000 sats) is below 100000 sats threshold and Lightning is available.
  Estimated fee:   2 sats
  Confirmation:    instant
```

### 7. Simulate payment

```bash
satspath pay rodrigo@satspath.dev 21000
```

Output:

```
─────────────────────────────────────────
SatsPath Payment Simulation
─────────────────────────────────────────
Resolving alias 'rodrigo@satspath.dev'...
  Found profile.
Verifying signed profile...
  Signature valid.
Checking available payment rails...
  Route selected: Lightning

Selected route: Lightning
Reason:         Amount (21000 sats) is below 100000 sats threshold and Lightning is available.
Estimated fee:  2 sats

Executing simulated payment of 21000 sats to rodrigo@satspath.dev...
  [Lightning] Generating invoice from rodrigo@satspath.dev...
  [Lightning] Invoice received.
  [Lightning] Sending payment...

Payment status: simulated_success

DISCLAIMER: This is a simulation. No real Bitcoin was moved.
```

### 8. Invite flow for unknown user

```bash
satspath invite julian@example.com 21000
```

Output:

```
'julian@example.com' is not registered on SatsPath.

Invite link:
https://satspath.local/claim?alias_hash=a1b2c3d4e5f6g7h8&amount=21000

Alias hash:  sha256(julian@example.com)
Amount:      21000 sats
Created at:  1735000000

WARNING: The receiver must claim this payment by generating their own keys locally.
         SatsPath never holds or generates keys on behalf of users.
```

### 9. Run full demo automatically

```bash
satspath demo
```

Runs all of the above steps in sequence.
