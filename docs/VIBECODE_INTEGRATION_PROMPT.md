# ⚡ SatsPath AI / Vibe-Coding Integration Prompt

> **Instructions for Developers:**  
> Copy and paste the entire prompt below directly into your AI coding assistant (**Cursor**, **Claude**, **ChatGPT**, **Windsurf**, **Antigravity**, or **Copilot**) to automatically integrate **SatsPath v2** multi-rail resolution and human-readable identities into your Bitcoin/Ark wallet.

---

```markdown
You are an expert Bitcoin, Lightning, Ark Protocol, and TypeScript engineer.
Your task is to integrate the SatsPath protocol SDK (`@satspath/wasm`) into our wallet application.

### 🎯 Goal
Allow users of our wallet to:
1. **Receive:** Have a human-readable identity (e.g., `user@domain.com` or `user@satspath.dev`) that automatically publishes and signs their public receiving methods (Lightning Address, Ark VTXO pubkey, and On-chain Bitcoin address).
2. **Send:** Enter human-readable aliases with `@` into the Send screen, automatically resolve the best payment route via SatsPath Smart Routing, and execute the payment using our wallet's existing payment functions.

---

### 📦 1. Installation & Setup
Run the following package manager command in the wallet repository:
```bash
pnpm add @satspath/wasm bip39 react-qr-code
```

---

### 🛡️ 2. Core Architectural & Security Rules (MUST FOLLOW)
1. **Zero Custody / Strict Isolation:**
   - NEVER transmit or expose the user's mnemonic or seed bytes.
   - SatsPath identity derivation happens strictly inside the trusted wallet boundary under HMAC-SHA512 `m/9737'/0'`.
   - SatsPath identity keys sign public profiles only. They DO NOT touch Bitcoin spending keys (`xprv`/`tprv`).
2. **Fail-Closed Resolution:**
   - If a recipient's profile signature is invalid, reject the quote immediately.
   - Treat `QuoteResponse` with granular status checks (`ok`, `invalid_signature`, `no_route`, `not_registered`).
3. **Smart Multi-Rail Routing:**
   - SatsPath returns a unified payment payload (`quoteResult.qr`):
     - If Lightning: BOLT11 invoice (`lnbc...`) or BOLT12 offer (`lno...`).
     - If Ark: Ark payment URI (`ark:<pubkey>?server=...&amount=...`).
     - If On-Chain: BIP-21 URI (`bitcoin:bc1q...?amount=...`).

---

### 💻 3. Implementation Code Blocks

#### A. Hook 1: Initialize Identity & Auto-Register Profile (`useSatsPathIdentity.ts`)
```typescript
import { useEffect, useState } from 'react';
import init, { derive_identity_keypair_from_seed, sign_profile } from '@satspath/wasm';

export interface SatsPathIdentity {
  pubkey_hex: string;
  secret_key_hex: string;
}

export function useSatsPathIdentity(seedBytes: Uint8Array | null) {
  const [identity, setIdentity] = useState<SatsPathIdentity | null>(null);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    async function setup() {
      await init();
      if (seedBytes && seedBytes.length > 0) {
        const id = derive_identity_keypair_from_seed(seedBytes, 0);
        if (id) {
          setIdentity(id);
        }
      }
      setIsReady(true);
    }
    setup();
  }, [seedBytes]);

  /**
   * Automatically builds, signs, and registers the user's public payment methods.
   */
  const publishProfile = async (
    chosenAlias: string, // e.g. "alice@satspath.dev"
    methods: {
      lightningAddress?: string;
      onchainAddress?: string;
      arkServer?: string;
      arkPubkey?: string;
    },
    authorityServerUrl = "https://satspath.dev"
  ) => {
    if (!identity) throw new Error("SatsPath identity not derived yet");

    const paymentMethods: any[] = [];
    if (methods.lightningAddress) {
      paymentMethods.push({
        type: "Lightning",
        lightning_address: methods.lightningAddress,
      });
    }
    if (methods.onchainAddress) {
      paymentMethods.push({
        type: "Onchain",
        address: methods.onchainAddress,
      });
    }
    if (methods.arkServer && methods.arkPubkey) {
      paymentMethods.push({
        type: "Ark",
        server: methods.arkServer,
        pubkey: methods.arkPubkey,
      });
    }

    const profile = {
      alias: chosenAlias,
      identity_pubkey: identity.pubkey_hex,
      methods: paymentMethods,
      updated_at: Math.floor(Date.now() / 1000),
      sequence: 1,
      preferences: ["Lightning", "Ark", "Onchain"],
      revoked: false,
    };

    // Sign profile with identity secret key
    const signedProfile = sign_profile(JSON.stringify(profile), identity.secret_key_hex);

    // Register on the authoritative SatsPath S2S server
    const res = await fetch(`${authorityServerUrl}/v1/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(signedProfile),
    });

    if (!res.ok) {
      throw new Error(`Failed to publish profile: ${res.statusText}`);
    }

    return signedProfile;
  };

  return { identity, isReady, publishProfile };
}
```

---

#### B. Hook 2: Intercept & Route Payments on Send Screen (`useSatsPathSend.ts`)
```typescript
import { quote } from '@satspath/wasm';

export interface RouteQuoteResult {
  status: 'ok' | 'invalid_signature' | 'no_route' | 'not_registered' | 'error';
  selectedRail?: 'Lightning' | 'Ark' | 'Onchain';
  estimatedFeeSats?: number;
  paymentPayload?: string;
  errorMessage?: string;
}

export async function resolveAndQuotePayment(
  recipient: string,
  amountSats: bigint
): Promise<RouteQuoteResult> {
  // If recipient is a SatsPath alias (e.g. user@domain.com)
  if (recipient.includes('@') && !recipient.startsWith('lnbc') && !recipient.startsWith('bc1')) {
    try {
      const result = await quote(recipient, amountSats);

      if (result.status === 'ok') {
        return {
          status: 'ok',
          selectedRail: result.selected_method.type,
          estimatedFeeSats: Number(result.fee_sats),
          paymentPayload: result.qr,
        };
      } else if (result.status === 'invalid_signature') {
        return {
          status: 'invalid_signature',
          errorMessage: `Cryptographic signature mismatch for ${result.recipient?.alias}`,
        };
      } else if (result.status === 'no_route') {
        return {
          status: 'no_route',
          errorMessage: result.reason || 'No compatible payment route found',
        };
      } else if (result.status === 'not_registered') {
        return {
          status: 'not_registered',
          errorMessage: 'Recipient alias is not registered on SatsPath',
        };
      }
    } catch (err: any) {
      return {
        status: 'error',
        errorMessage: err.message || 'Resolution error',
      };
    }
  }

  // If standard address/invoice was pasted directly
  return {
    status: 'ok',
    paymentPayload: recipient,
  };
}
```

---

#### C. Component: Send Screen Interceptor Integration
In your existing `SendScreen` or `SendModal`:
```tsx
import React, { useState } from 'react';
import { resolveAndQuotePayment, RouteQuoteResult } from './useSatsPathSend';

export function SendForm({ onExecutePayment }: { onExecutePayment: (payload: string) => Promise<void> }) {
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('1000');
  const [quoteState, setQuoteState] = useState<RouteQuoteResult | null>(null);
  const [loading, setLoading] = useState(false);

  const handleQuote = async () => {
    setLoading(true);
    const res = await resolveAndQuotePayment(recipient, BigInt(amount));
    setQuoteState(res);
    setLoading(false);
  };

  const handlePay = async () => {
    if (quoteState?.paymentPayload) {
      // Pass the resolved QR/Invoice payload directly into host wallet execution!
      await onExecutePayment(quoteState.paymentPayload);
    }
  };

  return (
    <div className="p-4 bg-zinc-900 text-white rounded-xl border border-zinc-800 space-y-4">
      <div>
        <label className="text-xs text-zinc-400">Recipient (Alias, Lightning, or BTC Address)</label>
        <input
          className="w-full bg-black border border-zinc-700 p-2 rounded text-white"
          placeholder="alice@satspath.dev"
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
        />
      </div>

      <div>
        <label className="text-xs text-zinc-400">Amount (Sats)</label>
        <input
          type="number"
          className="w-full bg-black border border-zinc-700 p-2 rounded text-white"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
      </div>

      <button
        onClick={handleQuote}
        disabled={loading}
        className="w-full bg-red-600 hover:bg-red-500 font-bold py-2 rounded transition"
      >
        {loading ? 'Resolving...' : 'Evaluate Route'}
      </button>

      {quoteState?.status === 'ok' && (
        <div className="p-3 bg-black/60 border border-red-500/40 rounded space-y-2">
          <div className="flex justify-between text-sm">
            <span>Optimal Rail:</span>
            <span className="font-bold text-red-400">{quoteState.selectedRail}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span>Estimated Fee:</span>
            <span>{quoteState.estimatedFeeSats} sats</span>
          </div>
          <button
            onClick={handlePay}
            className="w-full bg-green-600 hover:bg-green-500 font-bold py-2 rounded text-white mt-2"
          >
            Confirm & Pay
          </button>
        </div>
      )}

      {quoteState && quoteState.status !== 'ok' && (
        <div className="p-3 bg-red-950/50 border border-red-800 rounded text-red-300 text-sm">
          {quoteState.errorMessage}
        </div>
      )}
    </div>
  );
}
```

---

### 🚀 Tasks for the AI Assistant:
1. Identify where our wallet project handles **Wallet Initialization / Settings** and inject `useSatsPathIdentity`.
2. Locate our wallet's **Send Screen / Input Field** and hook up `resolveAndQuotePayment`.
3. Verify that `pnpm install` builds smoothly without TypeScript or linter errors.
```
