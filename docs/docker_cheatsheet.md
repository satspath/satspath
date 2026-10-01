# 🐳 SatsPath Docker Cheat Sheet

This guide contains all necessary commands to build, run, and test the full functionality of **SatsPath** securely using Docker containers.

> **NOTE:**
> Since the CLI container runs ephemerally, the standard format to execute any command is:
> `docker compose run --rm satspath-cli <command>`

---

## 1. Build and Base Environment

Before running commands, build the container images and launch the background daemon:

```bash
# Build all images (CLI, Daemon, and Ark Bridge)
docker compose build

# Start the local Daemon (satspathd) in background
docker compose up -d satspathd

# Verify the Daemon is running and healthy (Healthcheck)
docker compose ps
```

---

## 2. Wallet and Profile Initialization

SatsPath operates as a "receiver-profile" wallet. It manages your identity and public payment methods without taking custody of funds.

> **NETWORK NOTICE:** The `docker-compose.yml` stack defaults to `SATSPATH_NETWORK=mainnet`.
> The examples below use testnet methods and addresses (`tb1...`). Before executing them,
> ensure you set `SATSPATH_NETWORK=testnet` in your environment or `docker-compose.yml`.
> Never publish testnet receive methods to a mainnet profile.

```bash
# 1. Initialize cryptographic identity keys
docker compose run --rm satspath-cli wallet init

# 2. Register your alias and configure public payment methods
docker compose run --rm satspath-cli wallet add-methods bob@satspath.local \
    --lightning-address bob@getalby.com \
    --onchain-address tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx \
    --ark-server https://ark-testnet.example.com \
    --ark-pubkey 025b90f4a...

# 3. View current profile and cryptographic signature status
docker compose run --rm satspath-cli wallet show
```

---

## 3. Resolving Payments (Simulations and Quotes)

Before sending a payment, SatsPath evaluates network fees, urgency, and counterparty receive methods to determine the optimal route:

```bash
# Query the public profile of another user
docker compose run --rm satspath-cli dns resolve bob@satspath.local

# Generate a payment "Quote" for 50,000 sats (SatsPath selects the optimal rail)
docker compose run --rm satspath-cli quote bob@satspath.local 50000

# Generate a Quote for larger amounts (evaluates Lightning vs On-chain)
docker compose run --rm satspath-cli quote bob@satspath.local 250000
```

---

## 4. Payment Execution & Swaps

The `pay` command renders payment instructions. When passing experimental flags, you can simulate execution through `LightningExecutor` or orchestrate Submarine Swaps:

```bash
# Display payment instruction and QR payload for a recipient (does not move funds)
docker compose run --rm satspath-cli pay bob@satspath.local 1000

# Simulate experimental payment/swap execution on testnet
docker compose run --rm satspath-cli pay bob@satspath.local 100000 --testnet --experimental-swaps
```

---

## 5. Invite and Claim Flow

When paying a user who does **not** have a registered profile, SatsPath automatically generates an invite link:

```bash
# 1. Attempt payment to an unregistered user (generates an invite)
docker compose run --rm satspath-cli pay new_user@satspath.local 50000

# The above command returns a claim link (e.g. https://satspath.local/claim?alias_hash=...)
# 2. The recipient claims their profile using the link
docker compose run --rm satspath-cli claim "https://satspath.local/claim?alias_hash=abc123def456&amount=50000"
```

---

## 6. Security Maintenance (Key Rotation)

If an identity key is compromised or rotated per policy, SatsPath performs cryptographic rotation with `KeyRotation` proofs:

```bash
# 1. Rotate identity keys (generates new key and attaches rotation proof)
docker compose run --rm satspath-cli wallet rotate

# 2. Inspect profile status
# You should see a notification that the profile has been recently rotated
docker compose run --rm satspath-cli wallet show
```

---

## 7. ARK Bridge (Optional)

To use the TypeScript Ark bridge for advanced client validation, launch the `bridge` profile:

```bash
# Start the ark-bridge container
docker compose --profile bridge up -d ark-bridge

# Stop all services when finished
docker compose --profile bridge down
```
