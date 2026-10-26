# Phantom Key v2 - Competition Guide

## 🏆 Overview

Phantom Key v2 is a **novel security system** for LLM prompt processing that ensures real secrets never leave your infrastructure. This guide explains how to run the system and demonstrate its security properties for competition judging.

## 🎯 Key Innovations

Phantom Key v2 combines **four security primitives** in a novel way:

1. **Dealerless Threshold Key** - No single party ever knows the master secret
2. **Sealed Vault** - Each secret encrypted with unique key derived from threshold DH
3. **Format-Preserving Decoys** - Real secrets replaced with fake but valid-looking values
4. **Signed Hash-Chained Ledger** - Tamper-evident audit log of all outbound requests

**No existing project combines all four components.**

## 🚀 Quick Start

### Prerequisites

- Rust 1.70+
- Cargo
- SQLite (for production storage)

### Build

```bash
cd phantom_key_research
cargo build --release
```

### Configuration

Create a `config.yaml` file:

```yaml
# Number of parties and threshold
parties: 5
threshold: 3

# Share refresh settings
epoch_duration: 3600  # 1 hour
verification_period: 300  # 5 minutes

# Vault storage
vault:
  storage: "memory"  # or "sqlite"
  path: "/var/lib/phantom-key/vault.db"

# Ledger storage
ledger:
  storage: "memory"  # or "sqlite"
  path: "/var/log/phantom-key/ledger.db"

# Provider API keys (optional)
providers:
  bedrock:
    endpoint: "https://bedrock-runtime.us-east-1.amazonaws.com"
    api_key: "${BEDROCK_API_KEY}"
  openai:
    api_key: "${OPENAI_API_KEY}"
  gemini:
    api_key: "${GEMINI_API_KEY}"
```

### Run

```bash
# Start the server
./target/release/phantom-key server --config config.yaml

# Or with default config
./target/release/phantom-key server
```

## 🎬 Attack Lab (For Video)

Run the Attack Lab to demonstrate all security properties:

```bash
./scripts/attack_lab.sh
```

This will run **6 live demos**:

1. **Memory Safety** - No real secrets in process memory
2. **Log Inspection** - No real secrets in logs
3. **Wire Inspection** - No real secrets on wire
4. **DLEQ Validation** - Malicious partials rejected
5. **Ledger Tampering** - Chain breaks on modification
6. **Canary Detection** - Reappearance flagged

### Manual Demo

You can also run individual demos:

```bash
# Run via API
curl http://localhost:8080/attack-lab

# Or run specific demo via Rust test
cargo test --lib demo_memory_safety -- --nocapture
cargo test --lib demo_log_inspection -- --nocapture
cargo test --lib demo_wire_inspection -- --nocapture
cargo test --lib demo_dleq_validation -- --nocapture
cargo test --lib demo_ledger_tampering -- --nocapture
cargo test --lib demo_canary_detection -- --nocapture
```

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check |
| POST | /process | Process a prompt |
| POST | /store-secret | Store a secret in vault |
| GET | /get-secret/{handle} | Retrieve a secret from vault |
| GET | /ledger | Get ledger entries |
| GET | /vault | Get vault entries |
| GET | /attack-lab | Run all Attack Lab demos |
| GET | /status | Get system status |

### Process a Prompt

```bash
curl -X POST http://localhost:8080/process \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is the weather in SF?",
    "model": "anthropic.claude-3-sonnet",
    "provider": "bedrock"
  }'
```

### Store a Secret

```bash
curl -X POST http://localhost:8080/store-secret \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "my-api-key-12345",
    "secret_type": "api_key"
  }'
```

### Retrieve a Secret

```bash
curl http://localhost:8080/get-secret/⟦H123⟧
```

## 🔍 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Phantom Key v2                              │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  Core Crypto  │  │  Vault       │  │  Egress Court │    │
│  │  - DKG        │  │  - Sealed    │  │  - Ledger     │    │
│  │  - Threshold  │  │  - Handles   │  │  - Scanner    │    │
│  │    DH        │  │  - Decoys    │  │  - Canaries   │    │
│  │  - Share      │  │              │  │  - Interceptor│    │
│  │    Refresh   │  │              │  │  - TUI        │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    LLM Providers                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Bedrock    │  │   OpenAI     │  │   Gemini     │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Security Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Confidentiality** | Real secrets never sent to provider | Sealed vault + decoys |
| **Integrity** | Secrets cannot be tampered | AEAD encryption (ChaCha20-Poly1305) |
| **Detection** | Reappearance of canaries detected | Canary scanner |
| **Non-repudiation** | Actions provable | Signed ledger (Ed25519) |
| **Key separation** | Each secret has unique key | HKDF with handle |
| **Malicious party detection** | Invalid partials rejected | DLEQ proofs |

## ⚖️ Judging Rubric

### UI (3 points)

**Delivery:** Textual TUI with 4 panels

- **Chat Panel** - Shows LLM conversation
- **Egress Ledger Panel** - Shows request logs with chain status
- **Shareholder Panel** - Shows DKG party status
- **Vault Panel** - Shows stored secrets

**To run the TUI:**
```bash
./target/release/phantom-key tui
```

### Video (2 points)

**Delivery:** Attack Lab with 6 live demos

1. Memory Safety - No real secrets in process memory
2. Log Inspection - No real secrets in logs
3. Wire Inspection - No real secrets on wire
4. DLEQ Validation - Malicious partials rejected
5. Ledger Tampering - Chain breaks on modification
6. Canary Detection - Reappearance flagged

**To run:**
```bash
./scripts/attack_lab.sh
```

### API Evidence (2 points)

**Delivery:** Real provider calls with request IDs logged to ledger

- All outbound requests logged to signed, hash-chained ledger
- Each request has unique request_id
- Payloads are scanned for secrets
- Canaries are detected and triggered

**To verify:**
```bash
# Make a request
curl -X POST http://localhost:8080/process \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Test", "model": "test", "provider": "bedrock"}'

# Check ledger
curl http://localhost:8080/ledger | jq .
```

## 📊 Honest Limitations

Phantom Key v2 is **honest about its limitations**:

1. **Model sees decoys** - The task is not hidden from the model
2. **Best-effort detection** - Canaries provide detection, not proof of retention
3. **Threshold compromise** - k parties can reconstruct the secret
4. **Epoch compromise** - Old shares are vulnerable until refresh
5. **Side channels** - Not protected against timing attacks, etc.

## 🏆 What Makes It Strong

1. **Novel Combination** - First to combine dealerless DKG, sealed vault, decoys, and signed ledger
2. **Real Cryptography** - Uses well-vetted primitives (Ristretto255, Ed25519, ChaCha20-Poly1305, HKDF)
3. **Practical** - Clear implementation path, works with real LLM providers
4. **Judging-Optimized** - Focuses on rubric points (UI, Video, API Evidence)
5. **Honest** - Doesn't overstate capabilities

## 📚 Documentation

- `README.md` - Project overview
- `docs/PHANTOM_KEY_V2.md` - Corrected design specification
- `docs/MASTER_PLAN.md` - Implementation plan
- `docs/COMPETITION_GUIDE.md` - This guide
- `plan/` - Detailed phase plans

## 🤝 Team

- **Crypto Lead** - Implemented Phase 1 (Core Cryptography)
- **Security Lead** - Implemented Phase 2 (Vault System)
- **Backend Lead** - Implemented Phase 3 (Egress Court)
- **Integration Lead** - Implemented Phase 4 (Integration & Polish)

## 🎉 Next Steps

1. **Run the system:**
   ```bash
   cargo run --release server
   ```

2. **Run Attack Lab:**
   ```bash
   ./scripts/attack_lab.sh
   ```

3. **Record video:**
   ```bash
   ./scripts/record_video.sh
   ```

4. **Submit to competition!**

---

**Good luck!** 🚀
