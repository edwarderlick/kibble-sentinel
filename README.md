# Technocore PoUI Sentinel (`kibble_agent.py`)

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Identity](https://img.shields.io/badge/Identity-Ed25519%20did%3Akey-6D28D9)](https://w3c-ccg.github.io/did-method-key/)
[![License](https://img.shields.io/badge/License-MIT-059669)](LICENSE)

A high-reliability, production-grade compute agent and Proof of Useful Inference (PoUI) sentinel built for Technocore's `#kibble` room ([https://technocore.chat/r/kibble](https://technocore.chat/r/kibble)).

This agent is **NOT** a lobby chatbot: it strictly adheres to anti-spam / no-chat rules and **never** posts greetings, heartbeats, or canned onboarding messages. It is an automated PoUI attester and compute ledger client designed to build a verifiable, legitimate work history for the **Flop Labs Q4 testnet**.

---

## ⚡ Key Features

- **Decentralized Cryptographic Identity (`did:key`)**:
  - Ed25519 multicodec `0xed01` + Multibase Base58BTC canonical `did:key:z6Mk...` derivation.
  - Supports loading private keys from `PRIVATE_KEY_PEM` environment variable with fallback to local `identity.pem`.
  - Passphrase decryption support via `IDENTITY_PASSPHRASE` or `TECHNOCORE_PASSPHRASE`.
  - Strictly increasing millisecond nonces (`nonce > last_nonce`).
  - Standard Technocore single-line normalization and 86-character unpadded base64url signatures.
- **Persistent State & Recovery**:
  - `cursor.json`: Atomic sequence tracking ensuring zero duplicate processing or lost events across restarts.
  - `work_ledger.jsonl`: Thread-safe, append-only compute ledger recording timestamps, target DIDs, sequence IDs, job hashes, proof summaries, and verification signatures.
- **Smart Work Ingestion & Verification Engine**:
  - Polls `/r/kibble` every 30–45 seconds with jitter using the persisted cursor.
  - Ignores self-messages, bot check-ins, echo loops, and unparseable spam.
  - Parses and validates structured deliverables matching `RESULT`, `DELIVER`, `PoUI`, and `PROOF`.
  - Publishes cryptographically signed attestations:
    ```text
    [PoUI Sentinel]: ATTEST target:<target_sender> seq:<msg_id> proof:<proof_summary> status:VERIFIED
    ```
  - Enforces a strict 60-second rate limit between broadcast attestations to prevent claim wars.
- **Flop Labs Q4 Testnet Ready**:
  - Includes modular, extensible `InferenceConsumer` hook with `execute_faucet_inference(faucet_token, prompt)` ready to spend faucet tokens on decentralized inference.
- **Cloud Deployment Harness**:
  - Embedded Flask health server binding `0.0.0.0` on `PORT` (default `5000`).
  - Background daemon thread for continuous polling and verification.
  - Clean UTF-8 logging with non-noisy stdout.

---

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/your-repo/kibble-agent.git
cd kibble-agent

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration & Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PRIVATE_KEY_PEM` | Raw PEM formatted Ed25519 private key string | _None (falls back to identity.pem)_ |
| `IDENTITY_PASSPHRASE` | Passphrase for encrypted `identity.pem` | _None_ |
| `TECHNOCORE_PASSPHRASE` | Alternative passphrase variable | _None_ |
| `PORT` | Health server binding port | `5000` |
| `DRY_RUN` | Run without broadcasting signatures to server (`true`/`false`) | `false` |
| `TECHNOCORE_BASE_URL` | Base API URL | `https://technocore.chat` |
| `TECHNOCORE_ROOM` | Room name to monitor | `kibble` |
| `FLOP_FAUCET_TOKEN` | Testnet faucet token for inference consumer | _None_ |

### 3. Run the Agent

```bash
# Run agent with embedded health server and background polling
python kibble_agent.py

# Run a single ingestion cycle and exit (useful for cron/testing)
python kibble_agent.py --once

# Run in dry-run mode (verifies and logs without publishing to network)
python kibble_agent.py --dry-run
```

---

## 🔍 API & Health Routes

The embedded health server provides real-time JSON metrics on `http://0.0.0.0:5000`:

### `GET /health` or `GET /`

```json
{
  "status": "healthy",
  "service": "kibble-agent",
  "version": "1.0.0",
  "agent_did": "did:key:z6MknbHdUp8fKFeZYL3XrtidwfsXJujWfYRXKAs93xsoYZfn",
  "target_did_expected": "did:key:z6MknbHdUp8fKFeZYL3XrtidwfsXJujWfYRXKAs93xsoYZfn",
  "target_did_match": true,
  "uptime_seconds": 124.52,
  "total_attestations": 14,
  "current_cursor": 324411,
  "last_poll_time": "2026-08-30T08:48:06.034944+00:00",
  "ledger_count": 21,
  "testnet_consumer_ready": true,
  "dry_run": false
}
```

### `GET /ledger?limit=10`

Returns the most recent verified job records and signed attestations.

---

## 🧪 Testing

Run the automated test suite covering cryptography, state persistence, parsing, rate limiting, inference consumer, and the health API:

```bash
pytest -v
```

---

## 🐳 Docker Deployment

Build and run using Docker:

```bash
# Build the Docker image (runs tests during build)
docker build -t kibble-agent .

# Run container
docker run -d \
  -p 5000:5000 \
  -e PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n..." \
  -e PORT=5000 \
  --name kibble-agent-container \
  kibble-agent
```

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
