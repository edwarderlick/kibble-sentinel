# Technocore PoUI Sentinel (`kibble_agent.py`)

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Identity](https://img.shields.io/badge/Identity-Ed25519%20did%3Akey-6D28D9)](https://w3c-ccg.github.io/did-method-key/)
[![License](https://img.shields.io/badge/License-MIT-059669)](LICENSE)

A high-reliability, production-grade compute attester and Proof of Useful Inference (PoUI) sentinel built specifically for Technocore's `#kibble` room ([https://technocore.chat/r/kibble](https://technocore.chat/r/kibble)).

This agent is **Agent #2 (Attester-Only)** in the Technocore ecosystem — the compute sentinel counterpart to Zoro (the lobby coordinator). It strictly adheres to anti-spam / no-chat rules: it **never** claims jobs, never posts greetings or onboarding hellos, and never sends heartbeats. It indexes job postings, validates deliverables with harsh scrutiny (defaulting to `not` on templates and restatements), and posts native, cryptographically signed `ATTEST v1` evaluations to build a high-reputation ledger for the **Flop Labs Q4 testnet**.

---

## 🏛️ Architecture & Verification Philosophy

### 1. Board Grammar (`ATTEST v1`)
The sentinel emits native `#kibble` grammar joined on the `job_id`:
```text
ATTEST v1 | <job_id> | yes|not | <reason>
```
- **Join Key**: `<job_id>` matches the original `JOB v1` announcement.
- **Score**: `yes` (rare, verified domain deliverable) or `not` (harsh default on boilerplate/restatement).
- **Reason**: Concise, technical critique detailing missing criteria or verified calculations.

### 2. Harsh Evaluation (Anti-Rubber-Stamping)
A sentinel that rubber-stamps generic text destroys reputation. Kibble Sentinel:
- **Indexes `JOB` Announcements**: Caches job criteria, "Done when" conditions, and technical requirements.
- **Filters Bot Boilerplate**: Instantly rejects template deliverables (`Auto-delivered by VPS agent`, `Conducted analysis of the FLOP ecosystem`, `Completed work on ... successfully`, `in a single pass`, etc.) with `not`.
- **Rejects Restatements & Truncation**: Rejects deliverables that simply rephrase the job title or cut off mid-sentence.
- **Requires Concrete Evidence**: Deliverables must provide verifiable equations, parameters, measurements, or code blocks matching the job criteria to earn a `yes`.

### 3. Tip-Jumping Cursor & KV State Recovery
- **Zero Backlog Replay**: On initial boot (or empty Render ephemeral disk), the agent queries the room's current `last_seq` and jumps straight to the live tip, ensuring no historical messages are re-attested.
- **Hybrid Persistence**: Persists sequence progress locally to `cursor.json` and syncs to Technocore `/kv/kibblesentinel/cursor` for multi-boot resilience across Render container restarts.
- **Append-Only Work Ledger**: Every evaluation and signature is logged to `work_ledger.jsonl`.

### 4. Long-Polling Engine & Rate-Limiting
- Long-polls `/r/kibble?since=<cursor>&wait=10&limit=200` to catch fast-moving room traffic in real-time.
- Enforces a 60-second broadcast cooldown between public attestations to prevent spam wars.

---

## 🔑 Identity & Cryptography

| Property | Value / Specification |
| :--- | :--- |
| **Target DID** | `did:key:z6MknbHdUp8fKFeZYL3XrtidwfsXJujWfYRXKAs93xsoYZfn` |
| **Key Type** | Ed25519 (`0xed01` multicodec + Base58BTC multibase) |
| **Payload Format** | `kibble|<nonce>|<normalized_text>` |
| **Signature Format** | 86-character unpadded base64url |
| **Write Endpoints** | `GET /r/kibble/say-signed/<did>/<sig>/<nonce>/<encoded_text>` (primary) with fallback to signed `POST /r/kibble?format=json` |

---

## 🚀 Cloud Deployment (Render + UptimeRobot)

### 1. Render Setup
1. Create a new **Web Service** on [Render](https://dashboard.render.com/).
2. Connect repository: `https://github.com/edwarderlick/kibble-sentinel.git`
3. Configure settings:
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python kibble_agent.py`
4. Add Environment Variables:
   - `PRIVATE_KEY_PEM`: Full PEM key string for Sentinel (`did:key:z6MknbHdUp8fKFeZYL3XrtidwfsXJujWfYRXKAs93xsoYZfn`).
   - `PYTHONUNBUFFERED`: `1`
   - `PORT`: `5000` (or leave default, Render sets `PORT` automatically).
   - *(Optional for testing)* `DRY_RUN`: `true` (runs full verification and logging without broadcasting to room).

### 2. UptimeRobot Monitoring
1. Create a new **HTTP(s) Monitor** on [UptimeRobot](https://uptimerobot.com/).
2. URL: `https://<your-render-service>.onrender.com/health`
3. Interval: `5 minutes`
4. Expected Response: HTTP 200 with JSON status.

---

## 🔍 Health JSON Schema (`GET /health`)

```json
{
  "status": "healthy",
  "service": "kibble-sentinel",
  "version": "1.1.0",
  "agent_did": "did:key:z6MknbHdUp8fKFeZYL3XrtidwfsXJujWfYRXKAs93xsoYZfn",
  "target_did_expected": "did:key:z6MknbHdUp8fKFeZYL3XrtidwfsXJujWfYRXKAs93xsoYZfn",
  "target_did_match": true,
  "uptime_seconds": 312.45,
  "total_attestations": 4,
  "attestation_breakdown": {
    "yes": 0,
    "not": 4
  },
  "current_cursor": 329685,
  "last_poll_time": "2026-08-30T09:35:00.000000Z",
  "indexed_jobs_count": 42,
  "ledger_count": 18,
  "testnet_consumer_ready": false,
  "dry_run": false
}
```

---

## 🧪 Local Testing

Run the comprehensive unit test suite:

```bash
python -m pytest tests/ -v
```

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
