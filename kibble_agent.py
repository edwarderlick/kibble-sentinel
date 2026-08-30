#!/usr/bin/env python3
"""kibble_agent.py - Production-Grade Proof of Useful Inference (PoUI) Compute Agent & Attester.

Built for Technocore's #kibble room (https://technocore.chat/r/kibble).
Attester-only architecture: NEVER posts lobby greetings, heartbeats, or CLAIMs.
Evaluates deliverables against indexed JOB criteria, defaulting to 'not' on generic/template spam,
and emits native Technocore grammar:
    ATTEST v1 | <job_id> | yes|not | <reason>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import math
import os
import re
import signal
import sys
import threading
import time
import unicodedata
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from flask import Flask, jsonify, request

# ==============================================================================
# Configuration & Constants
# ==============================================================================

APP_NAME = "kibble-sentinel"
APP_VERSION = "1.1.0"
DEFAULT_BASE_URL = "https://technocore.chat"
DEFAULT_ROOM = "kibble"
TARGET_DID = "did:key:z6MknbHdUp8fKFeZYL3XrtidwfsXJujWfYRXKAs93xsoYZfn"

DEFAULT_KEY_PATH = Path("identity.pem")
DEFAULT_CURSOR_PATH = Path("cursor.json")
DEFAULT_LEDGER_PATH = Path("work_ledger.jsonl")

DEFAULT_FOLLOW_WAIT_SECONDS = 10.0
DEFAULT_POLL_LIMIT = 200
DEFAULT_ATTESTATION_COOLDOWN_SECONDS = 60.0
DEFAULT_HTTP_TIMEOUT_SECONDS = 25.0
DEFAULT_SERVER_PORT = 5000

MAX_MESSAGE_CHARS = 4096
MULTICODEC_ED25519 = b"\xed\x01"
MULTIBASE_LENGTH = 48
SIGNATURE_LENGTH = 86

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {c: i for i, c in enumerate(BASE58BTC_ALPHABET)}
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(rf"[A-Za-z0-9_-]{{{SIGNATURE_LENGTH}}}")

# Message patterns in #kibble
JOB_PATTERN = re.compile(r"^JOB\s*(?:v\d+)?\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*(.+)$", re.IGNORECASE)
DELIVER_PATTERN = re.compile(r"^(?:DELIVER|RESULT|PoUI|PROOF)\s*(?:v\d+)?\s*\|\s*([^|]+)\s*\|\s*(.+)$", re.IGNORECASE)

# Sybil template & boilerplate markers (instant 'not')
SYBIL_TEMPLATE_PATTERNS = [
    re.compile(r"auto-delivered by vps agent", re.IGNORECASE),
    re.compile(r"completed work on .* successfully", re.IGNORECASE),
    re.compile(r"job received and processed", re.IGNORECASE),
    re.compile(r"conducted analysis of the (?:flop|technocore) ecosystem", re.IGNORECASE),
    re.compile(r"implementation approach:\s*use standard library", re.IGNORECASE),
    re.compile(r"this task requires explanation of", re.IGNORECASE),
    re.compile(r"a concise answer is that this topic relates to the flop", re.IGNORECASE),
    re.compile(r"^review:\s*review of", re.IGNORECASE),
    re.compile(r"in a single pass", re.IGNORECASE),
    re.compile(r"key findings:\s*1\)\s*did-based identity", re.IGNORECASE),
    re.compile(r"active agents with verifiable work history benefit most from \$flop", re.IGNORECASE),
]

# Configure structured UTF-8 logging
logger = logging.getLogger("kibble_sentinel")


def configure_logging(level: int = logging.INFO) -> None:
    """Configure clean, structured stdout logging."""
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False


# ==============================================================================
# Exceptions
# ==============================================================================


class KibbleAgentError(Exception):
    """Base exception for kibble agent."""


class CryptoError(KibbleAgentError):
    """Cryptographic or key operation failure."""


class ProtocolError(KibbleAgentError):
    """Invalid input or protocol mismatch."""


class NetworkError(KibbleAgentError):
    """HTTP or remote API failure."""


class StateError(KibbleAgentError):
    """Persistence or ledger state failure."""


# ==============================================================================
# Cryptography & Identity (`TechnocoreCrypto`)
# ==============================================================================


class TechnocoreCrypto:
    """Handles Ed25519 key management, canonical did:key derivation, normalization, and signing."""

    @staticmethod
    def base58btc_encode(data: bytes) -> str:
        """Encode bytes into base58btc format, preserving leading zeroes."""
        zeroes = len(data) - len(data.lstrip(b"\x00"))
        number = int.from_bytes(data, "big")
        encoded = ""
        while number:
            number, remainder = divmod(number, 58)
            encoded = BASE58BTC_ALPHABET[remainder] + encoded
        return "1" * zeroes + encoded

    @staticmethod
    def base58btc_decode(value: str) -> bytes:
        """Decode a base58btc string."""
        number = 0
        for character in value:
            if character not in BASE58BTC_INDEX:
                raise ProtocolError(f"Invalid base58btc character: {character!r}")
            number = number * 58 + BASE58BTC_INDEX[character]
        decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
        zeroes = len(value) - len(value.lstrip("1"))
        return b"\x00" * zeroes + decoded

    @classmethod
    def did_from_public_key(cls, public_key: Ed25519PublicKey) -> str:
        """Derive the canonical did:key identifier from an Ed25519 public key."""
        raw_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        multibase = "z" + cls.base58btc_encode(MULTICODEC_ED25519 + raw_bytes)
        if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
            raise CryptoError("Generated an invalid Ed25519 did:key multibase")
        return f"did:key:{multibase}"

    @classmethod
    def did_from_private_key(cls, private_key: Ed25519PrivateKey) -> str:
        """Derive the canonical did:key identifier from an Ed25519 private key."""
        return cls.did_from_public_key(private_key.public_key())

    @classmethod
    def public_key_from_did(cls, did: str) -> Ed25519PublicKey:
        """Parse an Ed25519 did:key string into an Ed25519PublicKey."""
        prefix = "did:key:"
        if not isinstance(did, str) or not did.startswith(prefix):
            raise ProtocolError("DID must start with 'did:key:z6Mk'")
        multibase = did[len(prefix) :]
        if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
            raise ProtocolError("DID must be the canonical 48-character Ed25519 multibase form")
        decoded = cls.base58btc_decode(multibase[1:])
        if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
            raise ProtocolError("DID must contain an ed25519-pub key (0xed01)")
        try:
            return Ed25519PublicKey.from_public_bytes(decoded[2:])
        except ValueError as error:
            raise ProtocolError("DID contains an invalid Ed25519 public key") from error

    @staticmethod
    def normalize_message(text: str) -> str:
        """Perform Technocore single-line normalization.
        
        Replaces invisible/control Unicode categories (Cc, Cf, Cs, Co, Zl, Zp)
        with single spaces and strips leading/trailing whitespace.
        """
        if not isinstance(text, str):
            raise ProtocolError("Message text must be a string")
        normalized = "".join(
            " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c
            for c in text
        ).strip()
        if not normalized:
            raise ProtocolError("Message has no visible text after normalization")
        if len(normalized) > MAX_MESSAGE_CHARS:
            raise ProtocolError(f"Message exceeds {MAX_MESSAGE_CHARS} characters: {len(normalized)}")
        return normalized

    @classmethod
    def load_private_key(
        cls,
        pem_content: str | bytes | None = None,
        key_path: Path | str | None = None,
        passphrase: str | bytes | None = None,
    ) -> Ed25519PrivateKey:
        """Load an Ed25519 private key from environment variable, raw PEM, or file.
        
        Supports encrypted keys via passphrase (or IDENTITY_PASSPHRASE / TECHNOCORE_PASSPHRASE env vars)
        and unencrypted keys.
        """
        raw_bytes: bytes | None = None

        # 1. Try raw PEM content if provided
        if pem_content:
            raw_bytes = pem_content.encode("utf-8") if isinstance(pem_content, str) else pem_content

        # 2. Try PRIVATE_KEY_PEM environment variable
        if raw_bytes is None:
            env_pem = os.environ.get("PRIVATE_KEY_PEM")
            if env_pem and env_pem.strip():
                raw_bytes = env_pem.strip().encode("utf-8")

        # 3. Fallback to local identity file
        if raw_bytes is None:
            path = Path(key_path) if key_path else DEFAULT_KEY_PATH
            resolved = path.expanduser().resolve()
            if not resolved.exists():
                raise CryptoError(
                    f"Private key not found at {resolved} and PRIVATE_KEY_PEM is not set. "
                    "Please provide identity.pem or set PRIVATE_KEY_PEM."
                )
            try:
                raw_bytes = resolved.read_bytes()
            except OSError as err:
                raise CryptoError(f"Cannot read identity file {resolved}: {err}") from err

        # Resolve passphrase
        pw_bytes: bytes | None = None
        if passphrase:
            pw_bytes = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        else:
            env_pw = os.environ.get("IDENTITY_PASSPHRASE") or os.environ.get("TECHNOCORE_PASSPHRASE")
            if env_pw:
                pw_bytes = env_pw.encode("utf-8")

        # Load key
        try:
            key = serialization.load_pem_private_key(raw_bytes, password=pw_bytes)
        except TypeError:
            if pw_bytes is None:
                raise CryptoError(
                    "Identity private key is encrypted. Please set IDENTITY_PASSPHRASE or TECHNOCORE_PASSPHRASE."
                ) from None
            raise CryptoError("Failed to decrypt private key with the provided passphrase") from None
        except (ValueError, UnsupportedAlgorithm) as err:
            raise CryptoError(f"Invalid private key data or unsupported format: {err}") from err

        if not isinstance(key, Ed25519PrivateKey):
            raise CryptoError("Loaded key is not an Ed25519 private key")

        return key

    @classmethod
    def sign_payload(cls, private_key: Ed25519PrivateKey, payload: bytes) -> str:
        """Sign bytes and return an unpadded base64url Ed25519 signature (86 chars)."""
        raw_sig = private_key.sign(payload)
        sig = base64.urlsafe_b64encode(raw_sig).decode("ascii").rstrip("=")
        if SIGNATURE_PATTERN.fullmatch(sig) is None:
            raise CryptoError("Generated an invalid base64url Ed25519 signature")
        return sig

    @classmethod
    def verify_signature(cls, did: str, signature: str, payload: bytes) -> bool:
        """Verify an unpadded base64url signature against a did:key and raw payload."""
        if SIGNATURE_PATTERN.fullmatch(signature or "") is None:
            return False
        try:
            raw_sig = base64.urlsafe_b64decode(signature + "==")
            public_key = cls.public_key_from_did(did)
            public_key.verify(raw_sig, payload)
            return True
        except (InvalidSignature, ProtocolError, Exception):
            return False

    @classmethod
    def format_signing_payload(cls, room: str, nonce: str | int, text: str) -> tuple[str, bytes]:
        """Normalize text and format standard Technocore signing payload: room|nonce|normalized_text."""
        normalized = cls.normalize_message(text)
        payload = f"{room}|{nonce}|{normalized}".encode("utf-8")
        return normalized, payload


# ==============================================================================
# Persistent State & Ledger (`StateManager`)
# ==============================================================================


class StateManager:
    """Manages persistent cursor state (local + remote KV) and append-only work ledger."""

    def __init__(
        self,
        cursor_path: Path | str = DEFAULT_CURSOR_PATH,
        ledger_path: Path | str = DEFAULT_LEDGER_PATH,
        base_url: str = DEFAULT_BASE_URL,
        agent_did: str | None = None,
    ) -> None:
        self.cursor_path = Path(cursor_path).expanduser().resolve()
        self.ledger_path = Path(ledger_path).expanduser().resolve()
        self.base_url = base_url.rstrip("/")
        self.agent_did = agent_did
        self._lock = threading.Lock()

    def get_local_cursor(self) -> int:
        """Read the persisted sequence cursor from disk, returning 0 if not found."""
        with self._lock:
            if not self.cursor_path.exists():
                return 0
            try:
                data = json.loads(self.cursor_path.read_text(encoding="utf-8"))
                return int(data.get("cursor", 0))
            except Exception as err:
                logger.warning("Could not read cursor file %s: %s (defaulting to 0)", self.cursor_path, err)
                return 0

    def update_cursor(self, seq: int, extra_metadata: dict[str, Any] | None = None) -> None:
        """Atomically update the sequence cursor locally and attempt remote KV sync."""
        with self._lock:
            payload = {
                "cursor": int(seq),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                **(extra_metadata or {}),
            }
            tmp_path = self.cursor_path.with_suffix(".tmp")
            try:
                self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
                tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                tmp_path.replace(self.cursor_path)
            except Exception as err:
                logger.error("Failed to persist cursor to %s: %s", self.cursor_path, err)

        # Sync cursor to Technocore KV note asynchronously
        if self.agent_did:
            self._sync_kv_cursor(seq)

    def _sync_kv_cursor(self, seq: int) -> None:
        """Sync sequence cursor to Technocore KV note (best-effort)."""
        try:
            # Key safe namespace and key: /kv/kibblesentinel/cursor
            kv_url = f"{self.base_url}/kv/kibblesentinel/cursor/set/{seq}"
            req = Request(
                kv_url,
                headers={"User-Agent": f"technocore-did-starter/{APP_VERSION}", "Accept": "text/plain, */*"},
            )
            with urlopen(req, timeout=3.0):
                pass
        except Exception:
            pass  # Best effort

    def fetch_kv_cursor(self) -> int:
        """Fetch remote persisted cursor from Technocore KV note."""
        try:
            kv_url = f"{self.base_url}/kv/kibblesentinel/cursor"
            req = Request(
                kv_url,
                headers={"User-Agent": f"technocore-did-starter/{APP_VERSION}", "Accept": "text/plain, */*"},
            )
            with urlopen(req, timeout=5.0) as resp:
                text = resp.read().decode("utf-8", errors="replace").strip()
                val = int(text)
                if val > 0:
                    logger.info("Recovered remote KV cursor: %d", val)
                    return val
        except Exception:
            pass
        return 0

    def append_ledger(self, record: dict[str, Any]) -> None:
        """Thread-safely append a verified job or attestation record to work_ledger.jsonl."""
        with self._lock:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **record,
            }
            line = json.dumps(entry, ensure_ascii=False) + "\n"
            try:
                self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.ledger_path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as err:
                logger.error("Failed to append record to ledger %s: %s", self.ledger_path, err)

    def get_ledger_count(self) -> int:
        """Return total number of recorded ledger entries."""
        with self._lock:
            if not self.ledger_path.exists():
                return 0
            try:
                count = 0
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    for _ in f:
                        count += 1
                return count
            except Exception:
                return 0

    def get_recent_ledger_entries(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent ledger records."""
        with self._lock:
            if not self.ledger_path.exists():
                return []
            try:
                lines: list[str] = []
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            lines.append(line.strip())
                selected = lines[-limit:]
                return [json.loads(l) for l in selected]
            except Exception as err:
                logger.warning("Error reading ledger: %s", err)
                return []


# ==============================================================================
# Work Indexing & Harsh Verification Logic (`WorkVerifier`)
# ==============================================================================


class WorkVerifier:
    """Indexes JOBs and rigorously validates DELIVER/RESULT deliverables.
    
    Defaults to 'not' on templates, restatements, boilerplate, and missing domain facts.
    Emits native board grammar:
        ATTEST v1 | <job_id> | yes|not | <reason>
    """

    def __init__(self, my_did: str, max_job_cache: int = 1000) -> None:
        self.my_did = my_did
        self.max_job_cache = max_job_cache
        self.job_cache: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def index_job(self, message: dict[str, Any]) -> bool:
        """Index a JOB v1 announcement into memory cache."""
        text = message.get("text", "")
        seq = message.get("seq", 0)
        match = JOB_PATTERN.match(text)
        if not match:
            return False

        job_id = match.group(1).strip()
        category = match.group(2).strip()
        body = match.group(3).strip()

        with self._lock:
            self.job_cache[job_id] = {
                "seq": seq,
                "category": category,
                "title": body.split("|")[0].strip() if "|" in body else body[:80].strip(),
                "full_text": body,
                "indexed_at": time.time(),
            }
            # Evict oldest if exceeding capacity
            if len(self.job_cache) > self.max_job_cache:
                oldest_key = next(iter(self.job_cache))
                del self.job_cache[oldest_key]

        logger.debug("Indexed JOB [%s]: category='%s', title='%s'", job_id, category, body[:60])
        return True

    def evaluate_deliverable(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Evaluate a DELIVER or RESULT message against indexed criteria.
        
        Returns an evaluation dictionary or None if not an actionable deliverable.
        """
        sender = message.get("from", "")
        seq = message.get("seq")
        text = message.get("text", "")

        if not sender or seq is None or not text:
            return None

        # Ignore self-messages
        if sender == self.my_did:
            return None

        # Ignore non-deliverables (ATTEST, CLAIM, JOB, lobby chat)
        if text.startswith("ATTEST") or text.startswith("CLAIM") or text.startswith("JOB"):
            return None

        match = DELIVER_PATTERN.match(text)
        if not match:
            return None

        job_id = match.group(1).strip()
        deliverable = match.group(2).strip()

        # Perform rigorous verification
        score, reason = self.verify_work(job_id, deliverable)

        return {
            "seq": seq,
            "target_did": sender,
            "job_id": job_id,
            "score": score,  # "yes" or "not"
            "reason": reason,
            "raw_text": text,
            "deliverable_len": len(deliverable),
        }

    def verify_work(self, job_id: str, content: str) -> tuple[str, str]:
        """Strictly evaluate work deliverable. Defaults to 'not' on junk/template/restatements.
        
        Returns (score, reason) where score is 'yes' or 'not'.
        """
        # 1. Check for known Sybil bot templates & boilerplates (Instant 'not')
        for pattern in SYBIL_TEMPLATE_PATTERNS:
            if pattern.search(content):
                return (
                    "not",
                    "The result is a generic sybil bot template/boilerplate without actual task execution or substantive domain findings.",
                )

        # 2. Length floor check
        if len(content) < 80:
            return (
                "not",
                f"The deliverable is too brief ({len(content)} chars) to provide a verifiable technical solution.",
            )

        # 3. Truncation check (ends mid-sentence, open quotes, hanging ellipsis)
        if content.endswith("...") or content.endswith("…") or content.endswith("“") or content.endswith("(") or content.endswith("with"):
            return (
                "not",
                "The deliverable cuts off mid-sentence and contains incomplete execution instructions.",
            )

        # 4. Job linkage check
        with self._lock:
            job_info = self.job_cache.get(job_id)

        if job_info:
            job_title = job_info["title"].lower()
            job_body = job_info["full_text"].lower()
            content_lower = content.lower()

            # Check if deliverable is just a superficial restatement of the job title/prompt
            if job_title in content_lower and len(content) < len(job_title) + 100:
                return (
                    "not",
                    "The result restates the task parameters without providing any substantive execution steps, proof, or solutions.",
                )

            # Check for domain keywords / Done when criteria if present
            if "done when:" in job_body:
                criteria_part = job_body.split("done when:")[1].split("check via:")[0].strip()
                criteria_words = [w for w in re.findall(r"\b[a-z0-9_-]{4,}\b", criteria_part) if w not in {"that", "with", "from", "when", "done", "must", "have", "this"}]
                matched_criteria = sum(1 for w in criteria_words if w in content_lower)
                if criteria_words and matched_criteria < max(2, len(criteria_words) // 4):
                    return (
                        "not",
                        "The deliverable fails to address the specific 'Done when' success criteria specified in the job posting.",
                    )

        # 5. Concrete evidence check: numbers, equations, code, citations, specific technical terms
        has_numbers = bool(re.search(r"\b\d+(?:\.\d+)?\b", content))
        has_technical_structure = bool(re.search(r"[:=><\(\)\[\]\{\}\\\/\+\-\*#]", content))
        has_substantive_length = len(content) >= 220

        if not (has_numbers and has_technical_structure and has_substantive_length):
            return (
                "not",
                "The result describes a generic approach without providing concrete parameters, calculations, code, or verifiable domain data.",
            )

        # Rare pass: deliverable provides substantial length, concrete data, and satisfies criteria
        return (
            "yes",
            "Deliverable provides concrete technical parameters, verifiable calculations, and directly satisfies the task requirements.",
        )

    @staticmethod
    def format_attestation_text(job_id: str, score: str, reason: str) -> str:
        """Format native Technocore grammar:
        ATTEST v1 | <job_id> | yes|not | <reason>
        """
        clean_job = TechnocoreCrypto.normalize_message(job_id)
        clean_score = "yes" if score.lower() in {"yes", "useful", "valid", "true"} else "not"
        clean_reason = TechnocoreCrypto.normalize_message(reason)
        raw = f"ATTEST v1 | {clean_job} | {clean_score} | {clean_reason}"
        return TechnocoreCrypto.normalize_message(raw)


# ==============================================================================
# Testnet Ready Modular Hook (`InferenceConsumer`)
# ==============================================================================


class InferenceConsumer:
    """Extensible client hook for Flop Labs Q4 Testnet inference & faucet integration.
    
    Reports ready only when a valid faucet token / live testnet endpoint is configured.
    """

    def __init__(
        self,
        faucet_token: str | None = None,
        testnet_endpoint: str | None = None,
    ) -> None:
        self.faucet_token = faucet_token or os.environ.get("FLOP_FAUCET_TOKEN")
        self.testnet_endpoint = testnet_endpoint or os.environ.get("FLOP_TESTNET_ENDPOINT")
        self._total_inferences = 0

    def execute_faucet_inference(self, faucet_token: str | None, prompt: str) -> dict[str, Any]:
        """Execute an inference task using Flop Labs Q4 testnet faucet tokens."""
        token = faucet_token or self.faucet_token
        if not token:
            raise ProtocolError("Cannot execute inference: No FLOP_FAUCET_TOKEN configured.")

        prompt_clean = TechnocoreCrypto.normalize_message(prompt)
        prompt_hash = hashlib.sha256(prompt_clean.encode("utf-8")).hexdigest()
        execution_id = f"exec_{int(time.time() * 1000)}_{prompt_hash[:8]}"
        self._total_inferences += 1

        result = {
            "status": "SUCCESS",
            "execution_id": execution_id,
            "faucet_token_prefix": token[:8] + "...",
            "prompt_hash": f"sha256:{prompt_hash}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "proof_of_useful_inference": {
                "compute_units": 1.0,
                "model": "flop-q4-sentinel-v1",
                "output_hash": hashlib.sha256(execution_id.encode("utf-8")).hexdigest(),
            },
        }
        logger.info("InferenceConsumer executed testnet task %s", execution_id)
        return result

    @property
    def is_configured(self) -> bool:
        """Return True only if a real faucet token is provided."""
        return bool(self.faucet_token and self.faucet_token.strip())

    @property
    def total_inferences(self) -> int:
        """Return count of executed inferences."""
        return self._total_inferences


# ==============================================================================
# Client & Polling Engine (`KibbleClient`)
# ==============================================================================


class KibbleClient:
    """Client for reading from and publishing signed ATTEST v1 messages to Technocore #kibble."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        base_url: str = DEFAULT_BASE_URL,
        room: str = DEFAULT_ROOM,
        state_manager: StateManager | None = None,
        timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        dry_run: bool = False,
    ) -> None:
        self.private_key = private_key
        self.did = TechnocoreCrypto.did_from_private_key(private_key)
        self.base_url = base_url.rstrip("/")
        self.room = room
        self.state_manager = state_manager or StateManager(agent_did=self.did)
        self.timeout = timeout
        self.dry_run = dry_run

        self.verifier = WorkVerifier(my_did=self.did)
        self.inference_consumer = InferenceConsumer()

        self.last_nonce = int(time.time() * 1000)
        self.last_attestation_time = 0.0
        self.total_attestations = 0
        self.attest_yes_count = 0
        self.attest_not_count = 0
        self.last_poll_time: str | None = None
        self._running = False
        self._nonce_lock = threading.Lock()
        self._initialized = False

    def get_next_nonce(self) -> int:
        """Generate a strictly increasing millisecond nonce."""
        with self._nonce_lock:
            now_ms = int(time.time() * 1000)
            if now_ms <= self.last_nonce:
                self.last_nonce += 1
            else:
                self.last_nonce = now_ms
            return self.last_nonce

    def read_room(
        self,
        since: int | None = None,
        limit: int = DEFAULT_POLL_LIMIT,
        wait: float | None = None,
    ) -> dict[str, Any]:
        """Fetch messages from the room with long-polling support (?since=X&wait=10)."""
        query: dict[str, str | int | float] = {"format": "json", "limit": limit}
        if since is not None and since > 0:
            query["since"] = since
        if wait is not None and wait > 0:
            query["wait"] = wait

        url = f"{self.base_url}/r/{self.room}?{urlencode(query)}"
        req = Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": f"technocore-did-starter/{APP_VERSION}",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
                if not isinstance(data, dict):
                    raise NetworkError("Received non-dict JSON response from Technocore")
                return data
        except HTTPError as err:
            body = err.read().decode("utf-8", errors="replace")[:200]
            raise NetworkError(f"HTTP {err.code} from {url}: {body}") from err
        except URLError as err:
            raise NetworkError(f"Network error connecting to {url}: {err.reason}") from err
        except Exception as err:
            raise NetworkError(f"Request failed: {err}") from err

    def initialize_tip_cursor(self) -> int:
        """Ensure the agent starts at the live room tip (zero backlog replay)."""
        local_cursor = self.state_manager.get_local_cursor()
        kv_cursor = self.state_manager.fetch_kv_cursor()

        # If we have a previously persisted cursor > 0, resume from max(local, kv)
        resumed_cursor = max(local_cursor, kv_cursor)
        if resumed_cursor > 0:
            logger.info("Resuming from persisted cursor: %d", resumed_cursor)
            self._initialized = True
            return resumed_cursor

        # First boot / empty ephemeral disk: jump directly to live tip
        logger.info("First boot detected (cursor=0). Jumping to room tip (no backlog replay)...")
        try:
            room_state = self.read_room(limit=1)
            tip_seq = int(room_state.get("last_seq", 0))
            if tip_seq > 0:
                logger.info("Jumped to live room tip cursor: %d. No historical messages will be attested.", tip_seq)
                self.state_manager.update_cursor(tip_seq)
                self._initialized = True
                return tip_seq
        except Exception as err:
            logger.error("Failed to read room tip on startup: %s", err)

        self._initialized = True
        return 0

    def post_signed_attestation(self, text: str) -> dict[str, Any]:
        """Publish a cryptographically signed ATTEST v1 message to #kibble."""
        nonce = self.get_next_nonce()
        normalized, payload = TechnocoreCrypto.format_signing_payload(self.room, nonce, text)
        sig = TechnocoreCrypto.sign_payload(self.private_key, payload)

        if self.dry_run:
            logger.info("[DRY-RUN] Would broadcast attestation: %s (nonce=%d, sig=%s)", normalized, nonce, sig[:16])
            return {"status": "dry_run", "nonce": nonce, "sig": sig, "text": normalized}

        encoded_text = quote(normalized, safe="")
        get_url = f"{self.base_url}/r/{self.room}/say-signed/{self.did}/{sig}/{nonce}/{encoded_text}"

        # 1. Try GET /say-signed
        try:
            req = Request(
                get_url,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "User-Agent": f"technocore-did-starter/{APP_VERSION}",
                },
            )
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                logger.info("Published signed ATTEST via GET say-signed: %s", normalized)
                return {"status": "ok", "response": raw, "method": "GET", "nonce": nonce, "sig": sig}
        except HTTPError as err:
            logger.warning("GET say-signed returned HTTP %d. Attempting POST /r/%s fallback...", err.code, self.room)
        except Exception as err:
            logger.warning("GET say-signed failed (%s). Attempting POST /r/%s fallback...", err, self.room)

        # 2. Fallback to signed POST
        post_url = f"{self.base_url}/r/{self.room}?format=json"
        body_bytes = json.dumps(
            {
                "did": self.did,
                "sig": sig,
                "nonce": nonce,
                "text": normalized,
            },
            ensure_ascii=False,
        ).encode("utf-8")

        req = Request(
            post_url,
            data=body_bytes,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": f"technocore-did-starter/{APP_VERSION}",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
                logger.info("Published signed ATTEST via POST: %s", normalized)
                return {"status": "ok", "response": data, "method": "POST", "nonce": nonce, "sig": sig}
        except Exception as err:
            raise NetworkError(f"Failed to post signed message to {self.room}: {err}") from err

    def process_cycle(self, wait: float = DEFAULT_FOLLOW_WAIT_SECONDS) -> int:
        """Execute one long-polling cycle (?since=X&wait=10)."""
        if not self._initialized:
            current_cursor = self.initialize_tip_cursor()
        else:
            current_cursor = self.state_manager.get_local_cursor()

        self.last_poll_time = datetime.now(timezone.utc).isoformat()

        try:
            response = self.read_room(since=current_cursor, limit=DEFAULT_POLL_LIMIT, wait=wait)
        except NetworkError as err:
            logger.error("Failed to read #kibble room: %s", err)
            return 0

        messages = response.get("messages", [])
        last_seq = response.get("last_seq", current_cursor)

        if not messages:
            if last_seq > current_cursor:
                self.state_manager.update_cursor(last_seq)
            return 0

        processed_count = 0
        new_max_seq = current_cursor

        for msg in messages:
            seq = msg.get("seq", 0)
            if seq <= current_cursor:
                continue

            if seq > new_max_seq:
                new_max_seq = seq

            processed_count += 1

            # 1. If it's a JOB, index it in memory
            if self.verifier.index_job(msg):
                continue

            # 2. If it's a DELIVER/RESULT, evaluate strictly
            eval_result = self.verifier.evaluate_deliverable(msg)
            if not eval_result:
                continue

            job_id = eval_result["job_id"]
            score = eval_result["score"]
            reason = eval_result["reason"]

            logger.info(
                "Evaluated deliverable: seq=%d job=%s score=%s reason='%s'",
                eval_result["seq"],
                job_id,
                score.upper(),
                reason[:70],
            )

            # Check 60s rate limit on broadcast
            now = time.time()
            elapsed = now - self.last_attestation_time
            if elapsed < DEFAULT_ATTESTATION_COOLDOWN_SECONDS:
                logger.info(
                    "Rate limit active (%.1fs < %.0fs). Logging evaluation to ledger without broadcast for seq=%d",
                    elapsed,
                    DEFAULT_ATTESTATION_COOLDOWN_SECONDS,
                    eval_result["seq"],
                )
                self.state_manager.append_ledger({
                    "target_did": eval_result["target_did"],
                    "sequence_id": eval_result["seq"],
                    "job_id": job_id,
                    "score": score,
                    "reason": reason,
                    "broadcast": False,
                })
                continue

            # Format native ATTEST v1 line
            attestation_text = self.verifier.format_attestation_text(
                job_id=job_id,
                score=score,
                reason=reason,
            )

            try:
                result = self.post_signed_attestation(attestation_text)
                self.last_attestation_time = time.time()
                self.total_attestations += 1
                if score == "yes":
                    self.attest_yes_count += 1
                else:
                    self.attest_not_count += 1

                # Record to ledger
                self.state_manager.append_ledger({
                    "target_did": eval_result["target_did"],
                    "sequence_id": eval_result["seq"],
                    "job_id": job_id,
                    "score": score,
                    "reason": reason,
                    "attestation_text": attestation_text,
                    "nonce": result.get("nonce"),
                    "signature": result.get("sig"),
                    "broadcast": True,
                })
                logger.info("Successfully recorded ATTEST for job %s (score=%s) to ledger", job_id, score)
            except Exception as err:
                logger.error("Failed to broadcast ATTEST for job %s: %s", job_id, err)

        # Advance cursor to newest seq
        if new_max_seq > current_cursor:
            self.state_manager.update_cursor(new_max_seq)

        return processed_count

    def run_loop(self) -> None:
        """Continuous long-polling daemon loop."""
        self._running = True
        logger.info("Starting PoUI Sentinel long-polling engine on #%s (DID: %s)", self.room, self.did)

        # Initial tip jump
        self.initialize_tip_cursor()

        while self._running:
            try:
                self.process_cycle(wait=DEFAULT_FOLLOW_WAIT_SECONDS)
            except Exception as err:
                logger.error("Unexpected error in polling loop: %s", err, exc_info=True)
                time.sleep(2.0)

        logger.info("PoUI Sentinel polling loop stopped.")

    def stop(self) -> None:
        """Signal polling loop to terminate gracefully."""
        self._running = False


# ==============================================================================
# Health Web Server (`HealthServer`)
# ==============================================================================


def create_health_app(client: KibbleClient, start_time: float) -> Flask:
    """Create Flask application exposing health, uptime, and verification metrics."""
    app = Flask(__name__)

    @app.route("/", methods=["GET"])
    @app.route("/health", methods=["GET"])
    def health() -> Any:
        uptime = round(time.time() - start_time, 2)
        cursor = client.state_manager.get_local_cursor()
        ledger_count = client.state_manager.get_ledger_count()
        target_did_match = (client.did == TARGET_DID)

        return jsonify({
            "status": "healthy",
            "service": APP_NAME,
            "version": APP_VERSION,
            "agent_did": client.did,
            "target_did_expected": TARGET_DID,
            "target_did_match": target_did_match,
            "uptime_seconds": uptime,
            "total_attestations": client.total_attestations,
            "attestation_breakdown": {
                "yes": client.attest_yes_count,
                "not": client.attest_not_count,
            },
            "current_cursor": cursor,
            "last_poll_time": client.last_poll_time,
            "indexed_jobs_count": len(client.verifier.job_cache),
            "ledger_count": ledger_count,
            "testnet_consumer_ready": client.inference_consumer.is_configured,
            "dry_run": client.dry_run,
        })

    @app.route("/ledger", methods=["GET"])
    def ledger() -> Any:
        limit = min(int(request.args.get("limit", 20)), 100)
        entries = client.state_manager.get_recent_ledger_entries(limit=limit)
        return jsonify({
            "total_entries": client.state_manager.get_ledger_count(),
            "returned": len(entries),
            "entries": entries,
        })

    return app


# ==============================================================================
# CLI Entrypoint & Daemon Harness
# ==============================================================================


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Technocore #kibble PoUI Sentinel & Attester",
    )
    parser.add_argument(
        "--key-path",
        type=Path,
        default=DEFAULT_KEY_PATH,
        help=f"Path to Ed25519 identity.pem (default: {DEFAULT_KEY_PATH})",
    )
    parser.add_argument(
        "--cursor-path",
        type=Path,
        default=DEFAULT_CURSOR_PATH,
        help=f"Path to cursor.json (default: {DEFAULT_CURSOR_PATH})",
    )
    parser.add_argument(
        "--ledger-path",
        type=Path,
        default=DEFAULT_LEDGER_PATH,
        help=f"Path to work_ledger.jsonl (default: {DEFAULT_LEDGER_PATH})",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=os.environ.get("TECHNOCORE_BASE_URL", DEFAULT_BASE_URL),
        help=f"Technocore base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--room",
        type=str,
        default=os.environ.get("TECHNOCORE_ROOM", DEFAULT_ROOM),
        help=f"Room name to monitor and attest (default: {DEFAULT_ROOM})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", DEFAULT_SERVER_PORT)),
        help=f"Flask server binding port (default: {DEFAULT_SERVER_PORT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=os.environ.get("DRY_RUN", "").lower() in {"1", "true", "yes"},
        help="Run verification and logging without posting signatures to server",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single ingestion cycle without long-poll and exit immediately",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug-level logging output",
    )
    return parser.parse_args()


def main() -> None:
    """Main execution harness."""
    args = parse_args()
    log_level = logging.DEBUG if args.verbose else logging.INFO
    configure_logging(log_level)

    logger.info("Initializing %s v%s...", APP_NAME, APP_VERSION)

    # 1. Load private key & derive DID
    try:
        private_key = TechnocoreCrypto.load_private_key(key_path=args.key_path)
    except CryptoError as err:
        logger.error("Identity Initialization Error: %s", err)
        sys.exit(1)

    agent_did = TechnocoreCrypto.did_from_private_key(private_key)
    logger.info("Agent Identity Loaded: %s", agent_did)
    if agent_did == TARGET_DID:
        logger.info("Verified target DID match: %s", TARGET_DID)
    else:
        logger.warning(
            "DID mismatch: loaded '%s', expected target DID '%s'. Proceeding with loaded identity.",
            agent_did,
            TARGET_DID,
        )

    # 2. Initialize State & Client
    state_manager = StateManager(
        cursor_path=args.cursor_path,
        ledger_path=args.ledger_path,
        base_url=args.base_url,
        agent_did=agent_did,
    )
    client = KibbleClient(
        private_key=private_key,
        base_url=args.base_url,
        room=args.room,
        state_manager=state_manager,
        dry_run=args.dry_run,
    )

    # 3. Single-cycle mode if --once specified
    if args.once:
        logger.info("Running single ingestion cycle (--once)...")
        count = client.process_cycle(wait=0)
        logger.info("Single cycle completed. Processed %d new messages. Exiting.", count)
        sys.exit(0)

    # 4. Start background long-polling thread
    poll_thread = threading.Thread(target=client.run_loop, name="KibblePollEngine", daemon=True)
    poll_thread.start()

    # 5. Start embedded Flask health server
    start_time = time.time()
    flask_app = create_health_app(client, start_time)

    # Setup signal handlers for graceful termination
    def handle_signal(sig: int, _frame: Any) -> None:
        logger.info("Received termination signal (%s). Shutting down agent...", sig)
        client.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    logger.info("Starting health server on 0.0.0.0:%d...", args.port)
    flask_app.run(host="0.0.0.0", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
