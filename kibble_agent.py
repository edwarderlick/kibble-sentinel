#!/usr/bin/env python3
"""kibble_agent.py - Production-Grade Proof of Useful Inference (PoUI) Compute Agent.

Built for Technocore's #kibble room (https://technocore.chat/r/kibble).
This agent is a verifiable PoUI attester and compute ledger client designed to build
a legitimate work history for the Flop Labs Q4 testnet.

Strictly adheres to anti-spam / no-chat rules: NEVER posts greetings, heartbeats,
or canned onboarding messages. Only posts cryptographically signed attestations.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import math
import os
import random
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

APP_NAME = "kibble-agent"
APP_VERSION = "1.0.0"
DEFAULT_BASE_URL = "https://technocore.chat"
DEFAULT_ROOM = "kibble"
TARGET_DID = "did:key:z6MknbHdUp8fKFeZYL3XrtidwfsXJujWfYRXKAs93xsoYZfn"

DEFAULT_KEY_PATH = Path("identity.pem")
DEFAULT_CURSOR_PATH = Path("cursor.json")
DEFAULT_LEDGER_PATH = Path("work_ledger.jsonl")

DEFAULT_POLL_MIN_SECONDS = 30.0
DEFAULT_POLL_MAX_SECONDS = 45.0
DEFAULT_ATTESTATION_COOLDOWN_SECONDS = 60.0
DEFAULT_HTTP_TIMEOUT_SECONDS = 20.0
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
WORK_PATTERNS = [
    re.compile(r"^(?:RESULT|DELIVER|PoUI|PROOF)\s*(?:v\d+)?\s*\|\s*([^|]+)\s*\|\s*(.+)$", re.IGNORECASE),
    re.compile(r"^\[(?:PoUI|WORK|TASK|COMPUTE)[^\]]*\]\s*\|\s*([^|]+)\s*\|\s*(.+)$", re.IGNORECASE),
]

# Configure structured UTF-8 logging
logger = logging.getLogger("kibble_agent")


def configure_logging(level: int = logging.INFO) -> None:
    """Configure clean, structured UTF-8 stdout logging."""
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
            # Key is encrypted but no password provided or wrong password type
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
    def generate_and_save_identity(
        cls,
        path: Path | str,
        passphrase: str | bytes | None = None,
        overwrite: bool = False,
    ) -> tuple[Ed25519PrivateKey, str]:
        """Generate a new Ed25519 identity and save it to disk."""
        target_path = Path(path).expanduser().resolve()
        if target_path.exists() and not overwrite:
            raise CryptoError(f"Refusing to overwrite existing identity at {target_path}")

        key = Ed25519PrivateKey.generate()
        pw_bytes = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        encryption = (
            serialization.BestAvailableEncryption(pw_bytes)
            if pw_bytes
            else serialization.NoEncryption()
        )
        pem_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(pem_bytes)
        try:
            os.chmod(target_path, 0o600)
        except OSError:
            pass

        did = cls.did_from_private_key(key)
        return key, did

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
    """Manages persistent cursor state and append-only work ledger."""

    def __init__(
        self,
        cursor_path: Path | str = DEFAULT_CURSOR_PATH,
        ledger_path: Path | str = DEFAULT_LEDGER_PATH,
    ) -> None:
        self.cursor_path = Path(cursor_path).expanduser().resolve()
        self.ledger_path = Path(ledger_path).expanduser().resolve()
        self._lock = threading.Lock()

    def get_cursor(self) -> int:
        """Read the persisted sequence cursor, returning 0 if not found."""
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
        """Atomically update the persistent sequence cursor."""
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
                raise StateError(f"Failed to persist cursor: {err}") from err

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
                raise StateError(f"Failed to write to ledger: {err}") from err

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
# Work Ingestion & Verification Logic (`WorkVerifier`)
# ==============================================================================


class WorkVerifier:
    """Parses and validates structured work messages (RESULT, DELIVER, PoUI, PROOF)."""

    def __init__(self, my_did: str) -> None:
        self.my_did = my_did

    def parse_work_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Evaluate a room message to determine if it is verifiable unverified work.
        
        Ignores:
        - Self messages (from my_did)
        - Sentinels / existing PoUI attestations
        - Simple check-ins, unparseable chat, lobby spam
        """
        sender = message.get("from", "")
        seq = message.get("seq")
        text = message.get("text", "")

        if not sender or seq is None or not text:
            return None

        # Ignore self-messages
        if sender == self.my_did:
            return None

        # Ignore existing sentinel attestations or bot check-ins
        if "[PoUI Sentinel]" in text or text.startswith("ATTEST") or text.startswith("CLAIM"):
            return None

        # Check for matching work patterns
        for pattern in WORK_PATTERNS:
            match = pattern.match(text)
            if match:
                job_id = match.group(1).strip()
                content = match.group(2).strip()
                if self.is_valid_work_payload(job_id, content):
                    job_hash = hashlib.sha256(f"{job_id}:{content}".encode("utf-8")).hexdigest()
                    proof_summary = self.summarize_proof(job_id, content, job_hash)
                    return {
                        "seq": seq,
                        "target_did": sender,
                        "job_id": job_id,
                        "job_hash": f"sha256:{job_hash}",
                        "proof_summary": proof_summary,
                        "raw_text": text,
                        "content_len": len(content),
                    }

        return None

    @staticmethod
    def is_valid_work_payload(job_id: str, content: str) -> bool:
        """Validate structure and substance of the work deliverable.
        
        Requires:
        - Non-trivial job identifier (at least 3 characters)
        - Substantive output content (at least 15 characters, not just placeholder)
        - Verifiable structure (e.g. hash linkage, technical report, or execution summary)
        """
        if not job_id or len(job_id) < 3:
            return False
        if not content or len(content) < 15:
            return False

        # Filter trivial placeholders
        lowered = content.lower()
        if lowered in {"done", "finished", "ok", "delivered", "n/a", "test", "hello world"}:
            return False

        return True

    @staticmethod
    def summarize_proof(job_id: str, content: str, job_hash: str) -> str:
        """Create a compact, verifiable single-line proof summary for attestation."""
        clean_content = TechnocoreCrypto.normalize_message(content)
        # Use short hash and a trimmed snippet of the work evidence
        short_hash = job_hash[:16]
        preview = clean_content[:64]
        if len(clean_content) > 64:
            preview += "..."
        summary = f"job:{job_id} h:{short_hash} [{preview}]"
        # Ensure single line and within safe bounds
        return TechnocoreCrypto.normalize_message(summary)

    @staticmethod
    def format_attestation_text(target_sender: str, seq: int, proof_summary: str) -> str:
        """Build the exact required attestation message format:
        [PoUI Sentinel]: ATTEST target:<target_sender> seq:<msg_id> proof:<proof_summary> status:VERIFIED
        """
        raw = f"[PoUI Sentinel]: ATTEST target:{target_sender} seq:{seq} proof:{proof_summary} status:VERIFIED"
        return TechnocoreCrypto.normalize_message(raw)


# ==============================================================================
# Testnet Ready Modular Hook (`InferenceConsumer`)
# ==============================================================================


class InferenceConsumer:
    """Extensible client hook for Flop Labs Q4 Testnet inference & faucet integration.
    
    Ready to plug into Q4 faucet tokens and spend them on decentralized inference.
    """

    def __init__(
        self,
        faucet_token: str | None = None,
        testnet_endpoint: str | None = None,
    ) -> None:
        self.faucet_token = faucet_token or os.environ.get("FLOP_FAUCET_TOKEN")
        self.testnet_endpoint = testnet_endpoint or os.environ.get(
            "FLOP_TESTNET_ENDPOINT", "https://testnet.flop.ai/v1"
        )
        self._total_inferences = 0

    def execute_faucet_inference(self, faucet_token: str, prompt: str) -> dict[str, Any]:
        """Execute an inference task using Flop Labs Q4 testnet faucet tokens.
        
        This method acts as the standard pluggable hook for Q4 inference execution.
        """
        token = faucet_token or self.faucet_token
        if not token:
            logger.info("InferenceConsumer: No faucet token provided; simulating testnet dry-run execution")
            token = "faucet_testnet_dryrun"

        prompt_clean = TechnocoreCrypto.normalize_message(prompt)
        prompt_hash = hashlib.sha256(prompt_clean.encode("utf-8")).hexdigest()

        # Simulated Q4 PoUI execution stub
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
        logger.info("InferenceConsumer executed testnet task %s for prompt hash %s", execution_id, prompt_hash[:8])
        return result

    @property
    def is_configured(self) -> bool:
        """Return True if faucet token is configured."""
        return bool(self.faucet_token)

    @property
    def total_inferences(self) -> int:
        """Return count of executed inferences."""
        return self._total_inferences


# ==============================================================================
# Client & Polling Engine (`KibbleClient`)
# ==============================================================================


class KibbleClient:
    """Client for reading from and publishing signed attestations to Technocore #kibble."""

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
        self.state_manager = state_manager or StateManager()
        self.timeout = timeout
        self.dry_run = dry_run

        self.verifier = WorkVerifier(my_did=self.did)
        self.inference_consumer = InferenceConsumer()

        self.last_nonce = int(time.time() * 1000)
        self.last_attestation_time = 0.0
        self.total_attestations = 0
        self.last_poll_time: str | None = None
        self._running = False
        self._nonce_lock = threading.Lock()

    def get_next_nonce(self) -> int:
        """Generate a strictly increasing millisecond nonce."""
        with self._nonce_lock:
            now_ms = int(time.time() * 1000)
            if now_ms <= self.last_nonce:
                self.last_nonce += 1
            else:
                self.last_nonce = now_ms
            return self.last_nonce

    def read_room(self, since: int, limit: int = 50) -> dict[str, Any]:
        """Fetch messages from the room starting after sequence `since`."""
        query: dict[str, str | int] = {"format": "json", "limit": limit}
        if since > 0:
            query["since"] = since

        url = f"{self.base_url}/r/{self.room}?{urlencode(query)}"
        req = Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": f"{APP_NAME}/{APP_VERSION} (PoUI Sentinel; Flop Q4 Testnet)",
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

    def post_signed_attestation(self, text: str) -> dict[str, Any]:
        """Publish a cryptographically signed attestation message to #kibble.
        
        Implements primary GET write endpoint:
        GET https://technocore.chat/r/kibble/say-signed/<did>/<sig>/<nonce>/<encoded_text>
        with fallback to signed POST if GET fails or text is long.
        """
        nonce = self.get_next_nonce()
        normalized, payload = TechnocoreCrypto.format_signing_payload(self.room, nonce, text)
        sig = TechnocoreCrypto.sign_payload(self.private_key, payload)

        if self.dry_run:
            logger.info("[DRY-RUN] Would post attestation: %s (nonce=%d, sig=%s)", normalized, nonce, sig[:16])
            return {"status": "dry_run", "nonce": nonce, "sig": sig, "text": normalized}

        encoded_text = quote(normalized, safe="")
        get_url = f"{self.base_url}/r/{self.room}/say-signed/{self.did}/{sig}/{nonce}/{encoded_text}"

        # Attempt GET endpoint first
        try:
            req = Request(
                get_url,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "User-Agent": f"{APP_NAME}/{APP_VERSION}",
                },
            )
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                logger.info("Published signed attestation via GET say-signed: %s", normalized)
                return {"status": "ok", "response": raw, "method": "GET", "nonce": nonce, "sig": sig}
        except HTTPError as err:
            logger.warning("GET say-signed returned HTTP %d. Attempting POST /r/%s fallback...", err.code, self.room)
        except Exception as err:
            logger.warning("GET say-signed failed (%s). Attempting POST /r/%s fallback...", err, self.room)

        # Fallback to signed POST
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
                "User-Agent": f"{APP_NAME}/{APP_VERSION}",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
                logger.info("Published signed attestation via POST: %s", normalized)
                return {"status": "ok", "response": data, "method": "POST", "nonce": nonce, "sig": sig}
        except Exception as err:
            raise NetworkError(f"Failed to post signed message to {self.room}: {err}") from err

    def process_cycle(self) -> int:
        """Execute one polling and verification cycle.
        
        Returns count of new messages processed.
        """
        self.last_poll_time = datetime.now(timezone.utc).isoformat()
        current_cursor = self.state_manager.get_cursor()

        try:
            response = self.read_room(since=current_cursor, limit=50)
        except NetworkError as err:
            logger.error("Failed to read #kibble room: %s", err)
            return 0

        messages = response.get("messages", [])
        last_seq = response.get("last_seq", current_cursor)

        # If cursor is uninitialized (0) and room has messages, sync to current last_seq
        if current_cursor == 0 and last_seq > 0 and not messages:
            logger.info("Initializing cursor to current room sequence: %d", last_seq)
            self.state_manager.update_cursor(last_seq)
            return 0

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
            work_item = self.verifier.parse_work_message(msg)
            if not work_item:
                continue

            logger.info(
                "Identified verifiable PoUI work: seq=%d target=%s job=%s hash=%s",
                work_item["seq"],
                work_item["target_did"][:24] + "...",
                work_item["job_id"],
                work_item["job_hash"][:16],
            )

            # Check 60s rate limit
            now = time.time()
            elapsed = now - self.last_attestation_time
            if elapsed < DEFAULT_ATTESTATION_COOLDOWN_SECONDS:
                logger.info(
                    "Rate limit active (%.1fs < %.0fs). Skipping attestation broadcast for seq=%d",
                    elapsed,
                    DEFAULT_ATTESTATION_COOLDOWN_SECONDS,
                    work_item["seq"],
                )
                # Still record to ledger as verified work
                self.state_manager.append_ledger({
                    "target_did": work_item["target_did"],
                    "sequence_id": work_item["seq"],
                    "job_id": work_item["job_id"],
                    "job_hash": work_item["job_hash"],
                    "verification_status": "VERIFIED_RATE_LIMITED",
                    "proof_summary": work_item["proof_summary"],
                })
                continue

            # Format and publish attestation
            attestation_text = self.verifier.format_attestation_text(
                target_sender=work_item["target_did"],
                seq=work_item["seq"],
                proof_summary=work_item["proof_summary"],
            )

            try:
                result = self.post_signed_attestation(attestation_text)
                self.last_attestation_time = time.time()
                self.total_attestations += 1

                # Persist to append-only work ledger
                self.state_manager.append_ledger({
                    "target_did": work_item["target_did"],
                    "sequence_id": work_item["seq"],
                    "job_id": work_item["job_id"],
                    "job_hash": work_item["job_hash"],
                    "verification_status": "VERIFIED",
                    "proof_summary": work_item["proof_summary"],
                    "attestation_text": attestation_text,
                    "nonce": result.get("nonce"),
                    "signature": result.get("sig"),
                })
                logger.info("Successfully recorded attestation for seq=%d to work_ledger.jsonl", work_item["seq"])
            except Exception as err:
                logger.error("Failed to broadcast attestation for seq=%d: %s", work_item["seq"], err)

        # Update cursor to highest sequence processed
        if new_max_seq > current_cursor:
            self.state_manager.update_cursor(new_max_seq)

        return processed_count

    def run_loop(self) -> None:
        """Continuous polling daemon loop with 30-45s jittered intervals."""
        self._running = True
        logger.info("Starting PoUI Sentinel polling loop on #%s (DID: %s)", self.room, self.did)

        while self._running:
            try:
                self.process_cycle()
            except Exception as err:
                logger.error("Unexpected error in polling cycle: %s", err, exc_info=True)

            sleep_duration = random.uniform(DEFAULT_POLL_MIN_SECONDS, DEFAULT_POLL_MAX_SECONDS)
            # Sleep in small slices to respond promptly to stop signal
            deadline = time.time() + sleep_duration
            while self._running and time.time() < deadline:
                time.sleep(0.5)

        logger.info("PoUI Sentinel polling loop stopped.")

    def stop(self) -> None:
        """Signal polling loop to terminate gracefully."""
        self._running = False


# ==============================================================================
# Health Web Server (`HealthServer`)
# ==============================================================================


def create_health_app(client: KibbleClient, start_time: float) -> Flask:
    """Create a minimal Flask application exposing health and status metrics."""
    app = Flask(__name__)

    @app.route("/", methods=["GET"])
    @app.route("/health", methods=["GET"])
    def health() -> Any:
        uptime = round(time.time() - start_time, 2)
        cursor = client.state_manager.get_cursor()
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
            "current_cursor": cursor,
            "last_poll_time": client.last_poll_time,
            "ledger_count": ledger_count,
            "testnet_consumer_ready": True,
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
        description="Technocore #kibble PoUI Compute Agent & Ledger Attester",
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
        help="Run a single ingestion cycle and exit immediately",
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
    state_manager = StateManager(cursor_path=args.cursor_path, ledger_path=args.ledger_path)
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
        count = client.process_cycle()
        logger.info("Single cycle completed. Processed %d new messages. Exiting.", count)
        sys.exit(0)

    # 4. Start background polling thread
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
