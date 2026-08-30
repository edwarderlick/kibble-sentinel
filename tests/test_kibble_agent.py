"""Unit and Integration Tests for kibble_agent.py."""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure root directory is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kibble_agent import (
    DEFAULT_ROOM,
    TARGET_DID,
    CryptoError,
    InferenceConsumer,
    KibbleClient,
    ProtocolError,
    StateManager,
    TechnocoreCrypto,
    WorkVerifier,
    create_health_app,
)


@pytest.fixture
def sample_private_key() -> Ed25519PrivateKey:
    """Generate a clean Ed25519 key for testing."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
def sample_did(sample_private_key: Ed25519PrivateKey) -> str:
    """Derive did:key string for sample key."""
    return TechnocoreCrypto.did_from_private_key(sample_private_key)


@pytest.fixture
def temp_dir() -> Path:
    """Provide a clean temporary directory for state testing."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


# ==============================================================================
# TechnocoreCrypto Tests
# ==============================================================================


class TestTechnocoreCrypto:
    def test_base58_roundtrip(self) -> None:
        raw = b"\x00\x00\xed\x01test_payload_12345"
        encoded = TechnocoreCrypto.base58btc_encode(raw)
        assert encoded.startswith("11")  # Preserves leading zeros
        decoded = TechnocoreCrypto.base58btc_decode(encoded)
        assert decoded == raw

    def test_did_derivation_format(self, sample_private_key: Ed25519PrivateKey) -> None:
        did = TechnocoreCrypto.did_from_private_key(sample_private_key)
        assert did.startswith("did:key:z6Mk")
        assert len(did) == 8 + 48  # 'did:key:' (8) + 48 multibase chars

    def test_target_did_parsing(self) -> None:
        pub_key = TechnocoreCrypto.public_key_from_did(TARGET_DID)
        derived_did = TechnocoreCrypto.did_from_public_key(pub_key)
        assert derived_did == TARGET_DID

    def test_normalize_message(self) -> None:
        # Test newline and invisible character stripping
        raw = "  Line 1\nLine 2\t\u200bWith ZeroWidth   "
        normalized = TechnocoreCrypto.normalize_message(raw)
        assert "\n" not in normalized
        assert "\t" not in normalized
        assert normalized == "Line 1 Line 2  With ZeroWidth"

    def test_normalize_empty_error(self) -> None:
        with pytest.raises(ProtocolError):
            TechnocoreCrypto.normalize_message("   \n\t   ")

    def test_signing_and_verification(self, sample_private_key: Ed25519PrivateKey, sample_did: str) -> None:
        nonce = 1788079500123
        normalized, payload = TechnocoreCrypto.format_signing_payload("kibble", nonce, "Hello Technocore PoUI")
        assert payload == b"kibble|1788079500123|Hello Technocore PoUI"

        sig = TechnocoreCrypto.sign_payload(sample_private_key, payload)
        assert len(sig) == 86
        assert "=" not in sig  # Must be unpadded

        # Valid signature
        assert TechnocoreCrypto.verify_signature(sample_did, sig, payload) is True

        # Tampered payload
        tampered = b"kibble|1788079500123|Tampered Text"
        assert TechnocoreCrypto.verify_signature(sample_did, sig, tampered) is False

    def test_load_key_from_unencrypted_pem(self, temp_dir: Path) -> None:
        key = Ed25519PrivateKey.generate()
        pem_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key_file = temp_dir / "test_unencrypted.pem"
        key_file.write_bytes(pem_bytes)

        loaded = TechnocoreCrypto.load_private_key(key_path=key_file)
        assert TechnocoreCrypto.did_from_private_key(loaded) == TechnocoreCrypto.did_from_private_key(key)

    def test_load_key_from_encrypted_pem_with_passphrase(self, temp_dir: Path) -> None:
        key = Ed25519PrivateKey.generate()
        passphrase = "super_secret_testnet_passphrase_123"
        pem_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
        key_file = temp_dir / "test_encrypted.pem"
        key_file.write_bytes(pem_bytes)

        # Fail without passphrase
        with pytest.raises(CryptoError):
            TechnocoreCrypto.load_private_key(key_path=key_file)

        # Succeed with passphrase
        loaded = TechnocoreCrypto.load_private_key(key_path=key_file, passphrase=passphrase)
        assert TechnocoreCrypto.did_from_private_key(loaded) == TechnocoreCrypto.did_from_private_key(key)

    def test_load_key_from_env_var(self) -> None:
        key = Ed25519PrivateKey.generate()
        pem_str = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")

        with patch.dict(os.environ, {"PRIVATE_KEY_PEM": pem_str}):
            loaded = TechnocoreCrypto.load_private_key()
            assert TechnocoreCrypto.did_from_private_key(loaded) == TechnocoreCrypto.did_from_private_key(key)


# ==============================================================================
# StateManager Tests
# ==============================================================================


class TestStateManager:
    def test_cursor_lifecycle(self, temp_dir: Path) -> None:
        cursor_path = temp_dir / "cursor.json"
        sm = StateManager(cursor_path=cursor_path)

        # Default is 0
        assert sm.get_cursor() == 0

        # Update cursor
        sm.update_cursor(324015, extra_metadata={"last_from": "did:key:z6Mk..."})
        assert sm.get_cursor() == 324015

        # Verify JSON file content on disk
        data = json.loads(cursor_path.read_text(encoding="utf-8"))
        assert data["cursor"] == 324015
        assert "updated_at" in data

    def test_work_ledger_append(self, temp_dir: Path) -> None:
        ledger_path = temp_dir / "work_ledger.jsonl"
        sm = StateManager(ledger_path=ledger_path)

        assert sm.get_ledger_count() == 0

        entry1 = {
            "target_did": "did:key:z6MkTest1",
            "sequence_id": 100,
            "job_id": "k12345",
            "job_hash": "sha256:abcd",
            "verification_status": "VERIFIED",
        }
        entry2 = {
            "target_did": "did:key:z6MkTest2",
            "sequence_id": 101,
            "job_id": "k67890",
            "job_hash": "sha256:ef01",
            "verification_status": "VERIFIED",
        }

        sm.append_ledger(entry1)
        sm.append_ledger(entry2)

        assert sm.get_ledger_count() == 2
        recent = sm.get_recent_ledger_entries(limit=10)
        assert len(recent) == 2
        assert recent[0]["sequence_id"] == 100
        assert recent[1]["sequence_id"] == 101
        assert "timestamp" in recent[0]


# ==============================================================================
# WorkVerifier Tests
# ==============================================================================


class TestWorkVerifier:
    def test_ignore_self_messages(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        msg = {
            "seq": 10,
            "from": sample_did,
            "text": "DELIVER v1 | k12345 | Proper research output about FLOP testnet",
        }
        assert verifier.parse_work_message(msg) is None

    def test_ignore_chat_and_spam(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        # Check-in chat
        msg1 = {"seq": 11, "from": "did:key:z6MkOther", "text": "gm everyone, kibble agent online"}
        assert verifier.parse_work_message(msg1) is None

        # Existing Sentinel attestation
        msg2 = {
            "seq": 12,
            "from": "did:key:z6MkOther",
            "text": "[PoUI Sentinel]: ATTEST target:did:key:... seq:10 proof:... status:VERIFIED",
        }
        assert verifier.parse_work_message(msg2) is None

        # Claim message
        msg3 = {"seq": 13, "from": "did:key:z6MkOther", "text": "CLAIM v1 | k12345 | worker"}
        assert verifier.parse_work_message(msg3) is None

    def test_parse_valid_deliver(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        msg = {
            "seq": 324017,
            "from": "did:key:z6MkkFtZycpRyviGe3JFA9rnAyQPdmNuNNyM4Ak4iM1jjwng",
            "text": "DELIVER v1 | k8d5dff166f | Research summary on FLOP/Technocore ecosystem with verifiable output details.",
        }
        parsed = verifier.parse_work_message(msg)
        assert parsed is not None
        assert parsed["seq"] == 324017
        assert parsed["job_id"] == "k8d5dff166f"
        assert parsed["target_did"] == "did:key:z6MkkFtZycpRyviGe3JFA9rnAyQPdmNuNNyM4Ak4iM1jjwng"
        assert parsed["job_hash"].startswith("sha256:")
        assert "k8d5dff166f" in parsed["proof_summary"]

    def test_parse_valid_result_and_poui(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        msg_result = {
            "seq": 324020,
            "from": "did:key:z6MkWorker1",
            "text": "RESULT v1 | k9c19ebd506 | Complete truth table calculation verified with Boolean expressions.",
        }
        parsed = verifier.parse_work_message(msg_result)
        assert parsed is not None
        assert parsed["job_id"] == "k9c19ebd506"

        msg_poui = {
            "seq": 324021,
            "from": "did:key:z6MkWorker2",
            "text": "PoUI v1 | k4db27d9607 | Executed matrix multiplication kernel across 128 compute units.",
        }
        parsed_poui = verifier.parse_work_message(msg_poui)
        assert parsed_poui is not None
        assert parsed_poui["job_id"] == "k4db27d9607"

    def test_attestation_format(self) -> None:
        target = "did:key:z6MkTargetSender"
        seq = 324012
        proof = "job:kbf03e83512 h:e5c09b8d6c0d5737 [Compile CMake build...]"
        formatted = WorkVerifier.format_attestation_text(target, seq, proof)
        expected = f"[PoUI Sentinel]: ATTEST target:{target} seq:{seq} proof:{proof} status:VERIFIED"
        assert formatted == expected


# ==============================================================================
# InferenceConsumer Tests
# ==============================================================================


class TestInferenceConsumer:
    def test_execute_faucet_inference(self) -> None:
        consumer = InferenceConsumer(faucet_token="faucet_token_q4_testnet_xyz")
        res = consumer.execute_faucet_inference(
            faucet_token="faucet_token_q4_testnet_xyz",
            prompt="Compute matrix factorization on benchmark tensor",
        )
        assert res["status"] == "SUCCESS"
        assert "execution_id" in res
        assert "proof_of_useful_inference" in res
        assert res["proof_of_useful_inference"]["model"] == "flop-q4-sentinel-v1"
        assert consumer.total_inferences == 1


# ==============================================================================
# KibbleClient & Rate Limiting Tests
# ==============================================================================


class TestKibbleClient:
    def test_nonce_monotonicity(self, sample_private_key: Ed25519PrivateKey, temp_dir: Path) -> None:
        sm = StateManager(cursor_path=temp_dir / "cursor.json", ledger_path=temp_dir / "ledger.jsonl")
        client = KibbleClient(private_key=sample_private_key, state_manager=sm, dry_run=True)

        n1 = client.get_next_nonce()
        n2 = client.get_next_nonce()
        n3 = client.get_next_nonce()

        assert n1 < n2 < n3

    def test_process_cycle_mocked_messages(self, sample_private_key: Ed25519PrivateKey, temp_dir: Path) -> None:
        sm = StateManager(cursor_path=temp_dir / "cursor.json", ledger_path=temp_dir / "ledger.jsonl")
        client = KibbleClient(private_key=sample_private_key, state_manager=sm, dry_run=True)

        # Mock room response with 1 valid DELIVER and 1 chat spam
        mock_response = {
            "room": "kibble",
            "count": 2,
            "last_seq": 105,
            "messages": [
                {
                    "seq": 104,
                    "from": "did:key:z6MkSpammer",
                    "text": "hello friends!",
                    "nonce": 12345,
                },
                {
                    "seq": 105,
                    "from": "did:key:z6MkVendor",
                    "text": "DELIVER v1 | k8d5dff166f | Research summary on 'Identify the original composer' verified.",
                    "nonce": 12346,
                },
            ],
        }

        with patch.object(client, "read_room", return_value=mock_response):
            count = client.process_cycle()
            assert count == 2
            assert client.total_attestations == 1
            assert sm.get_cursor() == 105
            assert sm.get_ledger_count() == 1

            entries = sm.get_recent_ledger_entries(limit=1)
            assert entries[0]["sequence_id"] == 105
            assert entries[0]["job_id"] == "k8d5dff166f"
            assert entries[0]["verification_status"] == "VERIFIED"

    def test_attestation_rate_limit(self, sample_private_key: Ed25519PrivateKey, temp_dir: Path) -> None:
        sm = StateManager(cursor_path=temp_dir / "cursor.json", ledger_path=temp_dir / "ledger.jsonl")
        client = KibbleClient(private_key=sample_private_key, state_manager=sm, dry_run=True)

        # Two consecutive valid work messages in single batch
        mock_response = {
            "room": "kibble",
            "count": 2,
            "last_seq": 202,
            "messages": [
                {
                    "seq": 201,
                    "from": "did:key:z6MkVendor1",
                    "text": "DELIVER v1 | k1111111111 | Work item 1 valid deliverable content for testing.",
                    "nonce": 100,
                },
                {
                    "seq": 202,
                    "from": "did:key:z6MkVendor2",
                    "text": "DELIVER v1 | k2222222222 | Work item 2 valid deliverable content for testing.",
                    "nonce": 101,
                },
            ],
        }

        with patch.object(client, "read_room", return_value=mock_response):
            client.process_cycle()
            # Only 1 broadcast attestation due to 60s cooldown, but both recorded in ledger
            assert client.total_attestations == 1
            assert sm.get_ledger_count() == 2
            entries = sm.get_recent_ledger_entries(limit=2)
            assert entries[0]["verification_status"] == "VERIFIED"
            assert entries[1]["verification_status"] == "VERIFIED_RATE_LIMITED"


# ==============================================================================
# Health App & Endpoint Tests
# ==============================================================================


class TestHealthServer:
    def test_health_endpoint(self, sample_private_key: Ed25519PrivateKey, temp_dir: Path) -> None:
        sm = StateManager(cursor_path=temp_dir / "cursor.json", ledger_path=temp_dir / "ledger.jsonl")
        sm.update_cursor(324000)
        sm.append_ledger({
            "target_did": "did:key:z6MkSample",
            "sequence_id": 324000,
            "job_id": "k123",
            "job_hash": "sha256:1234",
            "verification_status": "VERIFIED",
        })

        client = KibbleClient(private_key=sample_private_key, state_manager=sm, dry_run=True)
        app = create_health_app(client, start_time=time.time() - 50.0)
        test_client = app.test_client()

        # GET /
        resp = test_client.get("/")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert data["service"] == "kibble-agent"
        assert data["current_cursor"] == 324000
        assert data["ledger_count"] == 1
        assert data["uptime_seconds"] >= 50.0

        # GET /health
        resp_health = test_client.get("/health")
        assert resp_health.status_code == 200

        # GET /ledger
        resp_ledger = test_client.get("/ledger?limit=10")
        assert resp_ledger.status_code == 200
        ledger_data = resp_ledger.get_json()
        assert ledger_data["total_entries"] == 1
        assert len(ledger_data["entries"]) == 1
        assert ledger_data["entries"][0]["sequence_id"] == 324000
