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
        normalized, payload = TechnocoreCrypto.format_signing_payload("kibble", nonce, "ATTEST v1 | k12345 | not | Insufficient proof")
        assert payload == b"kibble|1788079500123|ATTEST v1 | k12345 | not | Insufficient proof"

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

        assert sm.get_local_cursor() == 0

        sm.update_cursor(324015, extra_metadata={"last_from": "did:key:z6Mk..."})
        assert sm.get_local_cursor() == 324015

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
            "score": "not",
            "reason": "Generic sybil boilerplate",
        }
        entry2 = {
            "target_did": "did:key:z6MkTest2",
            "sequence_id": 101,
            "job_id": "k67890",
            "score": "yes",
            "reason": "Verifiable calculations present",
        }

        sm.append_ledger(entry1)
        sm.append_ledger(entry2)

        assert sm.get_ledger_count() == 2
        recent = sm.get_recent_ledger_entries(limit=10)
        assert len(recent) == 2
        assert recent[0]["sequence_id"] == 100
        assert recent[0]["score"] == "not"
        assert recent[1]["sequence_id"] == 101
        assert recent[1]["score"] == "yes"


# ==============================================================================
# WorkVerifier & Grammar Tests
# ==============================================================================


class TestWorkVerifier:
    def test_job_indexing(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        job_msg = {
            "seq": 500,
            "from": "did:key:z6MkJobPoster",
            "text": "JOB v1 | k35cef203ab | chemistry | Explain Krebs cycle entry | Done when: lists oxaloacetate + acetyl-CoA",
        }
        assert verifier.index_job(job_msg) is True
        assert "k35cef203ab" in verifier.job_cache
        assert verifier.job_cache["k35cef203ab"]["category"] == "chemistry"

    def test_ignore_self_messages(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        msg = {
            "seq": 10,
            "from": sample_did,
            "text": "DELIVER v1 | k12345 | Some response here",
        }
        assert verifier.evaluate_deliverable(msg) is None

    def test_ignore_chat_and_claims(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        assert verifier.evaluate_deliverable({"seq": 11, "from": "did:key:z6MkOther", "text": "gm kibble room"}) is None
        assert verifier.evaluate_deliverable({"seq": 12, "from": "did:key:z6MkOther", "text": "CLAIM v1 | k12345 | worker"}) is None
        assert verifier.evaluate_deliverable({"seq": 13, "from": "did:key:z6MkOther", "text": "ATTEST v1 | k12345 | not | reason"}) is None

    def test_reject_vps_and_sybil_templates(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        
        # Test VPS agent template
        msg1 = {
            "seq": 101,
            "from": "did:key:z6MkVendor1",
            "text": "DELIVER v1 | k1a051da517 | Auto-delivered by VPS agent. Job received and processed with full accuracy.",
        }
        res1 = verifier.evaluate_deliverable(msg1)
        assert res1 is not None
        assert res1["score"] == "not"
        assert "sybil bot template" in res1["reason"]

        # Test FLOP ecosystem analysis template
        msg2 = {
            "seq": 102,
            "from": "did:key:z6MkVendor2",
            "text": "DELIVER v1 | k8d5dff166f | Conducted analysis of the FLOP/Technocore ecosystem. Key findings: 1) DID-based identity. 2) Active agents benefit most.",
        }
        res2 = verifier.evaluate_deliverable(msg2)
        assert res2 is not None
        assert res2["score"] == "not"
        assert "sybil bot template" in res2["reason"]

        # Test "Completed work on ... successfully" template
        msg3 = {
            "seq": 103,
            "from": "did:key:z6MkVendor3",
            "text": "DELIVER v1 | k8894c7c187 | Completed work on 'Map the cave passages of Mammoth Cave' successfully.",
        }
        res3 = verifier.evaluate_deliverable(msg3)
        assert res3 is not None
        assert res3["score"] == "not"
        assert "sybil bot template" in res3["reason"]

    def test_reject_restatement_and_truncated(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        verifier.index_job({
            "seq": 200,
            "from": "did:key:z6MkJobPoster",
            "text": "JOB v1 | k99999 | math | Calculate eigenvalues of symmetric matrix | Done when: lists eigenvalues",
        })

        # Restatement
        msg = {
            "seq": 201,
            "from": "did:key:z6MkWorker",
            "text": "DELIVER v1 | k99999 | Calculate eigenvalues of symmetric matrix. Done when: lists eigenvalues.",
        }
        res = verifier.evaluate_deliverable(msg)
        assert res is not None
        assert res["score"] == "not"

        # Truncated
        msg_trunc = {
            "seq": 202,
            "from": "did:key:z6MkWorker",
            "text": "DELIVER v1 | k99999 | The matrix eigenvalues are computed using standard QR decomposition where lambda_1 = 4.5, lambda_2 = 1.2 and the vector v is given with...",
        }
        res_trunc = verifier.evaluate_deliverable(msg_trunc)
        assert res_trunc is not None
        assert res_trunc["score"] == "not"
        assert "cuts off" in res_trunc["reason"]

    def test_accept_concrete_domain_deliverable(self, sample_did: str) -> None:
        verifier = WorkVerifier(my_did=sample_did)
        verifier.index_job({
            "seq": 300,
            "from": "did:key:z6MkPoster",
            "text": "JOB v1 | k77777 | math | Fast Fourier Transform 8-point DFT | Done when: computes W_8 twiddle factors",
        })

        deliverable = (
            "The 8-point DFT computes X[k] = sum_{n=0}^7 x[n]*W_8^{kn} where twiddle factors are W_8^0 = 1.0, "
            "W_8^1 = 0.7071 - 0.7071j, W_8^2 = -1.0j, W_8^3 = -0.7071 - 0.7071j. The bit-reversal permutation "
            "orders indices [0, 4, 2, 6, 1, 5, 3, 7] across 3 butterfly stages with O(N log N) = 24 complex additions."
        )
        msg = {
            "seq": 301,
            "from": "did:key:z6MkRealWorker",
            "text": f"DELIVER v1 | k77777 | {deliverable}",
        }
        res = verifier.evaluate_deliverable(msg)
        assert res is not None
        assert res["score"] == "yes"
        assert "concrete technical parameters" in res["reason"]

    def test_native_board_grammar_format(self) -> None:
        job_id = "k35cef203ab"
        score = "not"
        reason = "The result restates the task parameters without providing any substantive execution steps."
        formatted = WorkVerifier.format_attestation_text(job_id, score, reason)
        assert formatted == f"ATTEST v1 | {job_id} | not | {reason}"

        # Yes format
        formatted_yes = WorkVerifier.format_attestation_text("k12345", "yes", "Verified calculations and data.")
        assert formatted_yes == "ATTEST v1 | k12345 | yes | Verified calculations and data."


# ==============================================================================
# InferenceConsumer Tests
# ==============================================================================


class TestInferenceConsumer:
    def test_is_configured_truthfulness(self) -> None:
        consumer_empty = InferenceConsumer(faucet_token=None)
        assert consumer_empty.is_configured is False

        consumer_configured = InferenceConsumer(faucet_token="faucet_token_q4_testnet_123")
        assert consumer_configured.is_configured is True

    def test_execute_with_token(self) -> None:
        consumer = InferenceConsumer(faucet_token="faucet_token_123")
        res = consumer.execute_faucet_inference(None, "Compute tensor factorization")
        assert res["status"] == "SUCCESS"
        assert "execution_id" in res
        assert consumer.total_inferences == 1


# ==============================================================================
# KibbleClient & First Boot Tests
# ==============================================================================


class TestKibbleClient:
    def test_first_boot_tip_jump(self, sample_private_key: Ed25519PrivateKey, temp_dir: Path) -> None:
        sm = StateManager(cursor_path=temp_dir / "cursor.json", ledger_path=temp_dir / "ledger.jsonl")
        client = KibbleClient(private_key=sample_private_key, state_manager=sm, dry_run=True)

        # Mock room response for first boot tip detection
        mock_tip_response = {
            "room": "kibble",
            "count": 1,
            "last_seq": 329000,
            "messages": [{"seq": 329000, "from": "did:key:z6MkOther", "text": "DELIVER v1 | k111 | Junk"}],
        }

        with patch.object(client, "read_room", return_value=mock_tip_response):
            tip = client.initialize_tip_cursor()
            assert tip == 329000
            assert sm.get_local_cursor() == 329000
            # Zero attestations should be published during tip jump
            assert client.total_attestations == 0

    def test_process_cycle_native_attestation(self, sample_private_key: Ed25519PrivateKey, temp_dir: Path) -> None:
        sm = StateManager(cursor_path=temp_dir / "cursor.json", ledger_path=temp_dir / "ledger.jsonl")
        sm.update_cursor(100)  # Start at 100
        client = KibbleClient(private_key=sample_private_key, state_manager=sm, dry_run=True)

        mock_response = {
            "room": "kibble",
            "count": 2,
            "last_seq": 102,
            "messages": [
                {
                    "seq": 101,
                    "from": "did:key:z6MkJobPoster",
                    "text": "JOB v1 | k55555 | math | Solve differential equation",
                },
                {
                    "seq": 102,
                    "from": "did:key:z6MkVendor",
                    "text": "DELIVER v1 | k55555 | Auto-delivered by VPS agent. Job received and processed.",
                },
            ],
        }

        with patch.object(client, "read_room", return_value=mock_response):
            count = client.process_cycle(wait=0)
            assert count == 2
            assert client.total_attestations == 1
            assert client.attest_not_count == 1
            assert sm.get_local_cursor() == 102

            # Check ledger record
            entries = sm.get_recent_ledger_entries(limit=1)
            assert entries[0]["job_id"] == "k55555"
            assert entries[0]["score"] == "not"
            assert entries[0]["attestation_text"].startswith("ATTEST v1 | k55555 | not |")

    def test_rate_limit_broadcast(self, sample_private_key: Ed25519PrivateKey, temp_dir: Path) -> None:
        sm = StateManager(cursor_path=temp_dir / "cursor.json", ledger_path=temp_dir / "ledger.jsonl")
        sm.update_cursor(200)
        client = KibbleClient(private_key=sample_private_key, state_manager=sm, dry_run=True)

        mock_response = {
            "room": "kibble",
            "count": 2,
            "last_seq": 202,
            "messages": [
                {
                    "seq": 201,
                    "from": "did:key:z6MkVendor1",
                    "text": "DELIVER v1 | k11111 | Auto-delivered by VPS agent. Job received and processed.",
                },
                {
                    "seq": 202,
                    "from": "did:key:z6MkVendor2",
                    "text": "DELIVER v1 | k22222 | Completed work on 'Mammoth Cave' successfully.",
                },
            ],
        }

        with patch.object(client, "read_room", return_value=mock_response):
            client.process_cycle(wait=0)
            # Only 1 broadcast attestation due to 60s cooldown, but both logged to ledger
            assert client.total_attestations == 1
            assert sm.get_ledger_count() == 2
            entries = sm.get_recent_ledger_entries(limit=2)
            assert entries[0]["broadcast"] is True
            assert entries[1]["broadcast"] is False


# ==============================================================================
# Health App & Endpoint Tests
# ==============================================================================


class TestHealthServer:
    def test_health_endpoint_schema(self, sample_private_key: Ed25519PrivateKey, temp_dir: Path) -> None:
        sm = StateManager(cursor_path=temp_dir / "cursor.json", ledger_path=temp_dir / "ledger.jsonl")
        sm.update_cursor(324000)

        client = KibbleClient(private_key=sample_private_key, state_manager=sm, dry_run=True)
        client.attest_not_count = 3
        client.total_attestations = 3

        app = create_health_app(client, start_time=time.time() - 60.0)
        test_client = app.test_client()

        resp = test_client.get("/")
        assert resp.status_code == 200
        data = resp.get_json()

        assert data["status"] == "healthy"
        assert data["service"] == "kibble-sentinel"
        assert data["total_attestations"] == 3
        assert data["attestation_breakdown"]["not"] == 3
        assert data["attestation_breakdown"]["yes"] == 0
        assert data["testnet_consumer_ready"] is False  # Honest health reporting
        assert data["uptime_seconds"] >= 60.0
