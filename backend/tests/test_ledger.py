"""Ledger (hash chain) behaviour, provenance events, and its documented limits."""
import json

from app.extensions import db
from app.models import LedgerBlock
from app.services.blockchain_service import GENESIS_HASH, _compute_block_hash, add_block, verify_chain
from tests.conftest import upload


def chain(eid):
    return LedgerBlock.query.filter_by(evidence_id=eid).order_by(LedgerBlock.timestamp.asc()).all()


def make_evidence(client, headers, content=b"x"):
    return upload(client, headers, "a.txt", content).get_json()["evidence"]["id"]


def test_upload_creates_genesis_linked_block_with_provenance(client, alice):
    eid = make_evidence(client, alice, b"hello")
    blocks = chain(eid)
    assert len(blocks) == 1 and blocks[0].previous_hash == GENESIS_HASH and blocks[0].event_type == "UPLOAD"
    payload = json.loads(blocks[0].payload)
    assert payload["sha256"] and payload["filename"] == "a.txt" and payload["size"] == 5
    assert blocks[0].actor_id and blocks[0].timestamp


def test_each_block_links_to_the_previous_one(client, alice):
    eid = make_evidence(client, alice)
    client.post(f"/api/evidence/{eid}/verify", headers=alice)
    client.get(f"/api/evidence/{eid}/download", headers=alice)
    blocks = chain(eid)
    assert [b.event_type for b in blocks] == ["UPLOAD", "VERIFY", "DOWNLOAD"]
    for prev, cur in zip(blocks, blocks[1:]):
        assert cur.previous_hash == prev.current_hash
    assert verify_chain(eid) == {"valid": True, "total_blocks": 3}


def test_verification_results_are_recorded_on_the_ledger(client, alice):
    eid = make_evidence(client, alice)
    client.post(f"/api/evidence/{eid}/verify", headers=alice)
    verify_block = [b for b in chain(eid) if b.event_type == "VERIFY"][0]
    assert json.loads(verify_block.payload)["hash_match"] is True


def test_edited_payload_is_detected(client, app, alice):
    eid = make_evidence(client, alice)
    block = chain(eid)[0]
    block.payload = json.dumps({"sha256": "f" * 64})
    db.session.commit()
    assert verify_chain(eid)["valid"] is False


def test_deleted_middle_block_is_detected(client, app, alice):
    eid = make_evidence(client, alice)
    client.post(f"/api/evidence/{eid}/verify", headers=alice)
    client.get(f"/api/evidence/{eid}/download", headers=alice)
    db.session.delete(chain(eid)[1])
    db.session.commit()
    result = verify_chain(eid)
    assert result["valid"] is False and result["broken_at_block"]


def test_reordered_or_relinked_block_is_detected(client, app, alice):
    eid = make_evidence(client, alice)
    client.post(f"/api/evidence/{eid}/verify", headers=alice)
    chain(eid)[1].previous_hash = GENESIS_HASH
    db.session.commit()
    assert verify_chain(eid)["valid"] is False


def test_verify_endpoint_flags_a_broken_chain_as_tampered(client, app, alice):
    eid = make_evidence(client, alice)
    chain(eid)[0].event_type = "FORGED"
    db.session.commit()
    r = client.post(f"/api/evidence/{eid}/verify", headers=alice).get_json()
    assert r["hash_match"] is True and r["ledger_chain"]["valid"] is False and r["status"] == "tampered"


def test_chains_are_independent_per_evidence_item(client, alice):
    a, b = make_evidence(client, alice), make_evidence(client, alice, b"y")
    assert chain(a)[0].previous_hash == chain(b)[0].previous_hash == GENESIS_HASH
    assert verify_chain(a)["valid"] and verify_chain(b)["valid"]


def test_empty_chain_is_valid(client, app, alice):
    assert verify_chain("no-such-evidence") == {"valid": True, "total_blocks": 0}


def test_KNOWN_LIMITATION_consistent_full_rewrite_is_not_detected(client, app, alice):
    """DOCUMENTED WEAKNESS (see docs/SECURITY_REPORT.md, finding F-04): the chain is an
    unsigned hash chain stored in the same database as the evidence metadata. Someone with
    database WRITE access who recomputes every hash produces a chain that verifies.
    The ledger therefore only provides tamper-EVIDENCE against partial/naive edits, not
    protection against a database administrator. This test pins today's behaviour."""
    eid = make_evidence(client, alice)
    block = chain(eid)[0]
    block.payload = json.dumps({"sha256": "0" * 64, "forged": True})
    block.current_hash = _compute_block_hash(block.evidence_id, block.event_type, block.previous_hash,
                                             block.actor_id or "", block.payload, block.timestamp.isoformat())
    db.session.commit()
    assert verify_chain(eid)["valid"] is True     # undetected -> requires external anchoring/signing (Phase 4)
