import json
import hashlib
from datetime import datetime
from app.extensions import db
from app.models import LedgerBlock

GENESIS_HASH = "0" * 64


def _compute_block_hash(evidence_id: str, event_type: str, previous_hash: str,
                         actor_id: str, payload: str, timestamp: str) -> str:
    raw = f"{evidence_id}|{event_type}|{previous_hash}|{actor_id}|{payload}|{timestamp}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get_last_block(evidence_id: str) -> LedgerBlock | None:
    return (
        LedgerBlock.query.filter_by(evidence_id=evidence_id)
        .order_by(LedgerBlock.timestamp.desc())
        .first()
    )


def add_block(evidence_id: str, event_type: str, actor_id: str = None,
              payload: dict = None) -> LedgerBlock:
    """Append a new block to an evidence item's chain, linking it to the
    previous block's hash (blockchain-style tamper evidence).
    """
    last_block = get_last_block(evidence_id)
    previous_hash = last_block.current_hash if last_block else GENESIS_HASH

    timestamp = datetime.utcnow()
    payload_str = json.dumps(payload or {})
    current_hash = _compute_block_hash(
        evidence_id, event_type, previous_hash, actor_id or "", payload_str,
        timestamp.isoformat(),
    )

    block = LedgerBlock(
        evidence_id=evidence_id,
        event_type=event_type,
        previous_hash=previous_hash,
        current_hash=current_hash,
        actor_id=actor_id,
        payload=payload_str,
        timestamp=timestamp,
    )
    db.session.add(block)
    db.session.commit()
    return block


def verify_chain(evidence_id: str) -> dict:
    """Recompute every block's hash in order and confirm the chain has not
    been tampered with. Returns a summary dict for the API response.
    """
    blocks = (
        LedgerBlock.query.filter_by(evidence_id=evidence_id)
        .order_by(LedgerBlock.timestamp.asc())
        .all()
    )
    expected_previous = GENESIS_HASH
    for block in blocks:
        recomputed = _compute_block_hash(
            block.evidence_id, block.event_type, block.previous_hash,
            block.actor_id or "", block.payload or "{}",
            block.timestamp.isoformat(),
        )
        if block.previous_hash != expected_previous or recomputed != block.current_hash:
            return {
                "valid": False,
                "broken_at_block": block.block_id,
                "total_blocks": len(blocks),
            }
        expected_previous = block.current_hash

    return {"valid": True, "total_blocks": len(blocks)}
