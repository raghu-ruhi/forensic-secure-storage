"""Equilibrium Optimizer + HKDF key derivation."""
import base64
import hashlib
import hmac
import json
import statistics

import pytest
from cryptography.fernet import Fernet

from app.models import KeyRecord
from app.services import key_generation_service as kg
from app.services.key_generation_service import (EOParams, KeyGenerationError, derive_key, generate_key_with_stats,
                                                 objective, quantise, run_equilibrium_optimizer, to_fernet_key)
from tests.conftest import upload


# ------------------------------------------------------------------ objective
def test_objective_range_and_ordering():
    degenerate = [0.0] * 32
    patterned = [float(i % 2) * 255 for i in range(32)]
    balanced_random = [float(b) for b in hashlib.sha256(b"seed").digest()]
    for pos in (degenerate, patterned, balanced_random):
        assert 0.0 <= objective(pos) <= 1.0
    assert objective(degenerate) > objective(patterned) > objective(balanced_random) - 0.5
    assert objective(degenerate) > objective(balanced_random)


def test_quantise_clips_and_rounds():
    assert quantise([-5, 0.4, 0.6, 254.5, 300] + [0] * 27)[:5] == bytes([0, 0, 1, 254, 255])
    assert len(quantise([1.0] * 32)) == 32


# ------------------------------------------------------------------ optimizer
def test_converges_better_than_random_initial_population():
    """Relative convergence: the optimizer must cut the best fitness found in the random
    initial population substantially, and never make it worse. (Absolute gains are small
    because random bytes already score well on this statistical objective - see docs.)"""
    ratios = []
    for seed in range(15):
        r = run_equilibrium_optimizer(EOParams(population=20, max_iter=60, patience=60), seed=seed)
        assert r.best_fitness <= r.initial_best_fitness
        assert all(a >= b for a, b in zip(r.history, r.history[1:])), "best fitness must never get worse"
        ratios.append(r.best_fitness / r.initial_best_fitness)
    assert statistics.mean(ratios) < 0.5
    assert sum(x < 0.8 for x in ratios) >= 13


def test_positions_stay_inside_the_search_bounds():
    p = EOParams(population=10, max_iter=30, lower=10.0, upper=200.0)
    r = run_equilibrium_optimizer(p, seed=7)
    assert len(r.best_position) == 32 and all(10.0 <= v <= 200.0 for v in r.best_position)


def test_same_seed_is_reproducible_different_seed_is_not():
    a = run_equilibrium_optimizer(EOParams(), seed=123)
    b = run_equilibrium_optimizer(EOParams(), seed=123)
    c = run_equilibrium_optimizer(EOParams(), seed=124)
    assert a.best_position == b.best_position and a.history == b.history
    assert a.best_position != c.best_position


def test_unseeded_runs_differ():
    assert run_equilibrium_optimizer(EOParams(max_iter=5)).best_position != \
        run_equilibrium_optimizer(EOParams(max_iter=5)).best_position


@pytest.mark.parametrize("bad", [dict(population=2), dict(population=5.5), dict(max_iter=0), dict(dim=16),
                                 dict(lower=100, upper=50), dict(lower=-1), dict(upper=300), dict(a1=0),
                                 dict(gp=1.5), dict(patience=0)])
def test_invalid_parameters_are_rejected(bad):
    with pytest.raises(KeyGenerationError):
        run_equilibrium_optimizer(EOParams(**bad), seed=1)


def test_stopping_conditions():
    r = run_equilibrium_optimizer(EOParams(max_iter=3, patience=100), seed=1)
    assert r.stopped_reason == "max_iter" and r.iterations_run == 3
    r = run_equilibrium_optimizer(EOParams(max_iter=500, patience=3), seed=1)
    assert r.stopped_reason == "stagnation" and r.iterations_run < 500
    r = run_equilibrium_optimizer(EOParams(max_iter=500, target_fitness=1.0), seed=1)
    assert r.stopped_reason == "target_reached" and r.iterations_run == 1


def test_custom_fitness_function_is_minimised():
    sphere = lambda x: sum((v - 100) ** 2 for v in x) / (32 * 255 ** 2)   # known optimum at 100
    r = run_equilibrium_optimizer(EOParams(population=20, max_iter=200, patience=200), seed=3, fitness_fn=sphere)
    assert r.best_fitness < 0.2 * r.initial_best_fitness


# ------------------------------------------------------------------ derivation
def rfc5869_hkdf(ikm, salt, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t = b"", b""
    for i in range(1, -(-length // 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def test_derive_key_matches_independent_hkdf_implementation():
    ikm, opt = bytes(range(32)), bytes(range(32, 64))
    expected = rfc5869_hkdf(ikm, hashlib.sha256(opt).digest(), kg.HKDF_INFO, 32)
    assert derive_key(ikm, opt) == expected
    assert derive_key(ikm, opt) == derive_key(ikm, opt)                   # deterministic given inputs


def test_derivation_depends_on_secret_ikm_not_on_optimizer():
    opt = b"\x01" * 32
    assert derive_key(b"A" * 32, opt) != derive_key(b"B" * 32, opt)       # secret IKM drives the key
    assert derive_key(b"A" * 32, opt) != derive_key(b"A" * 32, b"\x02" * 32)  # optimizer output only salts
    assert derive_key(b"A" * 32, opt) != derive_key(b"A" * 32, opt, info=b"other-context")  # domain separation


def test_short_ikm_is_refused():
    with pytest.raises(KeyGenerationError):
        derive_key(b"short", b"x" * 32)


def test_to_fernet_key_validates_length():
    assert Fernet(to_fernet_key(b"\x00" * 32))
    with pytest.raises(KeyGenerationError):
        to_fernet_key(b"\x00" * 31)


# ------------------------------------------------------------------ full workflow
def test_generated_key_is_a_valid_fernet_key_that_round_trips():
    key, stats = generate_key_with_stats(EOParams(max_iter=10), seed=5)
    assert len(base64.urlsafe_b64decode(key)) == 32
    assert Fernet(key).decrypt(Fernet(key).encrypt(b"evidence")) == b"evidence"


def test_fixed_optimizer_seed_never_makes_keys_reproducible():
    """Security-critical: a fixed seed controls Stage 1 only. Keys still differ every call."""
    keys = {generate_key_with_stats(EOParams(max_iter=5), seed=42)[0] for _ in range(25)}
    assert len(keys) == 25


def test_key_bytes_are_well_distributed():
    raw = b"".join(base64.urlsafe_b64decode(generate_key_with_stats(EOParams(max_iter=3))[0]) for _ in range(300))
    ones = sum(bin(b).count("1") for b in raw) / (len(raw) * 8)
    assert 0.49 < ones < 0.51          # sanity only - not a proof of security


def test_stats_are_recorded_and_contain_no_secret_material():
    key, stats = generate_key_with_stats(EOParams(max_iter=8), seed=9)
    assert stats["total_ms"] >= stats["optimization_ms"] >= 0 and stats["iterations_run"] <= 8
    assert stats["paper_enhancements_implemented"] is False and stats["kdf"] == "HKDF-SHA256"
    blob = json.dumps(stats)
    assert key.decode() not in blob and base64.urlsafe_b64decode(key).hex() not in blob


def test_keygen_stats_are_stored_with_the_key_record_without_the_key(client, app, alice):
    r = upload(client, alice, "a.txt").get_json()["evidence"]
    rec = KeyRecord.query.filter_by(evidence_id=r["id"]).one()
    meta = json.loads(rec.keygen_meta)
    assert meta["kdf"] == "HKDF-SHA256" and meta["total_ms"] > 0
    assert rec.wrapped_key not in rec.keygen_meta
    # rotation records fresh stats on the new record
    client.post(f"/api/evidence/{r['id']}/rotate-key", headers=alice)
    assert KeyRecord.query.filter_by(evidence_id=r["id"], is_active=True).one().keygen_meta


def test_keygen_does_not_log_key_material(caplog):
    import logging
    with caplog.at_level(logging.DEBUG):
        key, _ = generate_key_with_stats(EOParams(max_iter=4), seed=1)
    raw = base64.urlsafe_b64decode(key)
    assert key.decode() not in caplog.text and raw.hex() not in caplog.text
    assert "key generated" in caplog.text
