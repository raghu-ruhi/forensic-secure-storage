"""Key generation: continuous-space Equilibrium Optimizer + HKDF key derivation.

STATUS OF THE RESEARCH MAPPING  (read this first)
-------------------------------------------------
The project's paper ("Enhanced Equilibrium Optimizer" key generation,
Equations (1)-(12)) was NOT supplied, so those equations could not be
checked. What is implemented here is the *standard* Equilibrium Optimizer
(EO) of Faramarzi, Heidarinejad, Stephens & Mirjalili, "Equilibrium optimizer:
A novel optimization algorithm", Knowledge-Based Systems 191 (2020) 105190
(equations below are written from that publication - verify them against
the PDF). The paper's *enhancements* (whatever Eq. (1)-(12) add on top of
standard EO) are NOT implemented. Once the paper is provided, only
``_eo_update`` and ``EOParams`` need to change; nothing else depends on them.

TWO SEPARATE STAGES  (this separation is deliberate)
----------------------------------------------------
Stage 1 - OPTIMIZATION (``run_equilibrium_optimizer``). Searches a
    continuous space for a 32-element vector whose byte-quantisation scores
    best on a statistical-quality objective (``objective``). Uses a plain
    PRNG, seedable for reproducible tests. Its output is NOT secret and is
    never used as a key.

Stage 2 - DERIVATION (``derive_key``).
        key = HKDF-SHA256( IKM  = os.urandom(32),
                           salt = SHA-256(optimizer best bytes),
                           info = "forensic-evidence-aes256-v1" )
    The entropy of the key comes ONLY from the 256-bit CSPRNG input. The
    optimizer output merely acts as (public) salt/context. Therefore:
      * an attacker who knows or predicts the optimizer's output learns nothing
        about the key (HKDF's extract step needs the secret IKM);
      * the optimizer cannot reduce key entropy (the old implementation
        picked "the fittest of 5 random candidates", slightly reducing it).
    An optimizer does NOT make a key more secure; the security properties
    are provided by os.urandom (unpredictability) and HKDF (uniform,
    domain-separated output).

Fernet note: Fernet splits the 32 bytes into a 128-bit AES-CBC key and a
128-bit HMAC-SHA256 key (so bulk encryption is AES-128, not AES-256).

Nothing here logs keys, IKM or optimizer positions - only statistics.
"""
import base64
import hashlib
import logging
import math
import os
import random
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger("forensic.keygen")

KEY_BYTES = 32
HKDF_INFO = b"forensic-evidence-aes256-v1"
ALGORITHM_NAME = "equilibrium-optimizer(standard, Faramarzi 2020)"


class KeyGenerationError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class EOParams:
    population: int = 20          # N particles
    max_iter: int = 50            # Iter_max
    dim: int = KEY_BYTES          # decision variables = bytes of the candidate
    lower: float = 0.0            # C_min
    upper: float = 255.0          # C_max
    a1: float = 2.0               # exploration constant (generation-rate term F)
    a2: float = 1.0               # exploitation constant (time term t)
    gp: float = 0.5               # generation probability GP
    patience: int = 30            # stop after this many iterations without improvement
    min_improvement: float = 1e-9
    target_fitness: Optional[float] = None  # stop early when reached (minimisation)

    def validate(self) -> "EOParams":
        if not (isinstance(self.population, int) and 5 <= self.population <= 1000):
            raise KeyGenerationError("population must be an integer in [5, 1000]")
        if not (isinstance(self.max_iter, int) and 1 <= self.max_iter <= 10000):
            raise KeyGenerationError("max_iter must be an integer in [1, 10000]")
        if self.dim != KEY_BYTES:
            raise KeyGenerationError(f"dim must be {KEY_BYTES} (one variable per candidate byte)")
        if not (self.lower < self.upper and self.lower >= 0 and self.upper <= 255):
            raise KeyGenerationError("bounds must satisfy 0 <= lower < upper <= 255")
        if self.a1 <= 0 or self.a2 < 0:
            raise KeyGenerationError("a1 must be > 0 and a2 >= 0")
        if not 0.0 <= self.gp <= 1.0:
            raise KeyGenerationError("gp must be within [0, 1]")
        if self.patience < 1 or self.min_improvement < 0:
            raise KeyGenerationError("patience must be >= 1 and min_improvement >= 0")
        return self


# ---------------------------------------------------------------------------
# Objective function (minimised; 0 = ideal statistical profile)
# ---------------------------------------------------------------------------
def quantise(position: List[float], lower: float = 0.0, upper: float = 255.0) -> bytes:
    """Map a continuous position to a byte string: clip to bounds, round to nearest int."""
    return bytes(int(min(255, max(0, round(min(upper, max(lower, v)))))) for v in position)


def _entropy_deficit(data: bytes) -> float:
    """1 - H(data)/H_max, H = Shannon entropy of the byte histogram.
    H_max = log2(len(data)) because a sample of n bytes cannot show more than n distinct values."""
    n = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return 1.0 - h / math.log2(n)


def _bit_balance_error(data: bytes) -> float:
    """|ones/total - 0.5| * 2  : 0 when exactly half of the bits are 1."""
    ones = sum(bin(b).count("1") for b in data)
    return abs(ones / (len(data) * 8) - 0.5) * 2


def _longest_run_penalty(data: bytes) -> float:
    """Longest run of identical bits vs. the ~log2(n_bits) expected for random data.
    0 when <= expectation, rising towards 1 for very long runs."""
    bits = "".join(f"{b:08b}" for b in data)
    longest = run = 1
    for prev, cur in zip(bits, bits[1:]):
        run = run + 1 if cur == prev else 1
        longest = max(longest, run)
    expected = math.log2(len(bits))
    return min(1.0, max(0.0, (longest - expected) / (len(bits) - expected)) * 4)


def _serial_correlation(data: bytes) -> float:
    """|lag-1 serial correlation coefficient| of the byte sequence (0 = uncorrelated)."""
    n = len(data)
    mean = sum(data) / n
    var = sum((b - mean) ** 2 for b in data)
    if var == 0:
        return 1.0
    cov = sum((data[i] - mean) * (data[(i + 1) % n] - mean) for i in range(n))
    return abs(cov / var)


OBJECTIVE_WEIGHTS = (0.35, 0.25, 0.20, 0.20)


def objective(position: List[float]) -> float:
    """Weighted sum of four randomness-quality deficits of the quantised candidate.

        f(x) = 0.35*(1 - H/Hmax) + 0.25*bit_balance_error
             + 0.20*longest_run_penalty + 0.20*|serial_correlation|

    Range [0, 1]; lower is better. This is a *statistical-quality* heuristic
    chosen for this project (the paper's own objective was not supplied). It does
    not measure, and must not be read as, cryptographic strength.
    """
    data = quantise(position)
    w = OBJECTIVE_WEIGHTS
    return (w[0] * _entropy_deficit(data) + w[1] * _bit_balance_error(data)
            + w[2] * _longest_run_penalty(data) + w[3] * _serial_correlation(data))


# ---------------------------------------------------------------------------
# Equilibrium Optimizer (standard EO, Faramarzi et al. 2020)
# ---------------------------------------------------------------------------
@dataclass
class OptimizationResult:
    best_position: List[float]
    best_fitness: float
    initial_best_fitness: float
    iterations_run: int
    stopped_reason: str            # max_iter | stagnation | target_reached
    history: List[float] = field(default_factory=list)   # best fitness per iteration


def _initialise(params: EOParams, rng: random.Random) -> List[List[float]]:
    """Population initialisation:  C_i = C_min + rand_i * (C_max - C_min)."""
    span = params.upper - params.lower
    return [[params.lower + rng.random() * span for _ in range(params.dim)] for _ in range(params.population)]


def _equilibrium_pool(population, fitness) -> List[List[float]]:
    """Equilibrium pool: the four best particles C_eq1..C_eq4 plus their mean C_eq,ave."""
    order = sorted(range(len(population)), key=lambda i: fitness[i])[:4]
    best4 = [population[i][:] for i in order]
    mean = [sum(col) / len(best4) for col in zip(*best4)]
    return best4 + [mean]


def _eo_update(particle, pool, iteration, params, rng) -> List[float]:
    """One particle update.

      t   = (1 - Iter/Iter_max) ** (a2 * Iter/Iter_max)                (time term)
      F   = a1 * sign(r - 0.5) * (exp(-lambda * t) - 1)                (exploration/exploitation balance)
      GCP = 0.5 * r1 if r2 >= GP else 0                                (generation-rate control)
      G0  = GCP * (C_eq - lambda * C);   G = G0 * F                    (generation rate)
      C   = C_eq + (C - C_eq) * F + G / (lambda * V) * (1 - F),  V = 1 (concentration update)

    C_eq is drawn uniformly from the equilibrium pool for each particle; lambda and
    r are random vectors in [0,1]. Result is clipped to [C_min, C_max].
    """
    c_eq = pool[rng.randrange(len(pool))]
    frac = iteration / params.max_iter
    t = (1 - frac) ** (params.a2 * frac)
    r1, r2 = rng.random(), rng.random()
    gcp = 0.5 * r1 if r2 >= params.gp else 0.0
    new = []
    for c, ceq in zip(particle, c_eq):
        lam = max(rng.random(), 1e-12)           # avoid division by zero in G/(lambda*V)
        r = rng.random()
        f = params.a1 * (1 if r >= 0.5 else -1) * (math.exp(-lam * t) - 1)
        g = gcp * (ceq - lam * c) * f
        value = ceq + (c - ceq) * f + g / lam * (1 - f)
        new.append(min(params.upper, max(params.lower, value)))
    return new


def run_equilibrium_optimizer(params: EOParams = EOParams(), seed: Optional[int] = None,
                              fitness_fn: Callable[[List[float]], float] = objective) -> OptimizationResult:
    """Run the optimizer. ``seed`` makes the run reproducible (tests/benchmarks);
    with ``seed=None`` it is seeded from the OS CSPRNG. Either way the result is
    non-secret (see module docstring)."""
    params.validate()
    rng = random.Random(seed if seed is not None else secrets.randbits(64))  # nosec B311 - optimizer PRNG only; key material never comes from it

    population = _initialise(params, rng)
    fitness = [fitness_fn(p) for p in population]
    best_i = min(range(len(fitness)), key=fitness.__getitem__)
    best_pos, best_fit = population[best_i][:], fitness[best_i]
    initial_best, history, stagnant, reason = best_fit, [], 0, "max_iter"

    iteration = 0
    for iteration in range(1, params.max_iter + 1):
        pool = _equilibrium_pool(population, fitness)
        for i in range(params.population):
            candidate = _eo_update(population[i], pool, iteration, params, rng)
            cand_fit = fitness_fn(candidate)
            if cand_fit < fitness[i]:            # memory saving: keep a particle's better position
                population[i], fitness[i] = candidate, cand_fit

        gen_best = min(range(len(fitness)), key=fitness.__getitem__)
        if best_fit - fitness[gen_best] > params.min_improvement:
            stagnant = 0
        else:
            stagnant += 1
        if fitness[gen_best] < best_fit:
            best_pos, best_fit = population[gen_best][:], fitness[gen_best]
        history.append(best_fit)

        if params.target_fitness is not None and best_fit <= params.target_fitness:
            reason = "target_reached"
            break
        if stagnant >= params.patience:
            reason = "stagnation"
            break

    return OptimizationResult(best_pos, best_fit, initial_best, iteration, reason, history)


# ---------------------------------------------------------------------------
# Stage 2: key derivation (the only place key material is produced)
# ---------------------------------------------------------------------------
def derive_key(ikm: bytes, optimizer_output: bytes, info: bytes = HKDF_INFO) -> bytes:
    """HKDF-SHA256 -> 32 raw key bytes. Deterministic for fixed inputs (unit-testable)."""
    if len(ikm) < 32:
        raise KeyGenerationError("input keying material must be at least 32 bytes")
    salt = hashlib.sha256(optimizer_output).digest()
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=info).derive(ikm)


def to_fernet_key(raw: bytes) -> bytes:
    if len(raw) != KEY_BYTES:
        raise KeyGenerationError("key must be exactly 32 bytes")
    return base64.urlsafe_b64encode(raw)


def generate_key_with_stats(params: Optional[EOParams] = None, seed: Optional[int] = None):
    """Full workflow. Returns ``(fernet_key, stats)``.

    ``seed`` only seeds Stage 1; the IKM always comes from os.urandom, so even a
    fixed seed can never make the produced key reproducible."""
    params = params or _params_from_app_config()
    started = time.perf_counter()
    result = run_equilibrium_optimizer(params, seed=seed)
    opt_ms = (time.perf_counter() - started) * 1000

    ikm = os.urandom(32)
    key = to_fernet_key(derive_key(ikm, quantise(result.best_position)))
    total_ms = (time.perf_counter() - started) * 1000

    stats = {
        "algorithm": ALGORITHM_NAME, "paper_enhancements_implemented": False,
        "kdf": "HKDF-SHA256", "ikm_source": "os.urandom(32)",
        "population": params.population, "max_iter": params.max_iter,
        "iterations_run": result.iterations_run, "stopped_reason": result.stopped_reason,
        "initial_best_fitness": round(result.initial_best_fitness, 6),
        "best_fitness": round(result.best_fitness, 6),
        "optimization_ms": round(opt_ms, 3), "total_ms": round(total_ms, 3),
    }
    logger.info("key generated: iterations=%s fitness=%.4f total_ms=%.2f",
                stats["iterations_run"], stats["best_fitness"], total_ms)   # no key material
    return key, stats


def generate_optimal_key() -> bytes:
    """Backwards-compatible entry point: just the Fernet key."""
    return generate_key_with_stats()[0]


def _params_from_app_config() -> EOParams:
    try:
        from flask import current_app
        cfg = current_app.config
        return EOParams(population=cfg.get("EEO_POPULATION", 20), max_iter=cfg.get("EEO_MAX_ITER", 50))
    except RuntimeError:  # no app context (scripts, benchmarks)
        return EOParams()
