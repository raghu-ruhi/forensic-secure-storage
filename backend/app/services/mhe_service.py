"""Multiparty homomorphic encryption (MPHE) with OpenFHE - BFV, integer vectors.

WHAT THIS IS - AND IS NOT  (verified against the installed library, see
``capabilities()`` and tests/test_mhe.py::test_library_capabilities_are_as_documented)
------------------------------------------------------------------------------------
* IS: real **multiparty / threshold** HE. Every key holder generates a secret-key
  share; together they produce ONE joint public key. Anything encrypted under
  it can be evaluated on homomorphically, but decrypted only when EVERY
  holder contributes a partial decryption. No single holder - and not the
  server - can decrypt alone.
* IS NOT: **multikey** HE in the López-Alt/Tromer/Vaikuntanathan sense (ciphertexts
  under several *independent* keys combined without a shared setup round).
  OpenFHE exposes no such API and SEAL (TenSEAL) is single-key only, so
  genuine multikey HE could not be implemented with a maintained library. If the
  research paper requires true multikey HE, that remains UNMET; this module is
  the closest verified construction (joint-key setup instead of independent keys).
* The paper's exact MHE scheme/parameters were not supplied; nothing here claims
  to reproduce them.

SUPPORTED COMPUTATIONS (BFV, plaintext modulus t = 65537, packed integer slots)
  add, subtract, multiply by a public integer scalar, sum of many ciphertexts.
  Slot values are integers in [-(t-1)/2, (t-1)/2]; results wrap modulo t, so
  keep aggregates inside that range (validated for inputs; the caller is
  responsible for aggregate bounds).
NOT SUPPORTED HERE: ciphertext x ciphertext multiplication (needs the multiparty
  evaluation-key ceremony), comparisons, division, floating-point (CKKS).

KEY MANAGEMENT REQUIREMENTS
  Each secret-key share MUST stay with its owner. This service never persists
  shares; ``MultipartyKeys`` is an in-process helper for tests, benchmarks and a
  future owner-side client. A server that holds all shares is a single point
  of trust and defeats the purpose of multiparty HE.

WHERE IT BELONGS IN THIS PROJECT
  Not on bulk evidence: a 3-value ciphertext is ~1 MB and operations take
  hundreds of ms, versus microseconds for Fernet. Evidence files stay under
  Fernet (envelope encryption). MHE is for small numeric aggregates
  (e.g. per-case counters/sizes contributed by several owners) that should be
  summed without any one party seeing the others' inputs.
"""
import hashlib
import logging
from dataclasses import dataclass
from importlib import metadata
from typing import Dict, List, Sequence

import openfhe as fhe

logger = logging.getLogger("forensic.mhe")

PLAINTEXT_MODULUS = 65537
MAX_SLOTS = 1024  # we pack at most this many values per ciphertext


class MheError(Exception):
    """Base class for MHE failures (messages never contain key material)."""


class MheAuthorizationError(MheError):
    """Decryption attempted without the full set of required key-holders."""


class MheKeyMismatchError(MheError):
    """Ciphertexts/keys from different key sets were combined."""


class MheInvalidCiphertext(MheError):
    pass


def capabilities() -> dict:
    """What the selected library can and cannot do (checked at import/test time)."""
    names = dir(fhe.CryptoContext)
    return {
        "library": "OpenFHE (python bindings)", "library_version": metadata.version("openfhe"),
        "scheme": "BFV", "plaintext_modulus": PLAINTEXT_MODULUS,
        "multiparty_threshold_keygen": "MultipartyKeyGen" in names,
        "multiparty_decryption": "MultipartyDecryptFusion" in names,
        # No dedicated multikey-HE API exists. (Names like MultiKeySwitchGen / MultiAddPubKeys belong to the
        # MULTIPARTY protocol, so they must not be mistaken for independent-key multikey HE.)
        "multikey_independent_keys": any(tag in n.lower() for n in list(names) + dir(fhe)
                                          for tag in ("mkhe", "lopezalt", "multikeyhe", "independentkey")),
        "operations": ["add", "subtract", "scalar_multiply", "sum"],
        "unsupported": ["ciphertext_multiply (needs multiparty eval-key ceremony, not wired)",
                        "comparison", "division", "floating point"],
    }


@dataclass
class KeyPair:
    party_id: str
    public_key: object
    secret_key: object     # stays with its owner


@dataclass
class Ciphertext:
    ct: object
    keyset_id: str         # identifies the joint public key it was encrypted under
    length: int


def _context():
    params = fhe.CCParamsBFVRNS()
    params.SetPlaintextModulus(PLAINTEXT_MODULUS)
    params.SetMultiplicativeDepth(1)
    params.SetMultipartyMode(fhe.NOISE_FLOODING_MULTIPARTY)
    cc = fhe.GenCryptoContext(params)
    for feature in (fhe.PKESchemeFeature.PKE, fhe.PKESchemeFeature.KEYSWITCH, fhe.PKESchemeFeature.LEVELEDSHE,
                    fhe.PKESchemeFeature.ADVANCEDSHE, fhe.PKESchemeFeature.MULTIPARTY):
        cc.Enable(feature)
    return cc


def _check_values(values: Sequence[int]) -> List[int]:
    half = (PLAINTEXT_MODULUS - 1) // 2
    if not values or len(values) > MAX_SLOTS:
        raise MheError(f"provide between 1 and {MAX_SLOTS} integers")
    out = []
    for v in values:
        if isinstance(v, bool) or not isinstance(v, int):
            raise MheError("values must be integers")
        if not -half <= v <= half:
            raise MheError(f"values must be within [{-half}, {half}]")
        out.append(v)
    return out


class MultipartyKeys:
    """Runs the joint-key ceremony for a fixed, ordered set of key holders."""

    def __init__(self, party_ids: Sequence[str]):
        if len(party_ids) < 2 or len(set(party_ids)) != len(party_ids):
            raise MheError("at least two distinct key holders are required")
        self.cc = _context()
        self.party_ids = list(party_ids)
        self.pairs: Dict[str, KeyPair] = {}
        previous = None
        for pid in self.party_ids:  # lead generates a key; each next party extends the joint key
            kp = self.cc.KeyGen() if previous is None else self.cc.MultipartyKeyGen(previous.public_key)
            self.pairs[pid] = KeyPair(pid, kp.publicKey, kp.secretKey)
            previous = self.pairs[pid]
        self.joint_public_key = previous.public_key
        self.keyset_id = hashlib.sha256(fhe.Serialize(self.joint_public_key, fhe.BINARY)).hexdigest()[:16]

    # ---- operations (anyone holding the joint PUBLIC key may do these) ----
    def encrypt(self, values: Sequence[int]) -> Ciphertext:
        vals = _check_values(values)
        pt = self.cc.MakePackedPlaintext(vals)
        return Ciphertext(self.cc.Encrypt(self.joint_public_key, pt), self.keyset_id, len(vals))

    def _same_keyset(self, *cts: Ciphertext):
        if any(c.keyset_id != self.keyset_id for c in cts):
            raise MheKeyMismatchError("ciphertexts belong to a different key set")

    def add(self, a: Ciphertext, b: Ciphertext) -> Ciphertext:
        self._same_keyset(a, b)
        return Ciphertext(self.cc.EvalAdd(a.ct, b.ct), self.keyset_id, max(a.length, b.length))

    def subtract(self, a: Ciphertext, b: Ciphertext) -> Ciphertext:
        self._same_keyset(a, b)
        return Ciphertext(self.cc.EvalSub(a.ct, b.ct), self.keyset_id, max(a.length, b.length))

    def multiply_scalar(self, a: Ciphertext, k: int) -> Ciphertext:
        self._same_keyset(a)
        if isinstance(k, bool) or not isinstance(k, int) or abs(k) > (PLAINTEXT_MODULUS - 1) // 2:
            raise MheError("scalar must be a small integer")
        pt = self.cc.MakePackedPlaintext([k] * a.length)
        return Ciphertext(self.cc.EvalMult(a.ct, pt), self.keyset_id, a.length)

    def sum(self, cts: Sequence[Ciphertext]) -> Ciphertext:
        if not cts:
            raise MheError("nothing to sum")
        total = cts[0]
        for c in cts[1:]:
            total = self.add(total, c)
        return total

    # ---- decryption: needs EVERY key holder ----
    def decrypt(self, ct: Ciphertext, shares: Dict[str, object]) -> List[int]:
        """``shares`` maps party_id -> that party's secret key. Refuses unless all
        required parties are present (authorization), then fuses partial decryptions."""
        self._same_keyset(ct)
        missing = [p for p in self.party_ids if p not in shares]
        if missing:
            raise MheAuthorizationError(f"decryption requires all key holders; missing: {', '.join(missing)}")
        partials = []
        for index, pid in enumerate(self.party_ids):
            if index == 0:
                partials.append(self.cc.MultipartyDecryptLead([ct.ct], shares[pid])[0])
            else:
                partials.append(self.cc.MultipartyDecryptMain([ct.ct], shares[pid])[0])
        result = self.cc.MultipartyDecryptFusion(partials)
        result.SetLength(ct.length)
        return list(result.GetPackedValue())

    def decrypt_as_owner(self, ct: Ciphertext, party_ids: Sequence[str]) -> List[int]:
        """Convenience for tests/benchmarks where one process legitimately holds the shares."""
        return self.decrypt(ct, {p: self.pairs[p].secret_key for p in party_ids})

    # ---- (de)serialisation for storage / transport ----
    def serialize(self, ct: Ciphertext) -> bytes:
        return fhe.Serialize(ct.ct, fhe.BINARY)

    def deserialize(self, blob: bytes, length: int) -> Ciphertext:
        if not isinstance(blob, (bytes, bytearray)) or not blob:
            raise MheInvalidCiphertext("ciphertext must be non-empty bytes")
        try:
            result = fhe.DeserializeCiphertextString(bytes(blob), fhe.BINARY)
        except Exception as exc:  # noqa: BLE001 - library raises RuntimeError on malformed input
            raise MheInvalidCiphertext("malformed ciphertext") from exc
        ct = result[1] if isinstance(result, tuple) else result
        if not result or ct is None:
            raise MheInvalidCiphertext("malformed ciphertext")
        return Ciphertext(ct, self.keyset_id, length)
