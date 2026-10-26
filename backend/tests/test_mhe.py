"""Multiparty homomorphic encryption (OpenFHE BFV). Real library, no mocks."""
import pytest

pytest.importorskip("openfhe", reason="optional dependency: pip install -r requirements-mhe.txt")

from app.services.mhe_service import (MheAuthorizationError, MheError, MheInvalidCiphertext, MheKeyMismatchError,
                                      MultipartyKeys, PLAINTEXT_MODULUS, capabilities)

HALF = (PLAINTEXT_MODULUS - 1) // 2


@pytest.fixture(scope="module")
def keys():
    return MultipartyKeys(["alice", "bob", "carol"])      # one ceremony reused: keygen is slow


@pytest.fixture(scope="module")
def other_keys():
    return MultipartyKeys(["mallory", "eve"])


def test_library_capabilities_are_as_documented():
    cap = capabilities()
    assert cap["multiparty_threshold_keygen"] and cap["multiparty_decryption"]
    assert cap["multikey_independent_keys"] is False, "genuine multikey HE is NOT available in OpenFHE"
    assert cap["scheme"] == "BFV" and cap["library_version"]


def test_encrypt_decrypt_roundtrip(keys):
    ct = keys.encrypt([1, 2, 3, -4, 0, HALF, -HALF])
    assert keys.decrypt_as_owner(ct, ["alice", "bob", "carol"]) == [1, 2, 3, -4, 0, HALF, -HALF]


def test_ciphertext_does_not_contain_plaintext_values(keys):
    blob = keys.serialize(keys.encrypt([123456 % HALF] * 4))
    assert len(blob) > 10_000 and b"\x40\xe2\x01" not in blob[:64]


def test_homomorphic_add_subtract_scalar_and_sum(keys):
    a, b = keys.encrypt([10, 20, 30]), keys.encrypt([1, 2, 3])
    everyone = ["alice", "bob", "carol"]
    assert keys.decrypt_as_owner(keys.add(a, b), everyone) == [11, 22, 33]
    assert keys.decrypt_as_owner(keys.subtract(a, b), everyone) == [9, 18, 27]
    assert keys.decrypt_as_owner(keys.multiply_scalar(a, 3), everyone) == [30, 60, 90]
    assert keys.decrypt_as_owner(keys.multiply_scalar(a, -2), everyone) == [-20, -40, -60]
    contributions = [keys.encrypt([5, 1]), keys.encrypt([7, 2]), keys.encrypt([9, 3])]   # one per owner
    assert keys.decrypt_as_owner(keys.sum(contributions), everyone) == [21, 6]


def test_boundary_values_and_documented_wraparound(keys):
    assert keys.decrypt_as_owner(keys.encrypt([HALF, -HALF]), ["alice", "bob", "carol"]) == [HALF, -HALF]
    wrapped = keys.decrypt_as_owner(keys.add(keys.encrypt([HALF]), keys.encrypt([1])), ["alice", "bob", "carol"])
    assert wrapped == [-HALF], "sums beyond the plaintext range wrap modulo t (documented limitation)"


# ------------------------------------------------------------ authorization / ownership
def test_decryption_requires_every_key_holder(keys):
    ct = keys.encrypt([42, 7])
    for subset in (["alice"], ["alice", "bob"], ["bob", "carol"], []):
        with pytest.raises(MheAuthorizationError):
            keys.decrypt_as_owner(ct, subset)


def test_a_single_share_cryptographically_yields_no_plaintext(keys):
    """Bypass the service's guard and fuse ONE partial decryption: output must be garbage."""
    ct = keys.encrypt([42, 7, 99])
    lead = keys.cc.MultipartyDecryptLead([ct.ct], keys.pairs["alice"].secret_key)
    fused = keys.cc.MultipartyDecryptFusion([lead[0]])
    fused.SetLength(3)
    assert fused.GetPackedValue() != [42, 7, 99]


def test_a_stranger_key_in_place_of_a_holder_does_not_decrypt(keys, other_keys):
    ct = keys.encrypt([42, 7, 99])
    shares = {"alice": keys.pairs["alice"].secret_key, "bob": keys.pairs["bob"].secret_key,
              "carol": other_keys.pairs["mallory"].secret_key}      # forged third share
    assert keys.decrypt(ct, shares) != [42, 7, 99]


def test_mixing_ciphertexts_from_different_key_sets_is_refused(keys, other_keys):
    mine, theirs = keys.encrypt([1]), other_keys.encrypt([1])
    with pytest.raises(MheKeyMismatchError):
        keys.add(mine, theirs)
    with pytest.raises(MheKeyMismatchError):
        keys.decrypt_as_owner(theirs, ["alice", "bob", "carol"])


def test_key_sets_are_distinct(keys, other_keys):
    assert keys.keyset_id != other_keys.keyset_id


# ------------------------------------------------------------ invalid input / ciphertexts
def test_serialisation_roundtrip_then_decrypt(keys):
    ct = keys.encrypt([8, 9])
    restored = keys.deserialize(keys.serialize(ct), length=2)
    assert keys.decrypt_as_owner(restored, ["alice", "bob", "carol"]) == [8, 9]


@pytest.mark.parametrize("blob", [b"", b"junk", b"\x00" * 64, None, "text"])
def test_invalid_ciphertext_bytes_are_rejected(keys, blob):
    with pytest.raises(MheInvalidCiphertext):
        keys.deserialize(blob, length=1)


def test_truncated_ciphertext_is_rejected(keys):
    blob = keys.serialize(keys.encrypt([1]))
    with pytest.raises(MheInvalidCiphertext):
        keys.deserialize(blob[: len(blob) // 2], length=1)


@pytest.mark.parametrize("bad", [[], [1.5], ["1"], [True], [HALF + 1], [-HALF - 1], [None], list(range(1025))])
def test_invalid_plaintext_inputs_are_rejected(keys, bad):
    with pytest.raises(MheError):
        keys.encrypt(bad)


def test_invalid_scalar_is_rejected(keys):
    ct = keys.encrypt([1])
    for bad in (1.5, True, HALF + 1, "2"):
        with pytest.raises(MheError):
            keys.multiply_scalar(ct, bad)


def test_party_set_validation():
    for parties in ([], ["solo"], ["a", "a"]):
        with pytest.raises(MheError):
            MultipartyKeys(parties)


def test_sum_of_nothing_is_an_error(keys):
    with pytest.raises(MheError):
        keys.sum([])
