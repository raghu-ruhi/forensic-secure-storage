"""
Distributed Peer Storage Simulation.

Simulates the paper's BC-distributed data allocation across multiple peers
(Section III / Fig. 1) by replicating each encrypted evidence file into three
independent local folders (node_a, node_b, node_c), standing in for physically
separate storage nodes. Consistency is checked by comparing SHA-256 hashes of
the replicated ciphertext across all nodes.
"""
import os
import shutil
from flask import current_app
from app.services.hashing_service import sha256_file


def _node_paths():
    return {
        "node_a": current_app.config["NODE_A_PATH"],
        "node_b": current_app.config["NODE_B_PATH"],
        "node_c": current_app.config["NODE_C_PATH"],
    }


def replicate_to_nodes(encrypted_file_path: str, filename: str) -> list[str]:
    """Copy an encrypted evidence file into every peer node folder.
    Returns the list of node names it was successfully replicated to.
    """
    replicated = []
    for node_name, node_path in _node_paths().items():
        os.makedirs(node_path, exist_ok=True)
        dest = os.path.join(node_path, filename)
        shutil.copyfile(encrypted_file_path, dest)
        replicated.append(node_name)
    return replicated


def check_node_consistency(filename: str) -> dict:
    """Compare the ciphertext hash of the replicated file across all nodes.
    Any node whose copy hash differs (or is missing) is flagged.
    """
    hashes = {}
    for node_name, node_path in _node_paths().items():
        file_path = os.path.join(node_path, filename)
        if os.path.exists(file_path):
            hashes[node_name] = sha256_file(file_path)
        else:
            hashes[node_name] = None

    present_hashes = [h for h in hashes.values() if h is not None]
    consistent = len(set(present_hashes)) <= 1 and len(present_hashes) == len(hashes)

    return {"consistent": consistent, "node_hashes": hashes}


def read_from_any_node(filename: str) -> bytes:
    """Fetch the ciphertext from the first available node (fault tolerance
    demo: if node_a is down, fall back to node_b, then node_c)."""
    for node_name, node_path in _node_paths().items():
        file_path = os.path.join(node_path, filename)
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                return f.read()
    raise FileNotFoundError(f"{filename} not found on any peer node")


def replicate_bytes_to_nodes(data: bytes, filename: str) -> list[str]:
    """Same as replicate_to_nodes but from memory (the object now lives in the
    storage backend, not necessarily on this host's disk).

    NOTE: these "nodes" are local directories - a development simulation, NOT a
    distributed deployment. See docs/ARCHITECTURE_PHASE2.md (Phase 4 status).
    """
    replicated = []
    for node_name, node_path in _node_paths().items():
        os.makedirs(node_path, exist_ok=True)
        with open(os.path.join(node_path, filename), "wb") as f:
            f.write(data)
        replicated.append(node_name)
    return replicated
