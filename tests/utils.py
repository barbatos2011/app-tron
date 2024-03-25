from eth_keys import KeyAPI
from eth_keys.datatypes import Signature
from eth_keys.datatypes import PublicKey
import hashlib
from typing import List


def check_hash_signature(txID, signature, public_key):
    s = Signature(signature_bytes=signature)
    keys = KeyAPI('eth_keys.backends.NativeECCBackend')
    publicKey = PublicKey(bytes.fromhex(public_key))
    return keys.ecdsa_verify(txID, s, publicKey)


def check_tx_signature(transaction, signature, public_key):
    txID = hashlib.sha256(transaction).digest()
    return check_hash_signature(txID, signature, public_key)


def bip32_path_from_string(path: str) -> List[bytes]:
    splitted_path: List[str] = path.split("/")

    if not splitted_path:
        raise Exception(f"BIP32 path format error: '{path}'")

    if "m" in splitted_path and splitted_path[0] == "m":
        splitted_path = splitted_path[1:]

    return [int(p).to_bytes(4, byteorder="big") if "'" not in p
            else (0x80000000 | int(p[:-1])).to_bytes(4, byteorder="big")
            for p in splitted_path]


def packed_bip32_path_from_string(path: str) -> bytes:
    bip32_paths = bip32_path_from_string(path)

    return b"".join([
            len(bip32_paths).to_bytes(1, byteorder="big"),
            *bip32_paths
        ])