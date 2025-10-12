#BIP 32
import hmac, hashlib, struct
from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import Point

CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order

def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()
def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")
def bytes_from_int(i: int, length: int) -> bytes:
    return i.to_bytes(length, "big")

# Master key generation from seed
def master_key_from_seed(seed: bytes) -> (bytes, bytes):
    I = hmac_sha512(b"Bitcoin seed", seed)
    master_priv = I[:32]
    master_chain = I[32:]
    return master_priv, master_chain

#convert private key to public key
def priv_to_hub_compressed(privkey32: bytes) -> bytes:
    sk = SigningKey.from_string(privkey32, curve=SECP256k1)
    vk = sk.get_verifying_key()
    px = vk.pubkey.point.x()
    py = vk.pubkey.point.y()
    prefix = b'\x02' if (py % 2 == 0) else b'\x03'
    return prefix + bytes_from_int(px, 32)

#point addition
def point_from_pubbytes_uncompressed(pubkey: bytes) -> Point:
    if pubkey[0] != 0x04:
        raise ValueError("expected uncompressed public key")
    x = int_from_bytes(pubkey[1:33])
    y = int_from_bytes(pubkey[33:65])
    return Point(CURVE.curve, x, y)

def pubpoint_to_compressed(point: Point) -> bytes:
    prefix = b'\x02' if (point.y() % 2 == 0) else b'\x03'
    return prefix + bytes_from_int(point.x(), 32)

# serP(compressed) from verifying key
def get_pubkey_compressed_from_priv(privkey32: bytes) -> bytes:
    return priv_to_hub_compressed(privkey32)

# Child derivation
HARDENED_OFFSET = 0x80000000

def derive_child_private(parent_priv: bytes, parent_chain: bytes, index: int) -> (bytes, bytes):
    if index < 0 or index >= 2**32:
        raise ValueError("index out of range")
    if index >= HARDENED_OFFSET:
        data = b'\x00' + parent_priv + struct.pack(">L", index)
    else:
        serP = get_pubkey_compressed_from_priv(parent_priv)
        data = serP + struct.pack(">L", index)
    I = hmac_sha512(parent_chain, data)
    IL, IR = I[:32], I[32:]
    IL_int = int_from_bytes(IL)
    if IL_int >= N:
        raise ValueError("IL >= n, invalid child")
    
    kpar_int = int_from_bytes(parent_priv)
    chyld_int = (IL_int + kpar_int) % N
    if chyld_int == 0:
        raise ValueError("derived child priv key == 0")
    
    child_priv = bytes_from_int(chyld_int, 32)
    child_chain = IR
    return child_priv, child_chain

# derive along a path
def parse_path(path: str):
    if path == 'm' or path == 'M' or path == '':
        return []
    if path.startswith('m/'):
        path = path[2:]
    parts = path.split('/')
    indices = []
    for p in parts:
        if p.endswith("'") or p.endswith("h"):
            idx = int(p[:-1]) + HARDENED_OFFSET
        else:
            idx = int(p)
        indices.append(idx)
    return indices

def derive_path(master_priv: bytes, master_chain: bytes, path: str):
    priv = master_priv
    chain = master_chain
    for idx in parse_path(path):
        priv, chain = derive_child_private(priv, chain, idx)
    return priv, chain

def hexstr(b: bytes) -> str:
    return b.hex()

#main
if __name__ == "__main__":
    
    # 1) on va créer une seed aléatoire
    import os
    seed_demo = os.urandom(64)  # 64 bits
    print("Seed (hex):", seed_demo.hex())

    # 2) master key extraction
    master_priv, master_chain = master_key_from_seed(seed_demo)
    print("\nMaster Private Key (hex):", hexstr(master_priv))
    print("\nMaster Chain Code (hex):", hexstr(master_chain))

    # 3) Master public key
    master_pub_comp = get_pubkey_compressed_from_priv(master_priv)
    print("Master public key (compressed):", hexstr(master_pub_comp))

    # 4) Generate one child
    child_priv0, child_chain0 = derive_child_private(master_priv, master_chain, 0)
    print("\nChild @ index 0 (priv):", hexstr(child_priv0))
    print("Child @ index 0 (chain):", hexstr(child_chain0))
    print("Child @ index 0 (pub compressed):", hexstr(get_pubkey_compressed_from_priv(child_priv0)))

    # 5) Child at index N (ex: N = 42)
    N_index = 42
    child_privN, child_chainN = derive_child_private(master_priv, master_chain, N_index)
    print(f"\nChild @ index {N_index} (priv):", hexstr(child_privN))

    # 6) Child at index N at derivation level M 
    path = "m/0/1/2'"
    derived_priv, derived_chain = derive_path(master_priv, master_chain, path)
    print(f"\nDerived at path {path} -> priv:", hexstr(derived_priv))
    print(f"Derived at path {path} -> chain:", hexstr(derived_chain))

    