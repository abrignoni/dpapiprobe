"""Mint synthetic DPAPI structures for tests.

Everything here is fabricated in-process from random keys and plaintext; no Windows
data, no evidence and no recovered secrets are involved. The encrypt side is written
with standard hashlib/hmac/PyCryptodome calls (not by calling the library's own
derivations), so a round-trip exercises the library's offsets and key schedule against
an independently coded encryptor.

Fidelity to real Windows output is asserted separately, against the lab VM and the
corpus, not here; these vectors are the reproducible regression guard that ships.
"""
import hashlib
import hmac
import os
import struct

from Crypto.Cipher import AES

# Algorithm ids used by the forged vectors (the modern SHA-512 / AES-256 combination,
# plus a SHA-1 / AES-256 case that forces the CryptDeriveKey expansion path).
SHA1, SHA512 = 0x8004, 0x800E
AES256 = 0x6610
_HN = {SHA1: 'sha1', SHA512: 'sha512'}
_HLEN = {SHA1: 20, SHA512: 64}
PROVIDER_GUID_LE = bytes.fromhex('d08c9ddf0115d1118c7a00c04fc297eb')


def _kdf(pre_key, salt, dklen, iterations, alg_hash):
    hn = _HN[alg_hash]
    out = b''
    block = 1
    while len(out) < dklen:
        t = hmac.new(pre_key, salt + struct.pack('!L', block), hn).digest()
        u = t
        for _ in range(iterations - 1):
            u = hmac.new(pre_key, t, hn).digest()
            t = bytes(a ^ b for a, b in zip(t, u))
        out += t
        block += 1
    return out[:dklen]


def _derive_key(digest, alg_hash, need):
    hn = _HN[alg_hash]
    block = 64 if alg_hash != SHA512 else 128
    if len(digest) >= need:
        return digest[:need]
    padded = digest.ljust(block, b'\x00')
    ipad = bytes(b ^ 0x36 for b in padded)
    opad = bytes(b ^ 0x5c for b in padded)
    return (hashlib.new(hn, ipad).digest() + hashlib.new(hn, opad).digest())[:need]


def _pad(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def forge_master_key_file(pre_key, guid, master_key=None, rounds=8000,
                          alg_hash=SHA512):
    """A master-key file whose 64-byte key is ``master_key``, protected by ``pre_key``."""
    master_key = master_key or os.urandom(64)
    salt = os.urandom(16)
    hn, hlen = _HN[alg_hash], _HLEN[alg_hash]
    hmac_salt = os.urandom(16)
    tmp = hmac.new(pre_key, hmac_salt, hn).digest()
    stored = hmac.new(tmp, master_key, hn).digest()
    # Layout: hmac_salt(16) || stored(hlen) || [filler] || master_key(64), block-aligned,
    # with the key as the final 64 bytes (never PKCS7-padded: the decrypt reads [-64:]).
    body = hmac_salt + stored
    filler = (-(len(body) + 64)) % 16
    clear = body + b'\x00' * filler + master_key
    derived = _kdf(pre_key, salt, 32 + 16, rounds, alg_hash)
    ciphertext = AES.new(derived[:32], AES.MODE_CBC, derived[32:48]).encrypt(clear)
    mk = struct.pack('<L', 2) + salt + struct.pack('<LLL', rounds, alg_hash, AES256) + ciphertext
    header = (struct.pack('<L', 2) + b'\x00' * 8
              + guid.encode('utf-16-le') + b'\x00' * 8 + b'\x00' * 4
              + struct.pack('<QQQQ', len(mk), 0, 0, 0))
    return header + mk, master_key


def forge_blob(master_key, plaintext, mk_guid, entropy=None,
               alg_hash=SHA512, description='forged'):
    """A DPAPI blob over ``plaintext`` that ``master_key`` opens (Win7 session key)."""
    hn = _HN[alg_hash]
    salt = os.urandom(32)
    mk_hash = hashlib.sha1(master_key).digest() if len(master_key) > 20 else master_key
    session = hmac.new(mk_hash, salt + (entropy or b''), hn).digest()
    derived = _derive_key(session, alg_hash, 32 + 16)
    ciphertext = AES.new(derived[:32], AES.MODE_CBC, b'\x00' * 16).encrypt(_pad(plaintext))

    desc = description.encode('utf-16-le') + b'\x00\x00'
    guid = _guid_le(mk_guid)
    hmac_nonce = os.urandom(16)
    body = (struct.pack('<L', 1) + guid + struct.pack('<L', 0)      # mk version, guid, flags
            + struct.pack('<L', len(desc)) + desc
            + struct.pack('<LL', AES256, 256)
            + struct.pack('<L', len(salt)) + salt
            + struct.pack('<L', 0)                                   # strong password region
            + struct.pack('<LL', alg_hash, _HLEN[alg_hash] * 8)
            + struct.pack('<L', len(hmac_nonce)) + hmac_nonce
            + struct.pack('<L', len(ciphertext)) + ciphertext)
    signed = body                                                    # from mk version onward
    sign = hmac.new(mk_hash, hmac_nonce + (entropy or b'') + signed, hn).digest()
    blob = (struct.pack('<L', 1) + PROVIDER_GUID_LE + body
            + struct.pack('<L', len(sign)) + sign)
    return blob


def _guid_le(guid):
    parts = guid.split('-')
    return (struct.pack('<LHH', int(parts[0], 16), int(parts[1], 16), int(parts[2], 16))
            + bytes.fromhex(parts[3]) + bytes.fromhex(parts[4]))


def forge_credential_file(blob):
    """A minimal Credential Manager file wrapping ``blob``."""
    return struct.pack('<LL', 1, len(blob)) + blob


def forge_vpol(blob):
    """A minimal Policy.vpol wrapping one key ``blob``."""
    return (bytes.fromhex('00' * 16)            # vault GUID placeholder
            + struct.pack('<L', 0)
            + struct.pack('<L', len(blob)) + blob)


def forge_vault_key_cleartext(aes_key):
    """A decrypted vpol key cleartext whose tail is ``aes_key`` (len-prefixed)."""
    return os.urandom(24) + struct.pack('<L', len(aes_key)) + aes_key


def forge_vcrd(schema_guid, friendly_name, attributes):
    """A ``*.vcrd`` with the given attributes ``[(id, raw_bytes), ...]`` (structure only)."""
    name = friendly_name.encode('utf-16-le') + b'\x00\x00'
    head = (_guid_le(schema_guid) + struct.pack('<L', 4) + struct.pack('<Q', 0)
            + struct.pack('<LL', 0xffffffff, 0) + struct.pack('<L', len(name)) + name)
    maps_off = len(head) + 4 + 12 * len(attributes)
    maps = b''
    offset = maps_off
    bodies = b''
    for attr_id, raw in attributes:
        maps += struct.pack('<LLL', attr_id, offset, 0x101)
        bodies += raw
        offset += len(raw)
    return head + struct.pack('<L', 12 * len(attributes)) + maps + bodies
