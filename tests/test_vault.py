"""Tests for the Vault credential decryption and Web Credentials parsing (synthetic)."""
import os
import struct

from Crypto.Cipher import AES

import dpapiprobe as dp
from dpapiprobe import credvault

import forge


def _lstr(text):
    raw = text.encode('utf-16-le')
    return struct.pack('<L', len(raw)) + raw


def _web_credential_cleartext(user, resource, password):
    # Version, Count, Unknown, Id1, Username, Id2, Resource, Id3, Password
    return (struct.pack('<LLLL', 1, 4, 1, 2) + _lstr(user)
            + struct.pack('<L', 1) + _lstr(resource)
            + struct.pack('<L', 3) + _lstr(password))


def _pkcs7(data, block=16):
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def _forge_vcrd_attribute(attr_id, key, iv, cleartext):
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(_pkcs7(cleartext))
    size = len(ciphertext) + 21
    body = struct.pack('<LLLL', attr_id, 0, 0, 0)       # id + three unknown dwords
    if attr_id >= 100:
        body += struct.pack('<L', 0)                     # unknown dword for high ids
    body += struct.pack('<L', size) + b'\x01' + struct.pack('<L', len(iv)) + iv + ciphertext
    return body


def test_parse_web_credential():
    cleartext = _web_credential_cleartext('alice', 'https://example.test/login', 'hunter2pass')
    cred = dp.parse_web_credential(cleartext)
    assert cred == {'user': 'alice', 'resource': 'https://example.test/login',
                    'password': 'hunter2pass'}


def test_parse_web_credential_rejects_other():
    assert dp.parse_web_credential(b'\x02\x00\x00\x00rubbish') is None
    assert dp.parse_web_credential(b'') is None


def test_vault_credential_decrypt_and_parse():
    key = os.urandom(32)
    iv = os.urandom(16)
    cleartext = _web_credential_cleartext('bob', 'https://site.test/', 'pa55word!')
    attr = _forge_vcrd_attribute(100, key, iv, cleartext)
    data = forge.forge_vcrd(credvault.WEB_CREDENTIAL_SCHEMA, 'Internet Explorer', [(100, attr)])
    vcrd = dp.VaultCredential(data)
    assert vcrd.schema_guid == credvault.WEB_CREDENTIAL_SCHEMA
    decrypted, used = vcrd.decrypt([os.urandom(32), key])   # wrong key first, then the right one
    assert used == key
    cred = dp.parse_web_credential(decrypted[100])
    assert cred['user'] == 'bob' and cred['password'] == 'pa55word!'


def test_vpol_aes_key_candidates():
    key = os.urandom(32)
    vpol = dp.VaultPolicy(forge.forge_vpol(b'\x00' * 8))   # blob content irrelevant here
    vpol.cleartexts = [os.urandom(12) + struct.pack('<L', 32) + key + os.urandom(8)]
    assert key in vpol.aes_key_candidates(32)
