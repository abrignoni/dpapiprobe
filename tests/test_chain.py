"""Round-trip tests over synthetic (forged) DPAPI structures.

No Windows data is used here. These guard the library's parsing offsets and key
schedule against an independently coded encryptor. Fidelity to real Windows output is
validated separately (lab VM + corpus); see the README.
"""
import os
import struct

import pytest

import dpapiprobe as dp
from dpapiprobe import credvault

import forge

GUID = '11111111-2222-3333-4444-555555555555'


def _master_key(alg_hash=forge.SHA512):
    pre_key = os.urandom(20)
    mk_file, master_key = forge.forge_master_key_file(pre_key, GUID, alg_hash=alg_hash)
    recovered = dp.decrypt_master_key(mk_file, [pre_key])
    assert recovered == master_key
    return master_key


def test_master_key_guid():
    pre_key = os.urandom(20)
    mk_file, _ = forge.forge_master_key_file(pre_key, GUID)
    assert dp.master_key_guid(mk_file) == GUID


def test_master_key_wrong_prekey_returns_none():
    pre_key = os.urandom(20)
    mk_file, _ = forge.forge_master_key_file(pre_key, GUID)
    assert dp.decrypt_master_key(mk_file, [os.urandom(20)]) is None


def test_blob_round_trip():
    master_key = _master_key()
    plaintext = b'a saved Wi-Fi passphrase: hunter2-correct-horse'
    blob = forge.forge_blob(master_key, plaintext, GUID)
    assert dp.decrypt_blob(blob, master_key) == plaintext


def test_blob_with_entropy():
    master_key = _master_key()
    entropy = os.urandom(16)
    plaintext = b'protected with optional entropy'
    blob = forge.forge_blob(master_key, plaintext, GUID, entropy=entropy)
    assert dp.decrypt_blob(blob, master_key, entropy=entropy) == plaintext
    # the wrong (or missing) entropy must not verify
    assert dp.decrypt_blob(blob, master_key) is None
    assert dp.decrypt_blob(blob, master_key, entropy=os.urandom(16)) is None


def test_blob_cryptderivekey_expansion_path():
    # SHA-1 session key (20 bytes) is shorter than a 48-byte AES-256 key+IV, so the
    # CryptDeriveKey ipad/opad expansion must run.
    master_key = _master_key(alg_hash=forge.SHA1)
    plaintext = b'needs the ipad/opad expansion'
    blob = forge.forge_blob(master_key, plaintext, GUID, alg_hash=forge.SHA1)
    assert dp.decrypt_blob(blob, master_key) == plaintext


def test_blob_parses_guid_and_description():
    master_key = _master_key()
    blob = dp.DpapiBlob(forge.forge_blob(master_key, b'x', GUID, description='Local State'))
    assert blob.mk_guid == GUID
    assert blob.description == 'Local State'


def test_find_blob_offset():
    master_key = _master_key()
    blob = forge.forge_blob(master_key, b'x', GUID)
    wrapped = b'\xDE\xAD\xBE\xEF' * 4 + blob
    assert dp.find_blob_offset(wrapped) == 16
    assert dp.find_blob_offset(b'no provider guid here') is None


def test_credential_file():
    master_key = _master_key()
    inner = b'\x00' * 36 + b'\x05\x00\x00\x00' + 'cred'.encode('utf-16-le')
    blob = forge.forge_blob(master_key, inner, GUID)
    cred = dp.CredentialFile(forge.forge_credential_file(blob))
    assert cred.decrypt(master_key) == inner


def test_vault_policy_extracts_aes_key():
    master_key = _master_key()
    aes_key = os.urandom(32)
    cleartext = forge.forge_vault_key_cleartext(aes_key)
    blob = forge.forge_blob(master_key, cleartext, GUID)
    vpol = dp.VaultPolicy(forge.forge_vpol(blob))
    vpol.decrypt(master_key)
    assert vpol.cleartexts == [cleartext]
    assert aes_key in vpol.aes_keys


def test_vault_credential_structure():
    attrs = [(1, os.urandom(40)), (2, os.urandom(20)), (100, os.urandom(120))]
    data = forge.forge_vcrd('3ccd5499-87a8-4b10-a215-608888dd3b55', 'Internet Explorer', attrs)
    vcrd = credvault.VaultCredential(data)
    assert vcrd.schema_guid == '3ccd5499-87a8-4b10-a215-608888dd3b55'
    assert vcrd.friendly_name == 'Internet Explorer'
    assert [(a['id'], len(a['raw'])) for a in vcrd.attributes] == [(1, 40), (2, 20), (100, 120)]


@pytest.mark.parametrize('bad', [b'', b'short', b'\x01' * 10])
def test_blob_bad_input_raises(bad):
    with pytest.raises((IndexError, ValueError, struct.error)):
        dp.DpapiBlob(bad).decrypt(b'\x00' * 64)
