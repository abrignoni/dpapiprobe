"""Round-trip tests for the Chromium os_crypt chain over forged structures.

No Windows data is used. These guard the Local State key unwrap, the v10 AES-GCM value
decrypt, the legacy per-value DPAPI path, v20 detection and the cookie host-hash strip.
Fidelity to real Chrome output is validated separately (lab VM oracle + corpus).
"""
import base64
import os

from Crypto.Cipher import AES

import dpapiprobe as dp
from dpapiprobe import chromium

import forge

GUID = '11111111-2222-3333-4444-555555555555'


def _pool_with_key(tmp_path):
    pre_key = os.urandom(20)
    mk_file, master_key = forge.forge_master_key_file(pre_key, GUID)
    path = tmp_path / GUID
    path.write_bytes(mk_file)
    pool = dp.MasterKeyPool()
    pool.add_file(str(path))
    pool.decrypt_all([pre_key])
    return pool, master_key


def _local_state(encrypted_key, app_bound=False):
    oc = {'encrypted_key': base64.b64encode(encrypted_key).decode()}
    if app_bound:
        oc['app_bound_encrypted_key'] = base64.b64encode(b'APPB' + os.urandom(16)).decode()
    return {'os_crypt': oc}


def test_os_crypt_key_round_trip(tmp_path):
    pool, master_key = _pool_with_key(tmp_path)
    aes = os.urandom(32)
    encrypted_key = chromium.DPAPI_KEY_PREFIX + forge.forge_blob(master_key, aes, GUID)
    key, info = dp.os_crypt_key(_local_state(encrypted_key), pool)
    assert key == aes
    assert info['have_master_key'] is True
    assert info['app_bound'] is False


def test_v10_value_round_trip(tmp_path):
    pool, master_key = _pool_with_key(tmp_path)
    aes = os.urandom(32)
    encrypted_key = chromium.DPAPI_KEY_PREFIX + forge.forge_blob(master_key, aes, GUID)
    key, _ = dp.os_crypt_key(_local_state(encrypted_key), pool)
    secret = b'Chr0me-Saved-Pass!'
    nonce = os.urandom(12)
    cipher_text, tag = AES.new(aes, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(secret)
    value = b'v10' + nonce + cipher_text + tag
    clear, scheme = dp.decrypt_value(value, key=key)
    assert scheme == 'v10'
    assert clear == secret


def test_v20_detected_not_decrypted():
    value = b'v20' + os.urandom(12 + 8 + 16)
    clear, scheme = dp.decrypt_value(value, key=os.urandom(32))
    assert scheme == 'v20'
    assert clear is None


def test_legacy_dpapi_value(tmp_path):
    pool, master_key = _pool_with_key(tmp_path)
    value = forge.forge_blob(master_key, b'old-ie-style-pass', GUID)
    assert chromium.value_scheme(value) == 'dpapi'
    clear, scheme = dp.decrypt_value(value, mk_pool=pool)
    assert scheme == 'dpapi'
    assert clear == b'old-ie-style-pass'


def test_app_bound_flag(tmp_path):
    pool, master_key = _pool_with_key(tmp_path)
    aes = os.urandom(32)
    encrypted_key = chromium.DPAPI_KEY_PREFIX + forge.forge_blob(master_key, aes, GUID)
    _, info = dp.os_crypt_key(_local_state(encrypted_key, app_bound=True), pool)
    assert info['app_bound'] is True


def test_missing_master_key_returns_none(tmp_path):
    pool, master_key = _pool_with_key(tmp_path)
    other = '99999999-8888-7777-6666-555555555555'
    aes = os.urandom(32)
    encrypted_key = chromium.DPAPI_KEY_PREFIX + forge.forge_blob(master_key, aes, other)
    key, info = dp.os_crypt_key(_local_state(encrypted_key), pool)
    assert key is None
    assert info['have_master_key'] is False
    assert info['mk_guid'] == other


def test_cookie_host_hash_strip():
    plain = os.urandom(32) + b'session=abc123'
    assert chromium.strip_cookie_host_hash(plain, 24) == b'session=abc123'
    assert chromium.strip_cookie_host_hash(plain, 23) == plain
    assert chromium.strip_cookie_host_hash(plain, None) == plain
    assert chromium.strip_cookie_host_hash(None, 24) is None


def test_wrong_key_returns_none():
    value = b'v10' + os.urandom(12 + 8 + 16)
    assert dp.decrypt_gcm(value, os.urandom(32)) is None


def test_value_scheme_edges():
    assert chromium.value_scheme(b'') == 'empty'
    assert chromium.value_scheme(None) == 'empty'
    assert chromium.value_scheme(b'plain text, no prefix') == 'unknown'
