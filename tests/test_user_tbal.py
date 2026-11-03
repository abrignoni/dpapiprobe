"""Tests for the user-master-key candidates and TBAL parsing (synthetic data only)."""
import hashlib
import hmac
import os
import struct

import dpapiprobe as dp

import forge

SID = 'S-1-5-21-111111111-222222222-333333333-1001'
GUID = '22222222-3333-4444-5555-666666666666'


def _user_prekey(sid, password):
    pwd_sha1 = hashlib.sha1(password.encode('utf-16-le')).digest()
    return hmac.new(pwd_sha1, sid.encode('utf-16-le') + b'\x00\x00', 'sha1').digest()


def test_user_master_key_candidate_from_password_opens_key():
    password = 'Correct-Horse-7'
    prekey = _user_prekey(SID, password)
    mk_file, master_key = forge.forge_master_key_file(prekey, GUID)
    cands = dp.user_master_key_candidates(SID, password=password)
    assert dp.decrypt_master_key(mk_file, cands) == master_key


def test_user_master_key_candidate_from_sha1_hash():
    password = 'another-secret'
    prekey = _user_prekey(SID, password)
    mk_file, master_key = forge.forge_master_key_file(prekey, GUID)
    sha1_hash = hashlib.sha1(password.encode('utf-16-le')).digest()
    cands = dp.user_master_key_candidates(SID, sha1_hash=sha1_hash)
    assert dp.decrypt_master_key(mk_file, cands) == master_key


def test_user_master_key_wrong_password_no_candidate_opens():
    mk_file, _ = forge.forge_master_key_file(_user_prekey(SID, 'right'), GUID)
    assert dp.decrypt_master_key(mk_file, dp.user_master_key_candidates(SID, password='wrong')) is None


def _forge_tbal(nt_hash, sha1_hash, username, lm_hash=b'\x00' * 16):
    name = username.encode('utf-16-le')
    data = (struct.pack('<LLLL', 0, 0, 5, 0)       # [0:16] header (size filled in below)
            + nt_hash + lm_hash + sha1_hash         # [16:68]
            + b'\x00' * 60 + name)                  # descriptor block + trailing user name
    return data[:4] + struct.pack('<L', len(data)) + data[8:]


def test_parse_tbal():
    nt = os.urandom(16)
    sha1 = os.urandom(20)
    data = _forge_tbal(nt, sha1, 'TestUser')
    parsed = dp.parse_tbal(data)
    assert parsed['username'] == 'TestUser'
    assert parsed['nt_hash'] == nt
    assert parsed['sha1_hash'] == sha1
    assert parsed['lm_hash'] is None   # all-zero LM reported absent


def test_parse_tbal_rejects_short_or_mismatched():
    assert dp.parse_tbal(b'\x00' * 20) is None
    bad = _forge_tbal(os.urandom(16), os.urandom(20), 'x')[:-4]  # size field no longer matches
    assert dp.parse_tbal(bad) is None
