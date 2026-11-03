"""CLI tests for the user-context commands, over forged structures.

No Windows data. These check the argument plumbing, the user master-key pool build from a
password, and the chromium os_crypt path end to end through cli.main, including that
cleartext reaches --out and not the default output. vault and tbal wrap library functions
covered by test_vault.py and test_user_tbal.py.
"""
import base64
import json
import os
import sqlite3

from Crypto.Cipher import AES

import dpapiprobe as dp
from dpapiprobe import cli

import forge

GUID = '11111111-2222-3333-4444-555555555555'
SID = 'S-1-5-21-1-2-3-1001'
PASSWORD = 'Passw0rd!'


def _user_mk(tmp_path):
    candidates = dp.user_master_key_candidates(SID, password=PASSWORD)
    mk_file, master_key = forge.forge_master_key_file(candidates[0], GUID)
    protect = tmp_path / 'Protect' / SID
    protect.mkdir(parents=True)
    (protect / GUID).write_bytes(mk_file)
    return str(protect), master_key


def test_cli_user_masterkeys_opens_with_password(tmp_path):
    protect, _mk = _user_mk(tmp_path)
    assert cli.main(['user-masterkeys', '--sid', SID, '--protect', protect,
                     '--password', PASSWORD]) == 0


def test_cli_user_masterkeys_wrong_password_locked(tmp_path):
    protect, _mk = _user_mk(tmp_path)
    assert cli.main(['user-masterkeys', '--sid', SID, '--protect', protect,
                     '--password', 'wrong']) == 1


def test_cli_chromium_login_to_out(tmp_path, capsys):
    protect, master_key = _user_mk(tmp_path)
    aes = os.urandom(32)
    local_state = tmp_path / 'Local State'
    local_state.write_text(json.dumps({'os_crypt': {'encrypted_key':
        base64.b64encode(b'DPAPI' + forge.forge_blob(master_key, aes, GUID)).decode()}}))

    login = tmp_path / 'Login Data'
    con = sqlite3.connect(str(login))
    con.execute('CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)')
    nonce = os.urandom(12)
    ct, tag = AES.new(aes, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(b'secret-pass')
    con.execute('INSERT INTO logins VALUES (?,?,?)',
                ('https://x.test/login', 'u@test', b'v10' + nonce + ct + tag))
    con.commit()
    con.close()

    out = tmp_path / 'out.json'
    rc = cli.main(['chromium', '--sid', SID, '--protect', protect, '--password', PASSWORD,
                   '--local-state', str(local_state), '--login-data', str(login),
                   '--out', str(out)])
    assert rc == 0
    printed = capsys.readouterr().out
    assert 'secret-pass' not in printed          # cleartext must not hit the default output
    records = json.loads(out.read_text())
    assert any(r['value'] == 'secret-pass' for r in records)
