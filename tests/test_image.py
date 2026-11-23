"""Unit tests for the image front-end's path matcher and grouping, without an image.

The full open-image-and-decrypt path is validated against a real image (the AF-Case2
public E01) outside the suite; these cover the pure logic that decides which files the
chain needs and how they group into installs, accounts, vaults and Chromium profiles.
"""
import hashlib
import io
import os
import sqlite3
import struct

import pytest

from dpapiprobe import image
from dpapiprobe import cli


def test_category_matches_targets():
    assert image._category('Windows/System32/config/SYSTEM') == image.HIVE
    assert image._category('Windows/System32/config/SECURITY') == image.HIVE
    assert image._category(
        'Users/u/AppData/Roaming/Microsoft/Protect/S-1-5-21-1-2-3-1000/abc') == image.PROTECT
    assert image._category(
        'Windows/System32/Microsoft/Protect/S-1-5-18/Preferred') == image.PROTECT
    assert image._category(
        'Users/u/AppData/Local/Microsoft/Vault/GUID/Policy.vpol') == image.VAULT
    assert image._category('Users/u/AppData/Local/Microsoft/Vault/GUID/x.vcrd') == image.VAULT
    assert image._category(
        'Users/u/AppData/Local/Google/Chrome/User Data/Local State') == image.CHROMIUM
    assert image._category(
        'Users/u/AppData/Local/Google/Chrome/User Data/Default/Login Data') == image.CHROMIUM
    assert image._category(
        'Users/u/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies') == image.CHROMIUM


def test_category_ignores_unrelated():
    assert image._category('Windows/System32/notepad.exe') is None
    assert image._category('Users/u/Documents/passwords.txt') is None
    # a Protect path whose parent is not a SID is not a master-key file
    assert image._category('Users/u/AppData/Roaming/Microsoft/Protect/CREDHIST') is None


def test_safe_parts_stay_under_the_destination():
    assert image._safe_parts(['C:', 'Windows', 'System32']) == ['C_', 'Windows', 'System32']
    assert image._safe_parts(['..', 'a\\..\\b', '/etc/x']) == ['_', 'a', '_', 'b', 'etc', 'x']
    assert image._safe_parts(['. .', '.']) == ['_']
    assert image._safe_parts(['NUL.txt', 'a?b', 'foo.', 'x\udc80']) == \
        ['_NUL.txt', 'a_b', 'foo_', 'x_']


class _Entry:
    content_collected = True

    def __init__(self, path, data=b'data', times=None, is_folder=False, size=None):
        self.names = tuple(path.split('/'))
        self.data = data
        self.size = len(data) if size is None else size
        self.times = times or {}
        self.is_folder = is_folder


class _Image:
    def __init__(self, entries, fmt='L01'):
        self.logical_entries = entries
        self.format = fmt

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def open_entry(self, entry):
        if isinstance(entry.data, Exception):
            raise entry.data
        return io.BytesIO(entry.data)


def _extract(monkeypatch, tmp_path, entries, fmt='L01', cap=1 << 20):
    from dpapiprobe.vendor import ewfprobe
    monkeypatch.setattr(ewfprobe, 'open_ewf', lambda *a, **k: _Image(entries, fmt))
    inventory = {image.HIVE: [], image.PROTECT: [], image.CREDENTIAL: [], image.VAULT: [],
                 image.CHROMIUM: []}
    logs = []
    image._extract_logical('x.L01', str(tmp_path), None, None, inventory, logs.append, cap)
    return inventory, logs


def _bytes(paths):
    return sorted(open(p, 'rb').read() for p in paths)


SYSTEM = 'Windows/System32/config/SYSTEM'
CREDS = 'Users/u/AppData/Roaming/Microsoft/Credentials'
VAULT = 'Users/u/AppData/Local/Microsoft/Vault/g'


def test_logical_runs_do_not_mix_or_touch_earlier_files(monkeypatch, tmp_path):
    first, _ = _extract(monkeypatch, tmp_path, [_Entry(VAULT + '/a.vcrd', b'a')])
    second, _ = _extract(monkeypatch, tmp_path, [_Entry(VAULT + '/b.vcrd', b'b')])
    assert os.path.dirname(first[image.VAULT][0]) != os.path.dirname(second[image.VAULT][0])
    assert os.listdir(os.path.dirname(second[image.VAULT][0])) == ['b.vcrd']
    assert _bytes(first[image.VAULT]) == [b'a']


def test_logical_first_stored_takes_the_name(monkeypatch, tmp_path):
    inventory, logs = _extract(monkeypatch, tmp_path, [_Entry(SYSTEM, b'one'),
                                                       _Entry(SYSTEM, b'two')])
    assert _bytes(inventory[image.HIVE]) == [b'one']
    assert any('other-copies' in line for line in logs)


def test_logical_dl_entry_never_takes_a_live_entrys_name(monkeypatch, tmp_path):
    entries = [_Entry(SYSTEM, b'old', {'dl': 1}), _Entry(SYSTEM, b'live')]
    assert _bytes(_extract(monkeypatch, tmp_path, entries)[0][image.HIVE]) == [b'live']
    entries = [_Entry(SYSTEM, b'old', {'dl': 1}), _Entry(SYSTEM, b'x' * 20)]
    assert _extract(monkeypatch, tmp_path, entries, cap=10)[0][image.HIVE] == []
    only = [_Entry(SYSTEM, b'old', {'dl': 1})]
    assert _bytes(_extract(monkeypatch, tmp_path, only)[0][image.HIVE]) == [b'old']


def test_logical_unreadable_entry_gives_way(monkeypatch, tmp_path):
    entries = [_Entry(SYSTEM, OSError('bad'), size=4), _Entry(SYSTEM, b'good')]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.HIVE]) == [b'good']
    assert os.path.basename(inventory[image.HIVE][0]) == 'SYSTEM'


def test_logical_failed_copy_leaves_no_partial_file(monkeypatch, tmp_path):
    class Bad(_Image):
        def open_entry(self, entry):
            class Stream(io.BytesIO):
                def read(self, *_):
                    raise OSError('bad')
            return Stream()
    from dpapiprobe.vendor import ewfprobe
    monkeypatch.setattr(ewfprobe, 'open_ewf', lambda *a, **k: Bad([_Entry(SYSTEM)]))
    inventory = {image.HIVE: []}
    image._extract_logical('x', str(tmp_path), None, None, inventory, lambda _m: None, 99)
    assert inventory[image.HIVE] == []
    assert not [f for _d, _s, names in os.walk(tmp_path) for f in names]


def _other_copies(tmp_path):
    return sorted(open(os.path.join(d, n), 'rb').read() for d, _s, names in os.walk(tmp_path)
                  for n in names if 'other-copies' in d)


def test_logical_file_where_a_folder_is_needed(monkeypatch, tmp_path):
    entries = [_Entry(CREDS + '/sub', b'parent'), _Entry(CREDS + '/sub/child', b'child'),
               _Entry(CREDS + '/' + 'n' * 300 + '/x', b'long'), _Entry(SYSTEM, b'hive')]
    inventory, logs = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.CREDENTIAL]) == [b'child']
    assert _other_copies(tmp_path) == [b'parent']
    assert len(inventory[image.HIVE]) == 1
    assert any('could not write' in line for line in logs)


def test_logical_unreadable_child_leaves_the_path_free(monkeypatch, tmp_path):
    entries = [_Entry(CREDS + '/sub', b'parent'),
               _Entry(CREDS + '/sub/child', OSError('bad'), size=4)]
    inventory, logs = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.CREDENTIAL]) == [b'parent']
    assert any('could not read' in line for line in logs)


def test_logical_unwritable_child_leaves_the_path_free(monkeypatch, tmp_path):
    entries = [_Entry(CREDS + '/sub', b'parent'), _Entry(CREDS + '/sub/' + 'n' * 300, b'long')]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.CREDENTIAL]) == [b'parent']


def test_logical_losing_copy_is_kept_outside_the_inventory(monkeypatch, tmp_path):
    entries = [_Entry(VAULT + '/r.vcrd', b'one'), _Entry(VAULT + '/r.vcrd', b'two')]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.VAULT]) == [b'one']
    assert _other_copies(tmp_path) == [b'two']


def test_logical_dl_child_does_not_displace_a_live_file(monkeypatch, tmp_path):
    entries = [_Entry(CREDS + '/k', b'live'), _Entry(CREDS + '/k/old', b'old', {'dl': 1})]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.CREDENTIAL]) == [b'live']
    assert os.path.basename(inventory[image.CREDENTIAL][0]) == 'k'
    assert _other_copies(tmp_path) == [b'old']


def test_logical_empty_entry_is_not_inventoried(monkeypatch, tmp_path):
    assert _extract(monkeypatch, tmp_path, [_Entry(SYSTEM, b'')])[0][image.HIVE] == []


def test_logical_collection_rooted_at_the_profile_folder(monkeypatch, tmp_path):
    key = 'Microsoft/Protect/S-1-5-21-1-2-3-1001/11111111-2222-3333-4444-555555555555'
    assert len(_extract(monkeypatch, tmp_path, [_Entry(key)])[0][image.PROTECT]) == 1


def test_logical_failed_open_leaves_no_folder(monkeypatch, tmp_path):
    from dpapiprobe.vendor import ewfprobe

    def refuse(*_a, **_k):
        raise ewfprobe.EwfFormatError('bad')
    monkeypatch.setattr(ewfprobe, 'open_ewf', refuse)
    with pytest.raises(ewfprobe.EwfFormatError):
        image._extract_logical('x', str(tmp_path), None, None, {}, lambda _m: None, 99)
    assert os.listdir(tmp_path) == []


def _ad1_entry(code=None, deleted=False):
    entry = _Entry(SYSTEM, b'bytes')
    entry.type_code, entry.is_deleted = code, deleted
    return entry


def test_logical_skips_what_holds_no_file(monkeypatch, tmp_path):
    from dpapiprobe.vendor import ewfprobe
    skipped = [_ad1_entry(deleted=True)] + [_ad1_entry(c) for c in ('6', 'F', '10', '61', 'D')]
    folder = _ad1_entry()
    folder.is_folder = True
    inventory, _ = _extract(monkeypatch, tmp_path, skipped + [folder], fmt=ewfprobe.FORMAT_AD1)
    assert inventory[image.HIVE] == []
    kept, _ = _extract(monkeypatch, tmp_path, [_ad1_entry('5')], fmt=ewfprobe.FORMAT_AD1)
    assert len(kept[image.HIVE]) == 1
    uncollected = _Entry(SYSTEM, b'dir', is_folder=True)
    uncollected.content_collected = False
    assert _extract(monkeypatch, tmp_path, [uncollected])[0][image.HIVE] == []
    with_data = _Entry(SYSTEM, b'dir', is_folder=True)
    assert len(_extract(monkeypatch, tmp_path, [with_data])[0][image.HIVE]) == 1
    assert _extract(monkeypatch, tmp_path, [_Entry(SYSTEM, b'x' * 20)], cap=10)[0][image.HIVE] == []
    assert len(_extract(monkeypatch, tmp_path, [_Entry(SYSTEM, b'x' * 10)], cap=10)[0][image.HIVE]) == 1


@pytest.mark.parametrize('folder', ['Case #7', 'a?b', 'a%41'])
def test_cookie_version_reads_a_path_holding_uri_characters(tmp_path, folder):
    if os.name == 'nt' and '?' in folder:
        pytest.skip('Windows cannot create a folder with a question mark')
    where = tmp_path / folder
    where.mkdir()
    db = where / 'Cookies'
    con = sqlite3.connect(db)
    con.execute('CREATE TABLE meta (key TEXT, value TEXT)')
    con.execute("INSERT INTO meta VALUES ('version', '24')")
    con.commit()
    con.close()
    assert cli._cookies_version(str(db)) == 24
    assert sorted(os.listdir(tmp_path)) == [folder]


def test_logical_flattened_name_does_not_take_a_real_files_path(monkeypatch, tmp_path):
    flattened = _Entry('Windows/System32/x', b'other')
    flattened.names = ('Windows', 'System32', 'config\\SYSTEM')
    inventory, _ = _extract(monkeypatch, tmp_path, [flattened, _Entry(SYSTEM, b'hive')])
    named = {os.path.basename(p): open(p, 'rb').read() for p in inventory[image.HIVE]}
    assert named == {'SYSTEM': b'hive', 'SYSTEM~name-2': b'other'}


def test_logical_write_failure_is_not_called_unreadable(monkeypatch, tmp_path):
    class Full(io.BytesIO):
        def write(self, *_):
            raise OSError('no space')

    real_open = open

    def fake_open(path, mode='r', *a, **k):
        if str(path).endswith('.copying'):
            real_open(path, mode).close()
            return Full()
        return real_open(path, mode, *a, **k)
    monkeypatch.setattr('builtins.open', fake_open)
    _inventory, logs = _extract(monkeypatch, tmp_path, [_Entry(SYSTEM)])
    monkeypatch.undo()
    assert any('could not write' in line for line in logs)
    assert not any('could not read' in line for line in logs)


def test_readonly_uri_keeps_a_backslash_in_a_name(tmp_path):
    if os.sep == '\\':
        pytest.skip('a backslash is a separator on Windows')
    (tmp_path / 'a').mkdir()
    right, wrong = tmp_path / 'a\\b.db', tmp_path / 'a' / 'b.db'
    for path, value in ((right, 1), (wrong, 2)):
        con = sqlite3.connect(path)
        con.execute('CREATE TABLE logins (a)')
        con.execute('INSERT INTO logins VALUES (?)', (value,))
        con.commit()
        con.close()
    assert cli._chromium_rows(str(right), 'logins', ['a']) == [(1,)]


def test_readonly_uri_takes_a_surrogate_escaped_path():
    assert '%FF' in cli._readonly_uri('/tmp/bad\udcff/x.db')


def test_vault_folder_may_hold_brackets(tmp_path, monkeypatch):
    folder = tmp_path / '[root]'
    folder.mkdir()
    (folder / 'Policy.vpol').write_bytes(b'x')
    (folder / 'r.vcrd').write_bytes(b'x')
    seen = []

    class Policy:
        def __init__(self, _raw):
            pass

        def decrypt_with_pool(self, _pool):
            pass

        def aes_key_candidates(self, _size):
            return [b'k']

    class Record:
        friendly_name = 'x'

        def __init__(self, raw):
            seen.append(raw)

        def decrypt(self, _keys):
            return {}, None
    monkeypatch.setattr(cli, 'VaultPolicy', Policy)
    monkeypatch.setattr(cli, 'VaultCredential', Record)
    cli._decrypt_vault_dir(str(folder), None)
    assert seen == [b'x']


def test_a_bad_master_key_file_does_not_stop_the_pool():
    from dpapiprobe.masterkey import MasterKeyPool
    pool = MasterKeyPool()
    pool._files['11111111-2222-3333-4444-555555555555'] = b'x'
    unknown_cipher = bytes(96) + (32).to_bytes(8, 'little') + bytes(24) + bytes(28) + b'\xff' * 4
    pool._files['22222222-2222-3333-4444-555555555555'] = unknown_cipher
    seen = []
    assert pool.decrypt_all([b'candidate'], on_error=lambda g, _e: seen.append(g)) == 0
    assert len(seen) == 2
    with pytest.raises((struct.error, KeyError)):
        pool.decrypt_all([b'candidate'])


def test_logical_entry_failing_its_stored_hash_is_left_out(monkeypatch, tmp_path):
    bad, good = _Entry(SYSTEM, b'flipped'), _Entry(SYSTEM, b'good')
    bad.md5 = hashlib.md5(b'original').hexdigest()
    good.md5 = hashlib.md5(b'good').hexdigest().upper()
    inventory, logs = _extract(monkeypatch, tmp_path, [bad, good])
    assert _bytes(inventory[image.HIVE]) == [b'good']
    assert any('does not match the hash' in line for line in logs)


def test_logical_damage_without_a_stored_hash_is_left_out(monkeypatch, tmp_path):
    class Damaged(_Image):
        def _entry_damage(self, _entry):
            return [1]
    from dpapiprobe.vendor import ewfprobe
    monkeypatch.setattr(ewfprobe, 'open_ewf', lambda *a, **k: Damaged([_Entry(SYSTEM)], 'L01'))
    inventory, logs = {image.HIVE: []}, []
    image._extract_logical('x', str(tmp_path), None, None, inventory, logs.append, 99)
    assert inventory[image.HIVE] == [] and any('fails its checksum' in line for line in logs)


def test_logical_data_with_no_size_and_deleted_ad1_are_reported(monkeypatch, tmp_path):
    from dpapiprobe.vendor import ewfprobe
    sizeless = _Entry(SYSTEM, b'')
    sizeless.extents = [(10, 64)]
    assert any('no size' in line for line in _extract(monkeypatch, tmp_path, [sizeless])[1])
    placeholder = _Entry(SYSTEM, b'')
    placeholder.extents = [(10, 1)]
    assert _extract(monkeypatch, tmp_path, [placeholder])[1] == []
    logs = _extract(monkeypatch, tmp_path, [_ad1_entry(deleted=True)], fmt=ewfprobe.FORMAT_AD1)[1]
    assert any('as deleted' in line for line in logs)


def test_logical_folders_that_clean_to_one_name_stay_apart(monkeypatch, tmp_path):
    base = 'Users/u/AppData/Local/Microsoft/Vault/'
    entries = [_Entry(base + 'a:b/Policy.vpol', b'one'), _Entry(base + 'a_b/x.vcrd', b'two')]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    folders = {os.path.dirname(p): open(p, 'rb').read() for p in inventory[image.VAULT]}
    assert len(folders) == 2
    clean = [f for f, data in folders.items() if data == b'two'][0]
    assert os.path.basename(clean) == 'a_b'


def test_logical_folders_differing_by_case_stay_apart(monkeypatch, tmp_path):
    entries = [_Entry(VAULT + '/a.vcrd', b'a'), _Entry(VAULT[:-1] + 'G/b.vcrd', b'b')]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    assert len({os.path.dirname(p) for p in inventory[image.VAULT]}) == 2


@pytest.mark.parametrize('declared', [3, 8])
def test_logical_entry_of_another_length_than_declared_is_left_out(monkeypatch, tmp_path,
                                                                   declared):
    entry = _Entry(SYSTEM, b'hello', size=declared)
    inventory, logs = _extract(monkeypatch, tmp_path, [entry])
    assert inventory[image.HIVE] == [] and any('could not read' in line for line in logs)
    assert not [f for _d, _s, names in os.walk(tmp_path) for f in names]


def test_logical_names_differing_by_case_stay_distinct(monkeypatch, tmp_path):
    entries = [_Entry(SYSTEM, b'first'), _Entry(SYSTEM[:-6] + 'system', b'second')]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    named = {os.path.basename(p): open(p, 'rb').read() for p in inventory[image.HIVE]}
    assert named == {'SYSTEM': b'first', 'system~name-2': b'second'}


def test_logical_names_differing_by_normalization_stay_distinct(monkeypatch, tmp_path):
    entries = [_Entry(CREDS + '/Jos\u00e9', b'first'), _Entry(CREDS + '/Jose\u0301', b'second')]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.CREDENTIAL]) == [b'first', b'second']


def test_logical_file_names_that_clean_to_one_name_stay_apart(monkeypatch, tmp_path):
    entries = [_Entry(VAULT + '/a:b.vcrd', b'one'), _Entry(VAULT + '/a_b.vcrd', b'two')]
    inventory, _ = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.VAULT]) == [b'one', b'two']
    assert all(path.endswith('.vcrd') for path in inventory[image.VAULT])
    named = {open(p, 'rb').read(): os.path.basename(p) for p in inventory[image.VAULT]}
    assert named[b'two'] == 'a_b.vcrd'


def test_evidence_hash_asks_for_a_non_security_use(monkeypatch):
    seen = []
    real = hashlib.new

    def spy(name, *args, **kwargs):
        seen.append(kwargs.get('usedforsecurity'))
        return real(name, *args, **kwargs)
    monkeypatch.setattr(image.hashlib, 'new', spy)
    image._evidence_hash('md5')
    assert seen == [False]


def test_logical_failed_publish_leaves_nothing_and_carries_on(monkeypatch, tmp_path):
    real = os.replace

    def refuse_first(src, dst):
        if os.path.basename(dst) == 'bad':
            raise OSError('refused')
        real(src, dst)
    monkeypatch.setattr(image.os, 'replace', refuse_first)
    entries = [_Entry(CREDS + '/bad', b'one'), _Entry(CREDS + '/good', b'two')]
    inventory, logs = _extract(monkeypatch, tmp_path, entries)
    assert _bytes(inventory[image.CREDENTIAL]) == [b'two']
    assert any('could not write' in line for line in logs)
    names = [f for _d, _s, files in os.walk(tmp_path) for f in files]
    assert names == ['good']


def test_logical_entry_must_match_every_stored_hash(monkeypatch, tmp_path):
    entry = _Entry(SYSTEM, b'bytes')
    entry.md5 = hashlib.md5(b'bytes').hexdigest()
    entry.sha1 = hashlib.sha1(b'other').hexdigest()
    inventory, logs = _extract(monkeypatch, tmp_path, [entry])
    assert inventory[image.HIVE] == [] and any('does not match' in line for line in logs)


def test_local_state_is_keyed_by_this_os_folder():
    if os.sep == '\\':
        pytest.skip('a backslash is a separator on Windows')
    local_states, _logins, _cookies = cli._group_chromium(['/x/a\\b/User Data/Local State'])
    assert list(local_states) == ['/x/a\\b/User Data']


def test_vault_prefers_the_exact_policy_and_skips_folders(tmp_path, monkeypatch):
    if _folds_case(tmp_path):
        pytest.skip('needs a case-sensitive volume')
    (tmp_path / 'POLICY.VPOL').mkdir()
    (tmp_path / 'Policy.vpol').write_bytes(b'policy')
    (tmp_path / 'X.VCRD').mkdir()
    (tmp_path / 'r.vcrd').write_bytes(b'record')
    policies, records = [], []

    class Policy:
        def __init__(self, raw):
            policies.append(raw)

        def decrypt_with_pool(self, _pool):
            pass

        def aes_key_candidates(self, _size):
            return [b'k']

    class Record:
        friendly_name = 'x'

        def __init__(self, raw):
            records.append(raw)

        def decrypt(self, _keys):
            return {}, None
    monkeypatch.setattr(cli, 'VaultPolicy', Policy)
    monkeypatch.setattr(cli, 'VaultCredential', Record)
    cli._decrypt_vault_dir(str(tmp_path), None)
    assert policies == [b'policy'] and records == [b'record']


def _folds_case(folder):
    probe = folder / 'CaseProbe'
    probe.write_bytes(b'')
    try:
        return (folder / 'caseprobe').exists()
    finally:
        probe.unlink()


def test_vault_finds_names_in_any_case(tmp_path, monkeypatch):
    (tmp_path / 'POLICY.VPOL').write_bytes(b'x')
    (tmp_path / 'R.VCRD').write_bytes(b'record')
    seen = []

    class Policy:
        def __init__(self, _raw):
            pass

        def decrypt_with_pool(self, _pool):
            pass

        def aes_key_candidates(self, _size):
            return [b'k']

    class Record:
        friendly_name = 'x'

        def __init__(self, raw):
            seen.append(raw)

        def decrypt(self, _keys):
            return {}, None
    monkeypatch.setattr(cli, 'VaultPolicy', Policy)
    monkeypatch.setattr(cli, 'VaultCredential', Record)
    cli._decrypt_vault_dir(str(tmp_path), None)
    assert seen == [b'record']


def test_readonly_uri_keeps_parent_parts_for_the_os_to_resolve(tmp_path):
    if os.sep == '\\':
        pytest.skip('POSIX symlink behavior')
    (tmp_path / 'real' / 'sub').mkdir(parents=True)
    (tmp_path / 'link').symlink_to(tmp_path / 'real' / 'sub')
    db = tmp_path / 'real' / 'x.db'
    con = sqlite3.connect(db)
    con.execute('CREATE TABLE logins (a)')
    con.execute('INSERT INTO logins VALUES (1)')
    con.commit()
    con.close()
    assert cli._chromium_rows(str(tmp_path / 'link' / '..' / 'x.db'), 'logins', ['a']) == [(1,)]


def test_lost_entries_reach_the_warning_channel(monkeypatch, tmp_path):
    from dpapiprobe.vendor import ewfprobe, qnxprobe

    def logical(*_a, **_k):
        raise qnxprobe.LogicalEvidence('x', 'L01')
    monkeypatch.setattr(qnxprobe, 'open_image', logical)
    entries = [_Entry(SYSTEM, OSError('bad'), size=4)]
    monkeypatch.setattr(ewfprobe, 'open_ewf', lambda *a, **k: _Image(entries, 'L01'))
    warned, logged = [], []
    image.extract_dpapi_tree('x', str(tmp_path), on_log=logged.append,
                             on_warning=warned.append)
    assert any('could not read' in line for line in warned) and logged == []


def test_one_bad_vault_record_keeps_the_others(tmp_path, monkeypatch, capsys):
    (tmp_path / 'Policy.vpol').write_bytes(b'x')
    (tmp_path / 'a.vcrd').write_bytes(b'good')
    (tmp_path / 'z.vcrd').write_bytes(b'bad')

    class Policy:
        def __init__(self, _raw):
            pass

        def decrypt_with_pool(self, _pool):
            pass

        def aes_key_candidates(self, _size):
            return [b'k']

    class Record:
        friendly_name = 'x'

        def __init__(self, raw):
            if raw == b'bad':
                raise struct.error('short')

        def decrypt(self, _keys):
            return {'a': b'clear'}, None
    monkeypatch.setattr(cli, 'VaultPolicy', Policy)
    monkeypatch.setattr(cli, 'VaultCredential', Record)
    monkeypatch.setattr(cli, 'parse_web_credential',
                        lambda _c: {'resource': 'r', 'user': 'u', 'password': 'p'})
    assert [c['source'] for c in cli._decrypt_vault_dir(str(tmp_path), None)] == ['a.vcrd']
    assert 'z.vcrd' in capsys.readouterr().err


def test_one_bad_vault_attribute_keeps_the_others(tmp_path, monkeypatch, capsys):
    (tmp_path / 'Policy.vpol').write_bytes(b'x')
    (tmp_path / 'a.vcrd').write_bytes(b'x')

    class Policy:
        def __init__(self, _raw):
            pass

        def decrypt_with_pool(self, _pool):
            pass

        def aes_key_candidates(self, _size):
            return [b'k']

    class Record:
        friendly_name = 'x'

        def __init__(self, _raw):
            pass

        def decrypt(self, _keys):
            return {'bad': b'bad', 'good': b'good'}, None

    def parse(clear):
        if clear == b'bad':
            raise struct.error('short')
        return {'resource': 'r', 'user': 'u', 'password': 'p'}
    monkeypatch.setattr(cli, 'VaultPolicy', Policy)
    monkeypatch.setattr(cli, 'VaultCredential', Record)
    monkeypatch.setattr(cli, 'parse_web_credential', parse)
    assert len(cli._decrypt_vault_dir(str(tmp_path), None)) == 1
    assert 'an attribute of a.vcrd' in capsys.readouterr().err


def test_one_bad_login_row_keeps_the_others(tmp_path, monkeypatch, capsys):
    state = tmp_path / 'Local State'
    state.write_text('{}')
    db = tmp_path / 'Login Data'
    con = sqlite3.connect(db)
    con.execute('CREATE TABLE logins (origin_url, username_value, password_value)')
    con.executemany('INSERT INTO logins VALUES (?, ?, ?)',
                    [('a', 'u', b'good'), ('b', 'u', b'bad')])
    con.commit()
    con.close()

    def fake_decrypt(value, **_k):
        if value == b'bad':
            raise struct.error('short')
        return b'clear', 'v10'
    monkeypatch.setattr(cli, 'os_crypt_key', lambda *_a: (b'k', {}))
    monkeypatch.setattr(cli, 'decrypt_value', fake_decrypt)
    _key, _bound, rows = cli._decrypt_chromium_profile(str(state), str(db), None, None)
    assert [(r['value'], r['scheme']) for r in rows] == [('clear', 'v10'), (None, 'error')]
    assert 'a login of b' in capsys.readouterr().err


def test_chromium_store_path_may_hold_a_hash(tmp_path):
    folder = tmp_path / 'Profile#1'
    folder.mkdir()
    db = folder / 'Login Data'
    con = sqlite3.connect(db)
    con.execute('CREATE TABLE logins (a)')
    con.execute('INSERT INTO logins VALUES (1)')
    con.commit()
    con.close()
    assert cli._chromium_rows(str(db), 'logins', ['a']) == [(1,)]


def test_group_hives_and_protect():
    installs = cli._group_hives([
        '/x/lba0/Windows/System32/config/SYSTEM',
        '/x/lba0/Windows/System32/config/SECURITY'])
    (root, pair), = installs.items()
    assert pair['SYSTEM'].endswith('SYSTEM') and pair['SECURITY'].endswith('SECURITY')

    protect = cli._group_protect([
        '/x/Users/u/AppData/Roaming/Microsoft/Protect/S-1-5-21-1-2-3-1000/key1',
        '/x/Users/u/AppData/Roaming/Microsoft/Protect/S-1-5-21-1-2-3-1000/Preferred'])
    assert list(protect) == ['S-1-5-21-1-2-3-1000']
    assert len(next(iter(protect.values()))) == 1


def test_group_chromium():
    local_states, logins, cookies = cli._group_chromium([
        '/x/Chrome/User Data/Local State',
        '/x/Chrome/User Data/Default/Login Data',
        '/x/Chrome/User Data/Default/Network/Cookies'])
    assert list(local_states) == ['/x/Chrome/User Data']
    assert logins and cookies
