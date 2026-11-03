"""Command-line interface for dpapiprobe.

By default the commands print identifiers, lengths and SHA-1 fingerprints, not secret
values. Use the explicit output flags (``--out``, ``--out-dir``) to write recovered
cleartext to a file the user names.

SYSTEM-context commands (bootkey, lsa, masterkeys, blob, credential, vault-policy) need
only the boot key. User-context commands (user-masterkeys, tbal, vault, chromium) need the
account's cleartext password or its SHA-1 hash, or the account's ARSO/TBAL secret, which
the SAM NT hash alone cannot stand in for.
"""
import argparse
import glob
import hashlib
import json
import os
import sqlite3
import sys

from . import (
    CredentialFile,
    DpapiBlob,
    MasterKeyPool,
    VaultCredential,
    VaultPolicy,
    decrypt_value,
    get_bootkey,
    get_lsa_secrets,
    get_dpapi_system,
    os_crypt_key,
    parse_tbal,
    parse_web_credential,
    strip_cookie_host_hash,
    system_master_key_candidates,
    user_master_key_candidates,
)


def _fp(data):
    return hashlib.sha1(data).hexdigest()[:12] if data is not None else '-'


def _read(path):
    with open(path, 'rb') as handle:
        return handle.read()


def _system_context(args):
    bootkey = get_bootkey(args.system)
    dpapi_system = get_dpapi_system(args.security, bootkey)
    pool = MasterKeyPool()
    for directory in args.protect or []:
        pool.load_directory(directory)
    pool.decrypt_all(system_master_key_candidates(dpapi_system))
    return bootkey, dpapi_system, pool


def _tbal_hashes(system_hive, security_hive):
    """[(username, sha1_hash)] from every TBAL secret in one install."""
    bootkey = get_bootkey(system_hive)
    secrets = get_lsa_secrets(security_hive, bootkey)
    out = []
    for name, value in secrets.items():
        if name.startswith('M$_MSV1_0_TBAL'):
            parsed = parse_tbal(value)
            if parsed and parsed.get('sha1_hash'):
                out.append((parsed.get('username', ''), parsed['sha1_hash']))
    return out


def _user_candidates(args):
    """Pre-key candidates for the account's user master keys, from the given secrets."""
    candidates = []
    if getattr(args, 'password', None):
        candidates.extend(user_master_key_candidates(args.sid, password=args.password))
    if getattr(args, 'sha1', None):
        candidates.extend(user_master_key_candidates(
            args.sid, sha1_hash=bytes.fromhex(args.sha1)))
    if getattr(args, 'tbal', False):
        for _user, sha1 in _tbal_hashes(args.system, args.security):
            candidates.extend(user_master_key_candidates(args.sid, sha1_hash=sha1))
    return candidates


def _user_pool(args):
    pool = MasterKeyPool()
    for directory in args.protect or []:
        pool.load_directory(directory)
    pool.decrypt_all(_user_candidates(args))
    return pool


# --------------------------------------------------------------------------- SYSTEM context

def cmd_bootkey(args):
    print(get_bootkey(args.system).hex())
    return 0


def cmd_lsa(args):
    bootkey = get_bootkey(args.system)
    secrets = get_lsa_secrets(args.security, bootkey)
    if not secrets:
        print('no LSA secrets recovered')
        return 1
    for name in sorted(secrets):
        value = secrets[name]
        if args.out_dir:
            dest = '%s/%s.bin' % (args.out_dir.rstrip('/'), name.replace('$', ''))
            with open(dest, 'wb') as handle:
                handle.write(value)
            print('%-20s %5d bytes  -> %s' % (name, len(value), dest))
        else:
            print('%-20s %5d bytes  fp=%s' % (name, len(value), _fp(value)))
    return 0


def cmd_masterkeys(args):
    _, _, pool = _system_context(args)
    return _report_pool(pool)


def cmd_blob(args):
    pool = _user_pool(args) if _has_user_context(args) else _system_context(args)[2]
    blob = DpapiBlob(_read(args.infile))
    key = pool.get_key(blob.mk_guid)
    if key is None:
        print('master key %s not available/decrypted' % blob.mk_guid, file=sys.stderr)
        return 1
    entropy = bytes.fromhex(args.entropy) if args.entropy else None
    clear = blob.decrypt(key, entropy=entropy)
    if clear is None:
        print('blob did not verify (wrong key or entropy)', file=sys.stderr)
        return 1
    if args.out:
        with open(args.out, 'wb') as handle:
            handle.write(clear)
        print('wrote %d bytes to %s' % (len(clear), args.out))
    else:
        print('mkguid=%s len=%d fp=%s' % (blob.mk_guid, len(clear), _fp(clear)))
    return 0


def cmd_credential(args):
    _, _, pool = _system_context(args)
    cred = CredentialFile(_read(args.infile))
    key = pool.get_key(cred.blob.mk_guid)
    if key is None:
        print('master key %s not available/decrypted' % cred.blob.mk_guid, file=sys.stderr)
        return 1
    clear = cred.decrypt(key)
    if clear is None:
        print('credential blob did not verify', file=sys.stderr)
        return 1
    fields = cred.fields()
    print('len=%d fp=%s strings=%d secret_len=%d'
          % (len(clear), _fp(clear), len(fields['strings']), len(fields['secret'])))
    for text in fields['strings']:
        print('  %s' % text)
    if args.out:
        with open(args.out, 'wb') as handle:
            handle.write(clear)
        print('wrote cleartext to %s' % args.out)
    return 0


def cmd_vault_policy(args):
    _, _, pool = _system_context(args)
    vpol = VaultPolicy(_read(args.infile))
    vpol.decrypt_with_pool(pool)
    print('blobs=%d decrypted=%d key_fp=%s aes_key_lengths=%s'
          % (len(vpol.blobs), len(vpol.cleartexts), _fp(vpol.key_material()),
             [len(k) for k in vpol.aes_keys]))
    return 0 if vpol.cleartexts else 1


# ----------------------------------------------------------------------------- user context

def _has_user_context(args):
    return bool(getattr(args, 'password', None) or getattr(args, 'sha1', None)
                or getattr(args, 'tbal', False))


def _report_pool(pool):
    opened = 0
    for guid in pool.guids():
        key = pool.get_key(guid)
        if key:
            opened += 1
        print('%s  %s' % (guid, _fp(key) if key else 'LOCKED'))
    print('%d of %d master keys decrypted' % (opened, len(pool.guids())))
    return 0 if opened else 1


def cmd_tbal(args):
    hashes = _tbal_hashes(args.system, args.security)
    if not hashes:
        print('no TBAL/ARSO secret present')
        return 1
    for username, sha1 in hashes:
        print('%-20s sha1_fp=%s' % (username or '(unknown)', _fp(sha1)))
    return 0


def cmd_user_masterkeys(args):
    return _report_pool(_user_pool(args))


def _decrypt_vault_dir(vault_dir, pool):
    """Recovered web credentials from one Vault directory as a list of dicts."""
    vpol_path = os.path.join(vault_dir, 'Policy.vpol')
    if not os.path.isfile(vpol_path):
        return []
    vpol = VaultPolicy(_read(vpol_path))
    vpol.decrypt_with_pool(pool)
    aes_keys = vpol.aes_key_candidates(32)
    if not aes_keys:
        return []
    out = []
    for vcrd_path in sorted(glob.glob(os.path.join(vault_dir, '*.vcrd'))):
        record = VaultCredential(_read(vcrd_path))
        decrypted, _key = record.decrypt(aes_keys)
        for clear in (decrypted or {}).values():
            cred = parse_web_credential(clear)
            if cred:
                out.append({'schema': record.friendly_name, 'resource': cred['resource'],
                            'user': cred['user'], 'password': cred['password'],
                            'source': os.path.basename(vcrd_path), 'vault': vault_dir})
    return out


def _print_creds(records):
    for cred in records:
        print('%-28s %-24s pw_len=%d pw_fp=%s'
              % (cred['resource'][:28], cred['user'][:24], len(cred['password']),
                 _fp(cred['password'].encode('utf-8', 'replace'))))


def cmd_vault(args):
    records = _decrypt_vault_dir(args.vault_dir, _user_pool(args))
    if not records:
        print('no web credential recovered (user key or vault policy not available)',
              file=sys.stderr)
    _print_creds(records)
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as handle:
            json.dump(records, handle, indent=2)
        print('wrote %d credential(s) to %s' % (len(records), args.out))
    return 0 if records else 1


def _decrypt_chromium_profile(local_state, login_data, cookies, pool):
    """(os_crypt key, app_bound flag, [record dicts]) for one Chromium profile."""
    with open(local_state, 'r', encoding='utf-8') as handle:
        key, info = os_crypt_key(json.load(handle), pool)
    records = []
    if login_data and os.path.isfile(login_data):
        for origin, username, pwv in _chromium_rows(
                login_data, 'logins', ('origin_url', 'username_value', 'password_value')):
            if not pwv:
                continue
            clear, scheme = decrypt_value(bytes(pwv), key=key, mk_pool=pool)
            records.append(_record('login', _text(origin), _text(username), clear, scheme))
    if cookies and os.path.isfile(cookies):
        version = _cookies_version(cookies)
        for host, name, enc in _chromium_rows(
                cookies, 'cookies', ('host_key', 'name', 'encrypted_value')):
            if not enc:
                continue
            clear, scheme = decrypt_value(bytes(enc), key=key, mk_pool=pool)
            if clear is not None and scheme in ('v10', 'v20'):
                clear = strip_cookie_host_hash(clear, version)
            records.append(_record('cookie', _text(host), _text(name), clear, scheme))
    return key, info.get('app_bound'), records


def _record(kind, ident, name, clear, scheme):
    return {'kind': kind, 'id': ident, 'name': name, 'scheme': scheme,
            'value': clear.decode('utf-8', 'replace') if clear is not None else None}


def _chromium_rows(db_path, table, columns):
    con = sqlite3.connect('file:%s?mode=ro&immutable=1' % db_path, uri=True)
    con.text_factory = bytes
    try:
        return con.execute('SELECT %s FROM %s' % (', '.join(columns), table)).fetchall()
    finally:
        con.close()


def _text(value):
    return value.decode('utf-8', 'replace') if isinstance(value, (bytes, bytearray)) else value


def cmd_chromium(args):
    key, app_bound, records = _decrypt_chromium_profile(
        args.local_state, args.login_data, args.cookies, _user_pool(args))
    _print_chromium(key, app_bound, records)
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as handle:
            json.dump(records, handle, indent=2)
        print('wrote %d value(s) to %s' % (len(records), args.out))
    return 0 if key else 1


def _print_chromium(key, app_bound, records):
    print('os_crypt key: %s  app_bound=%s'
          % (_fp(key) if key else 'NOT RECOVERED', app_bound))
    for rec in records:
        if rec['value'] is not None:
            print('%-7s %-32s %-22s %-5s pw_len=%d pw_fp=%s'
                  % (rec['kind'], rec['id'][:32], rec['name'][:22], rec['scheme'],
                     len(rec['value']), _fp(rec['value'].encode('utf-8', 'replace'))))
        else:
            print('%-7s %-32s %-22s %-5s %s'
                  % (rec['kind'], rec['id'][:32], rec['name'][:22], rec['scheme'],
                     'app-bound (v20)' if rec['scheme'] == 'v20' else 'not decrypted'))


def _cookies_version(path):
    con = sqlite3.connect('file:%s?mode=ro&immutable=1' % path, uri=True)
    try:
        row = con.execute("SELECT value FROM meta WHERE key='version'").fetchone()
        return int(row[0]) if row and row[0] is not None else None
    except (sqlite3.Error, TypeError, ValueError):
        return None
    finally:
        con.close()


def _group_hives(paths):
    """{install root: {'SYSTEM': path, 'SECURITY': path}} from extracted hive paths."""
    installs = {}
    for path in paths:
        norm = path.replace('\\', '/')
        cut = norm.lower().find('/windows/system32/config/')
        root = norm[:cut] if cut != -1 else norm
        name = norm.rsplit('/', 1)[-1].upper()
        if name in ('SYSTEM', 'SECURITY'):
            installs.setdefault(root, {})[name] = path
    return installs


def _group_protect(paths):
    """{SID: set(master-key directories)} from extracted master-key file paths."""
    dirs = {}
    for path in paths:
        parent = path.replace('\\', '/').rsplit('/', 1)[0]
        sid = parent.rsplit('/', 1)[-1]
        if sid.upper().startswith('S-1-'):
            dirs.setdefault(sid, set()).add(parent)
    return dirs


def _group_vault(paths):
    """Sorted Vault directories (the parents of Policy.vpol and *.vcrd)."""
    return sorted({path.replace('\\', '/').rsplit('/', 1)[0] for path in paths})


def _group_chromium(paths):
    """(local_states {user data dir: Local State}, [login paths], [cookie paths])."""
    local_states, logins, cookies = {}, [], []
    for path in paths:
        norm = path.replace('\\', '/')
        base = norm.rsplit('/', 1)[-1].lower()
        if base == 'local state':
            local_states[norm.rsplit('/', 1)[0]] = path
        elif base in ('login data', 'login data for account'):
            logins.append(path)
        elif base == 'cookies':
            cookies.append(path)
    return local_states, logins, cookies


def cmd_triage(args):
    import shutil
    import tempfile
    from .image import extract_dpapi_tree, HIVE, PROTECT, VAULT, CHROMIUM

    workdir = args.extract_to or tempfile.mkdtemp(prefix='dpapiprobe-')
    log = (lambda msg: print('  ' + msg, file=sys.stderr)) if args.verbose else None
    try:
        inv = extract_dpapi_tree(args.image, workdir, password=args.image_password,
                                 private_key=args.image_key, on_log=log)
        installs = _group_hives(inv[HIVE])
        protect = _group_protect(inv[PROTECT])
        tbal = []
        for hives in installs.values():
            if hives.get('SYSTEM') and hives.get('SECURITY'):
                tbal.extend(_tbal_hashes(hives['SYSTEM'], hives['SECURITY']))

        pool = MasterKeyPool()
        candidates = []
        for sid, directories in protect.items():
            for directory in directories:
                pool.load_directory(directory)
            if args.password:
                candidates.extend(user_master_key_candidates(sid, password=args.password))
            for _user, sha1 in tbal:
                candidates.extend(user_master_key_candidates(sid, sha1_hash=sha1))
        if candidates:
            pool.decrypt_all(candidates)

        print('image: %s' % args.image)
        print('accounts with master keys: %d; TBAL secrets: %d' % (len(protect), len(tbal)))
        for username, sha1 in tbal:
            print('  TBAL %-20s sha1_fp=%s' % (username or '(unknown)', _fp(sha1)))

        collected = {'vault': [], 'chromium': []}
        for vault_dir in _group_vault(inv[VAULT]):
            creds = _decrypt_vault_dir(vault_dir, pool)
            if creds:
                print('vault %s:' % _rel(vault_dir, workdir))
                _print_creds(creds)
                collected['vault'].extend(creds)

        local_states, logins, cookies = _group_chromium(inv[CHROMIUM])

        def _udd(store):
            best = None
            for udd in local_states:
                if store.startswith(udd + '/') and (best is None or len(udd) > len(best)):
                    best = udd
            return best

        for store in sorted(logins) + sorted(cookies):
            udd = _udd(store)
            if udd is None:
                continue
            is_login = store in logins
            key, app_bound, records = _decrypt_chromium_profile(
                local_states[udd], store if is_login else None,
                None if is_login else store, pool)
            if records:
                print('chromium %s:' % _rel(store, workdir))
                _print_chromium(key, app_bound, records)
                collected['chromium'].extend(records)

        if args.out:
            with open(args.out, 'w', encoding='utf-8') as handle:
                json.dump(collected, handle, indent=2)
            print('wrote recovered cleartext to %s' % args.out)
        return 0
    finally:
        if args.extract_to is None:
            shutil.rmtree(workdir, ignore_errors=True)


def _rel(path, workdir):
    norm = path.replace('\\', '/')
    marker = workdir.replace('\\', '/') + '/'
    return norm.split(marker, 1)[-1] if marker in norm else norm


def build_parser():
    parser = argparse.ArgumentParser(prog='dpapiprobe',
                                     description='Offline Windows DPAPI decryptor')
    sub = parser.add_subparsers(dest='command', required=True)

    def add_hives(p, security=True, protect=False):
        p.add_argument('--system', required=True, help='path to the SYSTEM hive')
        if security:
            p.add_argument('--security', required=True, help='path to the SECURITY hive')
        if protect:
            p.add_argument('--protect', action='append',
                           help='a Protect\\S-1-5-18 directory of master keys (repeatable)')

    def add_user_context(p):
        p.add_argument('--sid', required=True, help='the account SID the master keys belong to')
        p.add_argument('--protect', action='append', required=True,
                       help="the user's Protect\\<SID> directory of master keys (repeatable)")
        p.add_argument('--password', help='the account cleartext password')
        p.add_argument('--sha1', help='the account password SHA-1 hash as hex')
        p.add_argument('--tbal', action='store_true',
                       help='recover the key from the ARSO/TBAL secret (needs --system/--security)')
        p.add_argument('--system', help='SYSTEM hive (only with --tbal)')
        p.add_argument('--security', help='SECURITY hive (only with --tbal)')

    p = sub.add_parser('bootkey', help='print the boot key (syskey)')
    add_hives(p, security=False)
    p.set_defaults(func=cmd_bootkey)

    p = sub.add_parser('lsa', help='decrypt and list LSA secrets')
    add_hives(p)
    p.add_argument('--out-dir', help='write each secret to <name>.bin in this directory')
    p.set_defaults(func=cmd_lsa)

    p = sub.add_parser('masterkeys', help='decrypt SYSTEM master keys')
    add_hives(p, protect=True)
    p.set_defaults(func=cmd_masterkeys)

    p = sub.add_parser('blob', help='decrypt a raw DPAPI blob file (SYSTEM or user context)')
    add_hives(p, protect=True)
    p.add_argument('--sid', help='account SID, for a user blob')
    p.add_argument('--password', help='account password, for a user blob')
    p.add_argument('--sha1', help='account password SHA-1 hex, for a user blob')
    p.add_argument('--tbal', action='store_true', help='recover the user key from TBAL')
    p.add_argument('--in', dest='infile', required=True, help='the blob file')
    p.add_argument('--entropy', help='optional entropy as hex')
    p.add_argument('--out', help='write cleartext here instead of a fingerprint')
    p.set_defaults(func=cmd_blob)

    p = sub.add_parser('credential', help='decrypt a Credential Manager file')
    add_hives(p, protect=True)
    p.add_argument('--in', dest='infile', required=True, help='the Credentials\\<hash> file')
    p.add_argument('--out', help='write cleartext here')
    p.set_defaults(func=cmd_credential)

    p = sub.add_parser('vault-policy', help='decrypt a Vault Policy.vpol (SYSTEM context)')
    add_hives(p, protect=True)
    p.add_argument('--in', dest='infile', required=True, help='the Policy.vpol file')
    p.set_defaults(func=cmd_vault_policy)

    p = sub.add_parser('tbal', help='recover ARSO/TBAL password hashes (open user keys with no password)')
    add_hives(p)
    p.set_defaults(func=cmd_tbal)

    p = sub.add_parser('user-masterkeys', help='decrypt a user account master keys')
    add_user_context(p)
    p.set_defaults(func=cmd_user_masterkeys)

    p = sub.add_parser('vault', help='decrypt a user Vault (Policy.vpol + *.vcrd web credentials)')
    add_user_context(p)
    p.add_argument('--vault-dir', required=True, help='the Vault\\<GUID> directory')
    p.add_argument('--out', help='write recovered credentials (cleartext) as JSON here')
    p.set_defaults(func=cmd_vault)

    p = sub.add_parser('chromium', help='recover the os_crypt key and decrypt Login Data / Cookies')
    add_user_context(p)
    p.add_argument('--local-state', required=True, help='the profile User Data Local State file')
    p.add_argument('--login-data', help='a Login Data database to decrypt')
    p.add_argument('--cookies', help='a Cookies database to decrypt')
    p.add_argument('--out', help='write recovered values (cleartext) as JSON here')
    p.set_defaults(func=cmd_chromium)

    p = sub.add_parser('triage',
                       help='open a disk image (E01/raw/AFF4/...) and decrypt everything found')
    p.add_argument('--image', required=True, help='the disk image to read (read only)')
    p.add_argument('--password', help='an account password to try on the user master keys')
    p.add_argument('--image-password', help='password for an encrypted image')
    p.add_argument('--image-key', help='private-key file for an encrypted image')
    p.add_argument('--extract-to', help='keep the extracted files here (default: a temp dir)')
    p.add_argument('--out', help='write recovered credentials (cleartext) as JSON here')
    p.add_argument('--verbose', action='store_true', help='log files skipped during extraction')
    p.set_defaults(func=cmd_triage)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
