"""Command-line interface for dpapiprobe (SYSTEM-context, Phase 1).

By default the commands print identifiers, lengths and SHA-1 fingerprints, not secret
values. Use the explicit output flags to write recovered cleartext to a file.
"""
import argparse
import hashlib
import sys

from . import (
    CredentialFile,
    DpapiBlob,
    MasterKeyPool,
    VaultPolicy,
    get_bootkey,
    get_lsa_secrets,
    get_dpapi_system,
    system_master_key_candidates,
)


def _fp(data):
    return hashlib.sha1(data).hexdigest()[:12] if data is not None else '-'


def _system_context(args):
    bootkey = get_bootkey(args.system)
    dpapi_system = get_dpapi_system(args.security, bootkey)
    pool = MasterKeyPool()
    for directory in args.protect or []:
        pool.load_directory(directory)
    pool.decrypt_all(system_master_key_candidates(dpapi_system))
    return bootkey, dpapi_system, pool


def _read(path):
    with open(path, 'rb') as handle:
        return handle.read()


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
    opened = 0
    for guid in pool.guids():
        key = pool.get_key(guid)
        if key:
            opened += 1
        print('%s  %s' % (guid, _fp(key) if key else 'LOCKED'))
    print('%d of %d master keys decrypted' % (opened, len(pool.guids())))
    return 0 if opened else 1


def cmd_blob(args):
    _, _, pool = _system_context(args)
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


def build_parser():
    parser = argparse.ArgumentParser(prog='dpapiprobe',
                                     description='Offline Windows DPAPI decryptor (SYSTEM context)')
    sub = parser.add_subparsers(dest='command', required=True)

    def add_hives(p, security=True, protect=False):
        p.add_argument('--system', required=True, help='path to the SYSTEM hive')
        if security:
            p.add_argument('--security', required=True, help='path to the SECURITY hive')
        if protect:
            p.add_argument('--protect', action='append',
                           help='a Protect\\S-1-5-18 directory of master keys (repeatable)')

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

    p = sub.add_parser('blob', help='decrypt a raw DPAPI blob file')
    add_hives(p, protect=True)
    p.add_argument('--in', dest='infile', required=True, help='the blob file')
    p.add_argument('--entropy', help='optional entropy as hex')
    p.add_argument('--out', help='write cleartext here instead of a fingerprint')
    p.set_defaults(func=cmd_blob)

    p = sub.add_parser('credential', help='decrypt a Credential Manager file')
    add_hives(p, protect=True)
    p.add_argument('--in', dest='infile', required=True, help='the Credentials\\<hash> file')
    p.add_argument('--out', help='write cleartext here')
    p.set_defaults(func=cmd_credential)

    p = sub.add_parser('vault-policy', help='decrypt a Vault Policy.vpol')
    add_hives(p, protect=True)
    p.add_argument('--in', dest='infile', required=True, help='the Policy.vpol file')
    p.set_defaults(func=cmd_vault_policy)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
