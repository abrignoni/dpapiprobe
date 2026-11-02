# dpapiprobe

An offline reader for Windows DPAPI protected data. Point it at registry hives and
master-key files pulled from a disk image and it recovers LSA secrets, decrypts SYSTEM
master keys, and unprotects DPAPI blobs, including the ones wrapped inside Credential
Manager and Vault containers. No live system, no agent, no network.

It is pure Python and depends only on PyCryptodome and python-registry, both permissive
licences. It is MIT, so a tool that ships frozen binaries can vendor it. That is the
reason it exists: the maintained offline DPAPI library, dpapick3, is GPL-3.0, which an
MIT project that distributes binaries cannot take as a runtime dependency.

## Scope

This release covers the SYSTEM context, which needs only the boot key and no user
password:

- Boot key (syskey) from the SYSTEM hive.
- All LSA secrets from the SECURITY hive, decrypted: `DPAPI_SYSTEM`, `$MACHINE.ACC`,
  `NL$KM`, `DefaultPassword`, `TBAL` and any others present.
- SYSTEM master keys, decrypted under `DPAPI_SYSTEM`.
- DPAPI blobs, with optional entropy.
- The Credential Manager files (`Credentials\<hash>`) and Vault policy files
  (`Policy.vpol`) that wrap a blob inside a container header, and the outer structure of
  Vault credential records (`*.vcrd`).

Not in this release:

- User context (Chromium passwords and cookies, user Credential Manager and Vault
  records, user master keys). Those need the account's cleartext password or its SHA-1,
  not the SAM NT hash, and are the next phase.
- Vault credential record (`*.vcrd`) attribute decryption. The records that carry
  attributes live in user vaults, so their decryption belongs with the user context; the
  SYSTEM vaults hold only policy and schema files.
- Pre-Vista (Windows XP / 2003) DPAPI, domain backup keys, CNG and smartcard protectors.

## Install

```bash
pip install dpapiprobe
```

Or from a checkout:

```bash
pip install -e .
```

## Command line

Every command reads hives and files from a mounted or extracted image. By default the
output is identifiers, lengths and SHA-1 fingerprints, not secret values; use the
explicit output flags to write recovered cleartext to a file.

```bash
dpapiprobe bootkey --system SYSTEM
dpapiprobe lsa --system SYSTEM --security SECURITY
dpapiprobe masterkeys --system SYSTEM --security SECURITY --protect Protect/S-1-5-18
dpapiprobe blob --system SYSTEM --security SECURITY \
    --protect Protect/S-1-5-18 --in blob.bin [--entropy HEX] [--out clear.bin]
dpapiprobe credential --system SYSTEM --security SECURITY \
    --protect Protect/S-1-5-18 --in "Credentials/DFBE70A7..."
dpapiprobe vault-policy --system SYSTEM --security SECURITY \
    --protect Protect/S-1-5-18 --in Policy.vpol
```

`--protect` can be given more than once, for example the `S-1-5-18` directory and its
`User` subdirectory.

## Library

```python
import dpapiprobe as dp

bootkey = dp.get_bootkey("SYSTEM")
secrets = dp.get_lsa_secrets("SECURITY", bootkey)        # {name: cleartext bytes}
dpapi_system = secrets["DPAPI_SYSTEM"]

pool = dp.MasterKeyPool()
pool.load_directory("Windows/System32/Microsoft/Protect/S-1-5-18")
pool.decrypt_all(dp.system_master_key_candidates(dpapi_system))

blob = dp.DpapiBlob(open("blob.bin", "rb").read())
clear = blob.decrypt(pool.get_key(blob.mk_guid))          # or decrypt(key, entropy=b"...")
```

## Validation

The test suite ships synthetic vectors only. They are forged in-process from random keys
with an encryptor coded separately from the library, so a round-trip checks the parsing
offsets and key schedule against an independent code path. Those forged blobs were also
confirmed to open under an independent engine, so the format they use is the real one.

The registry, master-key and blob paths were validated against real Windows data outside
the repo: a known-plaintext round trip minted on a Windows 11 lab VM (including the
optional-entropy path), and real images whose recovered keys matched an independent
decryptor. The registry-reader tests run against a local hive set when you point
`DPAPIPROBE_TEST_SYSTEM` and `DPAPIPROBE_TEST_SECURITY` at one; no hive ships here.

```bash
pip install -e . pytest
pytest
```

One fact worth stating, because it is easy to get wrong: the master-key KDF is
Microsoft's iterated-HMAC derivation that folds each round into the accumulator
(`T ^= HMAC(pwd, T)`). It is not RFC 2898 PBKDF2, and standard PBKDF2 does not open real
Windows master keys.

## Licence

MIT. See [LICENSE](LICENSE). Written clean-room from the documented DPAPI structures and
independent analysis.
