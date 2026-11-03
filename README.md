# dpapiprobe

An offline reader for Windows DPAPI protected data. Point it at registry hives and
master-key files pulled from a disk image, or at the image itself, and it recovers LSA
secrets, decrypts SYSTEM and user master keys, and unprotects DPAPI blobs, including the
ones wrapped inside Credential Manager and Vault containers and the Chromium browser key
store (saved passwords and cookies). No live system, no agent, no network.

It is pure Python and depends only on PyCryptodome and python-registry, both permissive
licences. It is MIT, so a tool that ships frozen binaries can vendor it. That is the
reason it exists: the maintained offline DPAPI library, dpapick3, is GPL-3.0, which an
MIT project that distributes binaries cannot take as a runtime dependency.

## Scope

**SYSTEM context** (needs only the boot key, no user password):

- Boot key (syskey) from the SYSTEM hive.
- All LSA secrets from the SECURITY hive, decrypted: `DPAPI_SYSTEM`, `$MACHINE.ACC`,
  `NL$KM`, `DefaultPassword`, `TBAL` and any others present.
- SYSTEM master keys, decrypted under `DPAPI_SYSTEM`.
- DPAPI blobs, with optional entropy.
- The Credential Manager files (`Credentials\<hash>`) and Vault policy files
  (`Policy.vpol`) that wrap a blob inside a container header.

**User context** (needs the account's cleartext password or its SHA-1, or its ARSO/TBAL
secret; the SAM NT hash alone does not open Windows 10 and 11 user master keys):

- User master keys, from the password, its SHA-1, or the account's ARSO/TBAL secret
  recovered with the boot key alone.
- Vault credential records (`*.vcrd`) and the Internet Explorer / Web Credentials schema:
  the resource, user name and password.
- Chromium (Chrome, Edge, Brave, Vivaldi, Opera) os_crypt: the Local State key, and the
  `v10` AES-GCM saved passwords (Login Data) and cookies (Cookies), with the cookie
  host-hash prefix stripped at Cookies schema version 24 and later.

Not covered: pre-Vista (Windows XP / 2003) DPAPI, domain backup keys, CNG and smartcard
protectors, and Chrome `v20` App-Bound Encryption (reported, not decrypted: the final key
is held by Chrome's elevation service and is version-specific).

## Install

From a checkout (no PyPI package yet):

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

User context (the account's password, its SHA-1, or `--tbal` with the hives):

```bash
dpapiprobe tbal --system SYSTEM --security SECURITY
dpapiprobe user-masterkeys --sid S-1-5-21-... \
    --protect "Users/<u>/AppData/Roaming/Microsoft/Protect/S-1-5-21-..." --password PW
dpapiprobe vault --sid S-1-5-21-... --protect "Protect/S-1-5-21-..." --tbal \
    --system SYSTEM --security SECURITY --vault-dir "Vault/<GUID>" [--out creds.json]
dpapiprobe chromium --sid S-1-5-21-... --protect "Protect/S-1-5-21-..." --password PW \
    --local-state "User Data/Local State" \
    --login-data "User Data/Default/Login Data" \
    [--cookies "User Data/Default/Network/Cookies"] [--out values.json]
```

Recovered passwords and cookie values are never printed; the default output is the site,
user name and a length and fingerprint, and the cleartext is written only to the `--out`
file you name.

`--protect` can be given more than once, for example the `S-1-5-18` directory and its
`User` subdirectory.

## Reading a disk image directly

Instead of files already pulled from an image, point it at the image and it finds them
itself, through the vendored `ewfprobe` and `qnxprobe` readers (E01, raw, AFF4, AD-encrypted
and split images; the NTFS volume and the other filesystems qnxprobe walks). No extra
dependency: both readers are pure Python and ship in the package. `triage` opens the image
read only, locates the hives, master keys, Vault and Chromium stores across every volume,
and decrypts what the account's password or its ARSO/TBAL secret opens:

```bash
dpapiprobe triage --image disk.E01 [--password PW] [--out creds.json]
```

The default output names the accounts, the TBAL secrets and the recovered credentials by
site and user; cleartext is written only to the `--out` file. `--extract-to DIR` keeps the
files it pulled, and `--image-password` / `--image-key` open an encrypted image.

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
