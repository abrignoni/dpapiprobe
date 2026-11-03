"""Open a disk image directly and extract the files the DPAPI chain needs.

The other probes in this family start from the image they were handed; this lets dpapiprobe
do the same. It opens an E01, raw, AFF4, split or encrypted image through the vendored
qnxprobe/ewfprobe readers, walks every filesystem volume it finds, and copies out just the
files the SYSTEM- and user-context chains use: the SYSTEM and SECURITY hives, the SYSTEM and
per-user DPAPI master keys, the Credential Manager and Vault containers, and the Chromium
browser key store and its Login Data and Cookies databases. The image is read only.

Extracted-file input is unaffected: this module is used only when a command is given an
image. The files are written under a destination directory, keeping their path inside the
volume, so the rest of the library and CLI read them exactly as they read a staged tree.
"""
import os

# file categories the chain consumes, decided from a volume-relative path
HIVE = 'hive'
PROTECT = 'protect'
CREDENTIAL = 'credential'
VAULT = 'vault'
CHROMIUM = 'chromium'

_BROWSER_MARKERS = ('/user data/', '/opera stable/')


def _category(rel):
    """The category of a volume-relative path, or None if the chain does not use it."""
    p = rel.replace('\\', '/').lower().lstrip('/')
    parts = p.split('/')
    if p.endswith('windows/system32/config/system') or p.endswith('windows/system32/config/security'):
        return HIVE
    if '/microsoft/protect/' in p and len(parts) >= 2 and parts[-2].startswith('s-1-'):
        return PROTECT
    if '/microsoft/credentials/' in p and not p.endswith('/'):
        return CREDENTIAL
    if '/microsoft/vault/' in p and (p.endswith('policy.vpol') or p.endswith('.vcrd')):
        return VAULT
    if any(marker in p for marker in _BROWSER_MARKERS):
        base = parts[-1]
        if base == 'local state' or base == 'login data' or base == 'login data for account' \
                or base == 'cookies':
            return CHROMIUM
    return None


def extract_dpapi_tree(image_path, dest_dir, password=None, private_key=None,
                       on_log=None, max_file_bytes=256 * 1024 * 1024):
    """Walk every volume of the image and copy the DPAPI-relevant files under dest_dir.

    Returns an inventory dict with one list of extracted file paths per category. Paths are
    kept relative to the volume (prefixed with the volume name so two volumes do not
    collide), so the files sit under dest_dir as they sat in the image. The image is opened
    read only; nothing is written back to it.
    """
    from .vendor import qnxprobe          # heavy; loaded only when an image is read
    log = on_log or (lambda _msg: None)
    fh = qnxprobe.open_image(image_path, password=password, private_key=private_key)
    inventory = {HIVE: [], PROTECT: [], CREDENTIAL: [], VAULT: [], CHROMIUM: []}
    s_ifmt, s_ifdir = 0o170000, 0o040000     # format-bits mask, directory, as qnxprobe uses
    for vol in qnxprobe.volumes(fh):
        walker = vol.get('walker')
        if walker is None:
            continue
        vol_name = vol.get('name') or ('lba%d' % vol.get('lba', 0))
        for entry in qnxprobe.walk_all(walker):
            path, node, mode, size = entry[0], entry[1], entry[2], entry[3]
            if (mode & s_ifmt) == s_ifdir:
                continue
            category = _category(path)
            if category is None:
                continue
            if size is None or size < 0 or size > max_file_bytes:
                log('skip oversized or sizeless %s (%s bytes)' % (path, size))
                continue
            dest = os.path.join(dest_dir, vol_name, path.replace('\\', '/'))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            written = 0
            try:
                with open(dest, 'wb') as handle:
                    for chunk in _as_chunks(walker.read_file(node, size)):
                        handle.write(chunk)
                        written += len(chunk)
            except Exception as ex:  # pylint: disable=broad-exception-caught
                log('could not read %s: %s' % (path, type(ex).__name__))  # bad record, keep walking
                continue
            if written:
                inventory[category].append(dest)
    return inventory


def _as_chunks(data):
    """read_file returns bytes on some walkers and a chunk generator on others."""
    if isinstance(data, (bytes, bytearray)):
        yield bytes(data)
    else:
        for chunk in data:
            if chunk:
                yield bytes(chunk)
