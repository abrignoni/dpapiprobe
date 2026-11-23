"""Open a disk image directly and extract the files the DPAPI chain needs.

The other probes in this family start from the image they were handed; this lets dpapiprobe
do the same. It opens an E01, raw, AFF4, split or encrypted image through the vendored
qnxprobe/ewfprobe readers, walks every filesystem volume it finds, and copies out just the
files the SYSTEM- and user-context chains use: the SYSTEM and SECURITY hives, the SYSTEM and
per-user DPAPI master keys, the Credential Manager and Vault containers, and the Chromium
browser key store and its Login Data and Cookies databases. The image is read only.
Logical evidence (L01, Lx01, AD1) holds no volumes, so the same files are matched among
its entries and copied into a new ``logical-*`` folder.

Extracted-file input is unaffected: this module is used only when a command is given an
image. The files are written under a destination directory, keeping their path inside the
volume, so the rest of the library and CLI read them exactly as they read a staged tree.
"""
import hashlib
import os
import re
import tempfile
import unicodedata

# AD1 entry types that hold no file's content (as the LEAPP cores' raw_image.py), plus D,
# an NTFS alternate data stream
_AD1_NOT_FILES = ('6', 'F', '10', '61', 'D')

_WINDOWS_RESERVED = re.compile(r'(?i)con|prn|aux|nul|conin\$|conout\$|(com|lpt)[1-9\u00b9\u00b2\u00b3]')

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
                       on_log=None, max_file_bytes=256 * 1024 * 1024, on_warning=None):
    """Walk every volume of the image and copy the DPAPI-relevant files under dest_dir.

    Returns an inventory dict with one list of extracted file paths per category. Paths are
    kept relative to the volume (prefixed with the volume name so two volumes do not
    collide), so the files sit under dest_dir as they sat in the image. Logical evidence has
    no volumes and goes into a new folder of dest_dir (``_extract_logical``). The image is
    opened read only; nothing is written back to it. ``on_warning`` receives what a logical
    source held and could not be extracted, which ``on_log`` receives when it is not given.
    """
    from .vendor import qnxprobe          # heavy; loaded only when an image is read
    log = on_log or (lambda _msg: None)
    inventory = {HIVE: [], PROTECT: [], CREDENTIAL: [], VAULT: [], CHROMIUM: []}
    try:
        fh = qnxprobe.open_image(image_path, password=password, private_key=private_key)
    except qnxprobe.LogicalEvidence:
        _extract_logical(image_path, dest_dir, password, private_key, inventory, log,
                         max_file_bytes, on_warning)
        return inventory
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


def _raw_parts(names):
    """An entry's stored names split at either separator, without empty and '.' parts."""
    return [part for name in names for part in re.split(r'[\\/]', name)
            if part not in ('', '.')]


def _safe_part(part):
    """One stored name as a part that stays under the destination on any OS: it can hold a
    drive letter, a parent reference, a character or name Windows cannot create, or an
    unpaired surrogate no filesystem API can encode."""
    part = re.sub('[:<>"|?*\x00-\x1f\ud800-\udfff]', '_', part)
    if not part.strip(' .'):
        part = '_'
    else:
        # Windows drops trailing dots and spaces, which would merge two names
        part = re.sub(r'[ .]+$', lambda m: '_' * len(m.group()), part)
    if _WINDOWS_RESERVED.fullmatch(part.split('.')[0].rstrip(' ')):
        part = '_' + part
    return part


def _safe_parts(names):
    """An entry's stored names as path parts that stay under the destination on any OS."""
    return [_safe_part(part) for part in _raw_parts(names)]


def _assign_folders(paths):
    """The safe parts of each ``(raw parts, safe parts)``, one place per source name.

    Cleaning a name can make two source names read alike (``a:b`` and ``a_b``). The CLI pairs
    files by folder and finds them by name, so they must not share a place. A name that
    needed no cleaning keeps it. The other gets a ``~name-<n>`` suffix, before a file's
    extension. Entries stored under one name still share it, and the caller chooses
    among them.
    """
    assigned, owners = {}, {}

    def place(raw, safe):
        out = []
        for depth, cleaned in enumerate(safe):
            key = _same_path_key('/'.join(raw[:depth + 1]))
            if key not in assigned:
                is_file = depth == len(safe) - 1
                base, ext = os.path.splitext(cleaned) if is_file else (cleaned, '')
                name, number = cleaned, 1
                slot = _same_path_key('/'.join(out + [name]))
                while owners.setdefault(slot, key) != key:
                    number += 1
                    name = '%s~name-%d%s' % (base, number, ext)
                    slot = _same_path_key('/'.join(out + [name]))
                assigned[key] = name
            out.append(assigned[key])
        return out

    for raw, safe in paths:                        # names that needed no cleaning go first
        if raw == safe:
            place(raw, safe)
    return [place(raw, safe) for raw, safe in paths]


def _copy_entry(img, entry, dest, run):
    """Copy an entry to a path nothing holds yet. Returns 'ok', 'taken' when something holds
    the path, 'unreadable' when the entry cannot be read in full at its declared size, 'damaged' when its bytes do not
    match the hash the evidence stores, 'bad-chunk' when it stores none and a chunk behind
    it failed its checksum, or 'unwritable' when the copy cannot be made. The bytes are read in full first, so an unreadable entry leaves no
    folder behind that would stand in another entry's way."""
    scratch = os.path.join(run, '.copying')
    kind, stored = (('md5', entry.md5) if getattr(entry, 'md5', None)
                    else ('sha1', getattr(entry, 'sha1', None)))
    digest = _evidence_hash(kind) if stored else None
    reading = True
    got = 0
    try:
        with img.open_entry(entry) as src:
            reading = False
            with open(scratch, 'wb') as handle:
                while True:
                    reading = True
                    chunk = src.read(1 << 20)
                    reading = False
                    if not chunk:
                        break
                    got += len(chunk)
                    if got > entry.size:           # more than the entry declares
                        break
                    handle.write(chunk)
                    if digest:
                        digest.update(chunk)
    except Exception:  # pylint: disable=broad-exception-caught
        if os.path.exists(scratch):
            os.remove(scratch)
        return 'unreadable' if reading else 'unwritable'
    if got != entry.size:
        os.remove(scratch)
        return 'unreadable'
    if digest and digest.hexdigest() != stored.lower():
        os.remove(scratch)
        return 'damaged'
    if not digest and _reader_saw_damage(img, entry):
        os.remove(scratch)
        return 'bad-chunk'
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'xb'):                     # claims the name; never overwrites
            pass
    except Exception:  # pylint: disable=broad-exception-caught
        os.remove(scratch)
        # a parent that is a file, or on Windows a folder at this name, raises its own error
        taken = os.path.lexists(dest) or any(
            os.path.isfile(parent) for parent in _parents(dest, run))
        _remove_empty_parents(dest, run)
        return 'taken' if taken else 'unwritable'
    try:
        os.replace(scratch, dest)
    except OSError:
        for leftover in (scratch, dest):
            if os.path.exists(leftover):
                os.remove(leftover)
        _remove_empty_parents(dest, run)
        return 'unwritable'
    return 'ok'


def _evidence_hash(kind):
    """A hash for an integrity check, which a build that blocks MD5 for security allows."""
    try:
        return hashlib.new(kind, usedforsecurity=False)
    except TypeError:                              # Python 3.8 has no such argument
        return hashlib.new(kind)


def _reader_saw_damage(img, entry):
    """For an entry with no stored hash: whether a chunk behind it failed its checksum. The
    reader hands such a chunk back and records it, as its own export checks afterwards."""
    check = getattr(img, '_entry_damage', None)
    if check is None:
        return False
    try:
        return bool(check(entry))
    except Exception:  # pylint: disable=broad-exception-caught
        return True


def _parents(path, run):
    """The folders above path, up to but not including the run's own folder."""
    parent = os.path.dirname(path)
    while parent != run and parent != os.path.dirname(parent):
        yield parent
        parent = os.path.dirname(parent)


def _remove_empty_parents(path, run):
    for parent in _parents(path, run):
        try:
            os.rmdir(parent)
        except OSError:
            return


def _extract_logical(image_path, dest_dir, password, private_key, inventory, log,
                     max_file_bytes, warn=None):
    """Copy the DPAPI-relevant files of an L01, Lx01 or AD1 into a new folder of dest_dir.

    An AD1's slack, index, attribute and stream records and folders whose content was not
    collected hold no file, so they are skipped. An entry FTK Imager lists as deleted is left
    out too, with a warning when it sits at a path the chain uses.
    Each run has its own folder, because the CLI loads whole directories and must not read
    another run's files. Under it, files/ holds what the chain reads, by real name. When
    entries want one path, the first readable one takes it, in this order: no dl time
    before a dl time, names stored as they are before a name holding a separator, deeper
    paths before a file that sits where they need a folder, then the first stored. An entry
    with a dl time never takes the path of a file without one, even one that is too large
    or unreadable. The others go to other-copies/<position>/,
    outside the inventory, so nothing reads them as the current file.
    """
    from .vendor import ewfprobe
    warn = warn or log
    with ewfprobe.open_ewf(image_path, password=password, private_key=private_key) as img:
        os.makedirs(dest_dir, exist_ok=True)
        run = tempfile.mkdtemp(prefix='logical-', dir=dest_dir)
        root = os.path.join(run, 'files')
        ad1 = img.format == ewfprobe.FORMAT_AD1
        found = []
        for position, entry in enumerate(img.logical_entries):
            if ad1 and entry.type_code in _AD1_NOT_FILES:
                continue
            if entry.is_folder and (ad1 or not entry.size or not entry.content_collected):
                continue
            raw = _raw_parts(entry.names)
            if not raw:
                continue
            safe = [_safe_part(part) for part in raw]
            rel = '/'.join(safe)
            category = _category('logical/' + rel)     # the prefix stands for a volume name
            if category is None:
                continue
            if ad1 and entry.is_deleted:
                warn('left out %s: FTK Imager lists it as deleted' % rel)
                continue
            found.append((position, entry, raw, safe, category))
        wanted, live = [], set()
        placed = _assign_folders([(item[2], item[3]) for item in found])
        for (position, entry, _raw, _safe, category), parts in zip(found, placed):
            rel = '/'.join(parts)
            has_dl = bool((entry.times or {}).get('dl'))
            if not has_dl:
                live.add(_same_path_key(rel))
            if entry.size > max_file_bytes:
                warn('skip oversized %s (%s bytes)' % (rel, entry.size))
            elif not entry.size:
                # EnCase stores an empty file with one placeholder byte, as the reader reads it
                stored = sum(length for _offset, length in getattr(entry, 'extents', None) or ())
                if stored > 1 or getattr(entry, 'duplicate_offset', None) is not None:
                    warn('left out %s: it records stored data and no size' % rel)
            else:
                joined = any(re.search(r'[\\/]', name) for name in entry.names)
                wanted.append((has_dl, joined, -len(parts), position, entry, parts,
                               category))
        wanted.sort(key=lambda item: item[:4])
        published = set()
        for has_dl, _joined, _depth, position, entry, parts, category in wanted:
            rel = '/'.join(parts)
            state = 'taken'
            key = _same_path_key(rel)
            # published is kept here so the choice is the same on any extraction volume
            if key not in published and not (has_dl and key in live):
                dest = os.path.join(root, *parts)
                state = _copy_entry(img, entry, dest, run)
                if state == 'ok':
                    inventory[category].append(dest)
                    published.add(key)
            if state == 'taken':
                other = os.path.join(run, 'other-copies', str(position), parts[-1])
                state = _copy_entry(img, entry, other, run)
                if state == 'ok':
                    warn('entry %d shares the path %s and was not decrypted; it is in '
                         'other-copies when --extract-to keeps the folder' % (position, rel))
            if state == 'unreadable':
                warn('could not read %s' % rel)
            elif state == 'unwritable':
                warn('could not write %s' % rel)
            elif state == 'damaged':
                warn('%s does not match the hash the evidence stores, so it was left out' % rel)
            elif state == 'bad-chunk':
                warn('%s holds a chunk that fails its checksum, so it was left out' % rel)


def _same_path_key(rel):
    """A path as a case-insensitive, normalising volume sees it."""
    return unicodedata.normalize('NFC', rel).casefold()


def _as_chunks(data):
    """read_file returns bytes on some walkers and a chunk generator on others."""
    if isinstance(data, (bytes, bytearray)):
        yield bytes(data)
    else:
        for chunk in data:
            if chunk:
                yield bytes(chunk)
