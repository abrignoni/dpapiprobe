"""Unit tests for the image front-end's path matcher and grouping, without an image.

The full open-image-and-decrypt path is validated against a real image (the AF-Case2
public E01) outside the suite; these cover the pure logic that decides which files the
chain needs and how they group into installs, accounts, vaults and Chromium profiles.
"""
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
