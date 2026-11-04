"""registry_secrets on hives built by tests/hivebuilder.py: the boot key, the refusal of a
pre-Vista SECURITY hive, a damaged secret, and that a hive is read as it is stored.

The boot key is also computed with python-registry, the reader this module used before 0.6.0,
when it is installed: both must give the same 16 bytes.
"""
import os
import struct
import tempfile
from unittest import mock

import pytest

import dpapiprobe as dp
from dpapiprobe import registry_secrets as rs

import hivebuilder
from hivebuilder import V

# four 4-byte class names, hex text, as the LSA subkeys store them
CLASSES = {'JD': '00112233', 'Skew1': '44556677', 'GBG': '8899aabb', 'Data': 'ccddeeff'}


def _system():
    lsa = {'name': 'Lsa', 'keys': [{'name': name, 'class': text} for name, text in CLASSES.items()]}
    tree = {'name': 'ROOT', 'keys': [
        {'name': 'Select', 'values': [V('Current', 4, struct.pack('<I', 1))]},
        {'name': 'ControlSet001', 'keys': [{'name': 'Control', 'keys': [lsa]}]},
    ]}
    return hivebuilder.build(tree)


def _security(with_polek=True, secret=b'\x01' * 120):
    policy = {'name': 'Policy', 'keys': [
        {'name': 'Secrets', 'keys': [{'name': 'DPAPI_SYSTEM', 'keys': [
            {'name': 'CurrVal', 'values': [V('', 0, secret)]}]}]}]}
    if with_polek:
        policy['keys'].append({'name': 'PolEKList', 'values': [V('', 0, b'\x02' * 200)]})
    return hivebuilder.build({'name': 'ROOT', 'keys': [policy]})


def _write(folder, name, data):
    path = os.path.join(folder, name)
    with open(path, 'wb') as handle:
        handle.write(data)
    return path


def test_bootkey_is_the_class_names_unscrambled():
    with tempfile.TemporaryDirectory() as folder:
        key = dp.get_bootkey(_write(folder, 'SYSTEM', _system()))
    scrambled = bytes.fromhex(''.join(CLASSES[name] for name in ('JD', 'Skew1', 'GBG', 'Data')))
    assert key == bytes(scrambled[rs._BOOTKEY_PERM[i]] for i in range(16))  # pylint: disable=protected-access


def test_bootkey_matches_python_registry():
    try:
        from Registry import Registry as registry  # pylint: disable=import-outside-toplevel
    except ImportError:
        pytest.skip('python-registry is not installed')
    with tempfile.TemporaryDirectory() as folder:
        path = _write(folder, 'SYSTEM', _system())
        with open(path, 'rb') as handle:
            reg = registry.Registry(handle)
            current = 'ControlSet%03d' % reg.open('Select').value('Current').value()
            lsa = reg.open(current + '\\Control\\Lsa')
            scrambled = b''.join(bytes.fromhex(lsa.subkey(n)._nkrecord.classname())  # pylint: disable=protected-access
                                 for n in rs._BOOTKEY_SUBKEYS)  # pylint: disable=protected-access
        old = bytes(scrambled[rs._BOOTKEY_PERM[i]] for i in range(16))  # pylint: disable=protected-access
        assert dp.get_bootkey(path) == old


def test_a_hive_without_polek_list_is_unsupported():
    with tempfile.TemporaryDirectory() as folder:
        with pytest.raises(dp.UnsupportedHive):
            dp.get_lsa_secrets(_write(folder, 'SECURITY', _security(with_polek=False)), b'\x00' * 16)


def test_secrets_are_listed_by_name():
    with tempfile.TemporaryDirectory() as folder:
        secrets = dp.get_lsa_secrets(_write(folder, 'SECURITY', _security()), b'\x00' * 16)
    assert list(secrets) == ['DPAPI_SYSTEM']


def test_a_secret_whose_data_cannot_be_read_raises():
    data = bytearray(_security())
    hive = rs.regfprobe.Hive(bytes(data), recover=False)
    value = hive.open_key('Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal').value('')
    struct.pack_into('<I', data, 4096 + value.offset + 4 + 8, 0x7FFFFFF8)   # data offset past the end
    with tempfile.TemporaryDirectory() as folder:
        with pytest.raises(rs.regfprobe.RegfError):
            dp.get_lsa_secrets(_write(folder, 'SECURITY', bytes(data)), b'\x00' * 16)


def test_hives_are_read_as_stored_without_their_logs():
    with tempfile.TemporaryDirectory() as folder:
        path = _write(folder, 'SYSTEM', _system())
        _write(folder, 'SYSTEM.LOG1', b'regf' + b'\x00' * 4092)
        with mock.patch.object(rs.regfprobe, 'Hive', wraps=rs.regfprobe.Hive) as hive:
            dp.get_bootkey(path)
        assert hive.call_args.kwargs == {'recover': False}
