"""Registry-reader tests, gated on a local hive set (no hives ship in the repo).

Set ``DPAPIPROBE_TEST_SYSTEM`` and ``DPAPIPROBE_TEST_SECURITY`` to a SYSTEM and
SECURITY hive to exercise the boot-key and LSA-secret paths against real bytes. The
test checks shapes (a 16-byte boot key, a 44-byte DPAPI_SYSTEM) and prints no values.
"""
import os

import pytest

import dpapiprobe as dp

SYSTEM = os.environ.get('DPAPIPROBE_TEST_SYSTEM')
SECURITY = os.environ.get('DPAPIPROBE_TEST_SECURITY')
_reason = 'set DPAPIPROBE_TEST_SYSTEM and DPAPIPROBE_TEST_SECURITY to run'


@pytest.mark.skipif(not (SYSTEM and SECURITY), reason=_reason)
def test_bootkey_is_16_bytes():
    assert len(dp.get_bootkey(SYSTEM)) == 16


@pytest.mark.skipif(not (SYSTEM and SECURITY), reason=_reason)
def test_dpapi_system_is_44_bytes():
    bootkey = dp.get_bootkey(SYSTEM)
    assert len(dp.get_dpapi_system(SECURITY, bootkey)) == 44


@pytest.mark.skipif(not (SYSTEM and SECURITY), reason=_reason)
def test_lsa_secrets_include_dpapi_system():
    bootkey = dp.get_bootkey(SYSTEM)
    secrets = dp.get_lsa_secrets(SECURITY, bootkey)
    assert 'DPAPI_SYSTEM' in secrets
