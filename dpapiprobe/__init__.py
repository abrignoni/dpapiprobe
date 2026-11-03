"""dpapiprobe: an offline Windows DPAPI decryption library (clean-room, MIT).

Phase 1 (SYSTEM context, no credential gate): boot key, all LSA secrets, SYSTEM
master keys, DPAPI blobs (with optional entropy), and the Credential Manager / Vault
containers that wrap them.
"""
from .arso import parse_tbal
from .blob import DpapiBlob, decrypt_blob, find_blob_offset
from .credvault import CredentialFile, VaultPolicy
from .masterkey import (
    MasterKeyPool,
    decrypt_master_key,
    master_key_guid,
    user_master_key_candidates,
)
from .registry_secrets import (
    UnsupportedHive,
    get_bootkey,
    get_dpapi_system,
    get_lsa_secrets,
    system_master_key_candidates,
)

__version__ = '0.2.0'

__all__ = [
    'DpapiBlob',
    'decrypt_blob',
    'find_blob_offset',
    'CredentialFile',
    'VaultPolicy',
    'MasterKeyPool',
    'decrypt_master_key',
    'master_key_guid',
    'user_master_key_candidates',
    'parse_tbal',
    'UnsupportedHive',
    'get_bootkey',
    'get_dpapi_system',
    'get_lsa_secrets',
    'system_master_key_candidates',
    '__version__',
]
