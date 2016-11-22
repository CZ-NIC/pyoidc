import os

from oic.extension.oidc_fed import evaluate_metadata_statement
from oic.extension.oidc_fed import MetadataStatement
from oic.extension.oidc_fed import pack_metadata_statement
from oic.extension.oidc_fed import unpack_metadata_statement
from oic.utils.keyio import build_keyjar

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

keys = [
    {"type": "RSA", "key": os.path.join(BASE_PATH, "fo_sig.key"),
     "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
fo_jwks, fo_keyjar, fo_kidd = build_keyjar(keys)

issuer = 'https://fedop.example.org'

keys = [
    {"type": "RSA", "key": os.path.join(BASE_PATH, "org_sig.key"),
     "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
org_jwks, org_keyjar, org_kidd = build_keyjar(keys)

org_issuer = 'https://org.example.com/org.jwks'

keys = [
    {"type": "RSA", "key": os.path.join(BASE_PATH, "sysadm_sig.key"),
     "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
sysadm_jwks, sysadm_keyjar, sysadm_kidd = build_keyjar(keys)


def test_pack_unpack():
    meta = MetadataStatement(signing_keys=org_jwks,
                             tos_uri='https://example.com/tos.html')
    ms = pack_metadata_statement(meta, fo_keyjar, issuer, scopes=['a', 'b'])

    # all local
    _ms = unpack_metadata_statement(jwt_ms=ms, keyjar=fo_keyjar)
    assert set(_ms.keys()) == {'exp', 'iat', 'iss', 'jti', 'kid',
                               'scopes', 'signing_keys', 'tos_uri'}
    assert _ms['iss'] == issuer


def test_pack_pack_unpack():
    meta_org = MetadataStatement(signing_keys=org_jwks,
                                 tos_uri='https://example.com/tos.html')
    ms0 = pack_metadata_statement(meta_org, fo_keyjar, issuer,
                                  scopes=['a', 'b'])

    meta_sysadm = MetadataStatement(signing_keys=sysadm_jwks,
                                    redirect_uris=['https://example.com/rp/cb'])
    ms1 = pack_metadata_statement(meta_sysadm, org_keyjar, org_issuer,
                                  metadata_statements=[ms0])

    _meta = unpack_metadata_statement(jwt_ms=ms1, keyjar=fo_keyjar)

    assert set(_meta.keys()) == {'exp', 'iat', 'iss', 'jti', 'kid',
                                 'signing_keys', 'redirect_uris',
                                 'metadata_statements'}
    assert _meta['iss'] == org_issuer

    cms = evaluate_metadata_statement(_meta)

    assert cms
