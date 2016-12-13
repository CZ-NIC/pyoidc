import os

import pytest
from jwkest.jwk import rsa_load
from oic.extension.oidc_fed import Operator, ClientMetadataStatement

from oic.oic import DEF_SIGN_ALG

from oic.utils.keyio import KeyBundle, build_keyjar, KeyJar

from oic.extension.fed_client import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/keys"))
_key = rsa_load(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYS = {}
ISSUER = {}
OPERATOR = {}

for entity in ['fo', 'fo1', 'org', 'inter', 'admin', 'ligo', 'op']:
    fname = os.path.join(BASE_PATH, "{}.key".format(entity))
    _keydef = KEYDEFS[:]
    _keydef[0]['key'] = fname

    _jwks, _keyjar, _kidd = build_keyjar(_keydef)
    KEYS[entity] = {'jwks': _jwks, 'keyjar': _keyjar, 'kidd': _kidd}
    ISSUER[entity] = 'https://{}.example.org'.format(entity)
    OPERATOR[entity] = Operator(keyjar=_keyjar, iss=ISSUER[entity], jwks=_jwks)

FOP = OPERATOR['fo']
FOP.fo_keyjar = FOP.keyjar
FO1P = OPERATOR['fo1']
FO1P.fo_keyjar = FO1P.keyjar
ORGOP = OPERATOR['org']
ADMINOP = OPERATOR['admin']
INTEROP = OPERATOR['inter']
LIGOOP = OPERATOR['ligo']
OPOP = OPERATOR['op']


def fo_member(*args):
    _kj = KeyJar()
    for fo in args:
        _kj.import_jwks(fo.jwks, fo.iss)
    return _kj


def create_compound_metadata_statement(spec):
    _ms = None
    for signer, sig_args, op, op_args in spec:
        _cms = ClientMetadataStatement(signing_keys=signer.jwks, **op_args)
        if _ms:
            sig_args['metadata_statements'] = [_ms]
        _ms = signer.pack_metadata_statement(_cms, **sig_args)
    return _ms

SPEC = [
    [ORGOP, {'contacts':['info@example.com']},
     FOP, {'alg':'RS256', 'scope':['openid']}],
    [INTEROP, {'tos_uri':['https://inter.example.com/tos.html']},
     ORGOP, {'alg':'RS256'}],
    [ADMINOP, {'redirect_uris':['https://rp.example.com/auth_cb']},
     INTEROP, {'alg':'RS256'}]
]


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        sms = [create_compound_metadata_statement(SPEC)]
        self.redirect_uri = "http://example.com/redirect"
        self.client = Client(CLIENT_ID,
                             client_authn_method=CLIENT_AUTHN_METHOD,
                             fo_keyjar=fo_member(FOP, FO1P),
                             signed_metadata_statements=sms,
                             fo_priority_order=[FOP.iss, FO1P.iss]
                             )
        self.client.redirect_uris = [self.redirect_uri]
        self.client.authorization_endpoint = \
            "http://example.com/authorization"
        self.client.token_endpoint = "http://example.com/token"
        self.client.userinfo_endpoint = "http://example.com/userinfo"
        self.client.client_secret = "abcdefghijklmnop"
        self.client.keyjar[""] = KC_RSA
        self.client.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG[
                "openid_request_object"]}


    def test_init(self):
        assert True