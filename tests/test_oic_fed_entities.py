import json
import os
from time import time

import pytest
from jwkest.jwk import rsa_load

from oic import rndstr
from oic.federation import ClientMetadataStatement
from oic.federation import Operator
from oic.federation.client import Client
from oic.federation.provider import Provider
from oic.oic import DEF_SIGN_ALG
from oic.oic.message import RegistrationResponse
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import build_keyjar
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))
_key = rsa_load(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "scope": ["openid"],
    "response_type": ["code"],
    "user_info": {
        "name": None,
        "email": None,
        "nickname": None
    },
    "request_method": "param"
}

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://connect-op.heroku.com",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

KEYJAR = KeyJar()
KEYJAR[""] = KC_RSA

CDB = {}

USERDB = {
    "username": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "username"
    }
}

URLMAP = {CLIENT_ID: ["https://example.com/authz"]}


def _eq(l1, l2):
    return set(l1) == set(l2)


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie == "FAIL":
            return None, 0
        else:
            return {"uid": self.user}, time()


# AUTHN = UsernamePasswordMako(None, "login.mako", tl, PASSWD, "authenticated")
AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = rndstr(16)  # symmetric key used to encrypt cookie info
USERINFO = UserInfo(USERDB)

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


def fo_keyjar(*args):
    _kj = KeyJar()
    for fo in args:
        _kj.import_jwks(fo.jwks, fo.iss)
    return _kj

def fo_member(*args):
    return Operator(fo_keyjar=fo_keyjar(*args))


def create_compound_metadata_statement(spec):
    _ms = None
    root_signer = ''
    for op, op_args, signer, sig_args in spec:
        _cms = ClientMetadataStatement(signing_keys=op.jwks, **op_args)
        if _ms:
            sig_args['metadata_statements'] = [_ms]
        else:  # root signed
            root_signer = signer.iss
        _ms = signer.pack_metadata_statement(_cms, **sig_args)
    return root_signer, _ms


SPEC = [
    [ORGOP, {'contacts': ['info@example.com']},
     FOP, {'alg': 'RS256', 'scope': ['openid']}],
    [INTEROP, {'tos_uri': ['https://rp.example.com/tos.html']},
     ORGOP, {'alg': 'RS256'}],
    [ADMINOP, {'redirect_uris': ['https://rp.example.com/auth_cb']},
     INTEROP, {'alg': 'RS256'}]
]


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        signer, ms = create_compound_metadata_statement(SPEC)
        sms = {signer: [ms]}

        self.redirect_uri = "http://example.com/redirect"
        self.client = Client(CLIENT_ID,
                             client_authn_method=CLIENT_AUTHN_METHOD,
                             fo_keyjar=fo_member(FOP, FO1P).fo_keyjar,
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

        self.provider = Provider(
            SERVER_INFO["issuer"], SessionDB(SERVER_INFO["issuer"]), CDB,
            AUTHN_BROKER, USERINFO, AUTHZ, verify_client, SYMKEY, urlmap=URLMAP,
            keyjar=KEYJAR, fo_keyjar=fo_keyjar(FOP, FO1P),
            fo_priority_order=[FOP.iss, FO1P.iss])
        self.provider.baseurl = self.provider.name

    def test_init(self):
        receiver = fo_member(FOP, FO1P)
        ms = receiver.unpack_metadata_statement(
            jwt_ms=self.client.signed_metadata_statements[FOP.iss][0])
        res = receiver.evaluate_metadata_statement(ms)
        assert FOP.iss in res

    def test_create_registration_request(self):
        req = self.client.federated_client_registration_request(
            redirect_uris=['https://rp.example.com/auth_cb']
        )
        msg = self.provider.registration_endpoint(req.to_json())
        assert msg.status == '201 Created'
        reqresp = RegistrationResponse(**json.loads(msg.message))
        assert reqresp['response_types'] == ['code']