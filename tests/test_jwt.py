import os
import six
from oic.utils.jwt import JWT
from oic.utils.keyio import build_keyjar

if six.PY2:
    from utils_for_tests import _eq, query_string_compare
else:
    from .utils_for_tests import _eq, query_string_compare

__author__ = 'roland'


BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/keys"))

keys = [
    {"type": "RSA", "key": os.path.join(BASE_PATH, "cert.key"),
     "use": ["enc", "sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]
jwks, keyjar, kidd = build_keyjar(keys)
issuer = 'https://fedop.example.org'


def test_jwt_pack():
    _jwt = JWT(keyjar, lifetime=3600, iss=issuer).pack()

    assert _jwt
    assert len(_jwt.split('.')) == 3


def test_jwt_pack_and_unpack():
    srv = JWT(keyjar, iss=issuer)
    _jwt = srv.pack(sub='sub')

    info = srv.unpack(_jwt)

    assert _eq(info.keys(), ['jti', 'iat', 'exp', 'iss', 'sub'])