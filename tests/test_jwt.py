import os

from oic.utils.jwt import JWT
from oic.utils.keyio import build_keyjar
from oic.utils.keyio import keybundle_from_local_file

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


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_jwt_pack():
    _jwt = JWT(keyjar, lifetime=3600, iss=issuer).pack()

    assert _jwt
    assert len(_jwt.split('.')) == 3


def test_jwt_pack_and_unpack():
    srv = JWT(keyjar, iss=issuer)
    _jwt = srv.pack(sub='sub')

    info = srv.unpack(_jwt)

    assert _eq(info.keys(), ['jti', 'iat', 'exp', 'iss', 'sub', 'kid'])


class TestJWT(object):
    """Tests for JWT."""

    def test_unpack_verify_key(self):
        srv = JWT(keyjar, iss=issuer)
        _jwt = srv.pack(sub="sub")
        # Remove the signing key from keyjar
        keyjar.remove_key("", "RSA", "")
        # And add it back as verify
        kb = keybundle_from_local_file(os.path.join(BASE_PATH, "cert.key"), "RSA", ["ver"])
        # keybundle_from_local_file doesn'assign kid, so assign manually
        kb._keys[0].kid = kidd["sig"]["RSA"]
        keyjar.add_kb("", kb)
        info = srv.unpack(_jwt)
        assert info["sub"] == "sub"
