# pylint: disable=missing-docstring,no-self-use
import json
import logging
import os
import time
from datetime import datetime as dt
from datetime import timedelta

import pytest
from freezegun import freeze_time

from oic.oauth2.message import MissingSigningKey
from oic.oic import AuthorizationResponse
from oic.utils.keyio import JWKSError
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import RSAKey
from oic.utils.keyio import build_keyjar
from oic.utils.keyio import dump_jwks
from oic.utils.keyio import key_export
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.keyio import rsa_init

__author__ = 'rohe0002'

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))
folder = os.path.abspath(os.path.dirname(__file__))
jwks_folder = os.path.join(folder, 'jwks')

RSAKEY = os.path.join(BASE_PATH, "cert.key")
RSA0 = os.path.join(BASE_PATH, "rsa.key")

with open(os.path.join(jwks_folder, 'jwks0.json')) as f:
    JWK0 = json.load(f)
with open(os.path.join(jwks_folder, 'jwks1.json')) as f:
    JWK1 = json.load(f)
with open(os.path.join(jwks_folder, 'jwks2.json')) as f:
    JWK2 = json.load(f)
with open(os.path.join(jwks_folder, 'jwks_uk.json')) as f:
    JWK_UK = json.load(f)
with open(os.path.join(jwks_folder, 'jwks_spo.json')) as f:
    JWKS_SPO = json.load(f)
with open(os.path.join(jwks_folder, 'jwks_fault.json')) as f:
    JWKS_ERR_1 = json.load(f)


def test_rsa_init(tmpdir):
    path = tmpdir.strpath
    res = rsa_init({
                       'use': ['enc'], 'type': 'RSA', 'size': 1024,
                       'name': os.path.join(path, "rsa_enc")
                   })
    assert res


def test_keybundle_from_local_jwk_file():
    kb = keybundle_from_local_file(
        "file://{}".format(os.path.join(BASE_PATH, "jwk.json")),
        "jwk",
        ["ver", "sig"])
    assert len(kb) == 1
    kj = KeyJar()
    kj.issuer_keys[""] = [kb]
    keys = kj.get_signing_key()
    assert len(keys) == 1
    key = keys[0]
    assert isinstance(key, RSAKey)
    assert key.kid == "abc"


def test_key_export():
    kj = KeyJar()
    url = key_export("http://example.com/keys/", "outbound", "secret",
                     keyjar=kj, sig={"alg": "rsa", "format": ["x509", "jwk"]})

    assert url == "http://example.com/keys/outbound/jwks"

    # Now a jwks should reside in './keys/outbound/jwks'

    kb = KeyBundle(source='file://./keys/outbound/jwks')

    # One key
    assert len(kb) == 1
    # more specifically one RSA key
    assert len(kb.get('RSA')) == 1
    k = kb.get('RSA')[0]
    # For signing
    assert k.use == 'sig'


def test_build_keyjar():
    keys = [
        {"type": "RSA", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    jwks, keyjar, kidd = build_keyjar(keys)
    for key in jwks["keys"]:
        assert "d" not in key  # the JWKS shouldn't contain the private part of the keys

    assert len(keyjar[""]) == 2  # 1 with RSA keys and 1 with EC key

    assert "RSA" in kidd["enc"]
    assert "RSA" in kidd["sig"]
    assert "EC" in kidd["sig"]


def test_build_keyjar_missing(tmpdir):
    keys = [{
                "type": "RSA",
                "key": os.path.join(tmpdir.dirname, "missisng_file"),
                "use": ["enc", "sig"]
            }]

    jwks, keyjar, kidd = build_keyjar(keys)

    assert len(keyjar[""]) == 1

    assert "RSA" in kidd["enc"]
    assert "RSA" in kidd["sig"]


def test_dump_public_jwks():
    keys = [
        {"type": "RSA", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    jwks, keyjar, kidd = build_keyjar(keys)

    kbl = keyjar.issuer_keys['']
    dump_jwks(kbl, 'foo.jwks')
    kb_public = KeyBundle(source='file://./foo.jwks')
    # All RSA keys
    for k in kb_public.keys():
        if k.kty == 'RSA':
            assert not k.d
            assert not k.p
            assert not k.q
        else:  # MUST be 'EC'
            assert not k.d


def test_dump_private_jwks():
    keys = [
        {"type": "RSA", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    jwks, keyjar, kidd = build_keyjar(keys)

    kbl = keyjar.issuer_keys['']
    dump_jwks(kbl, 'foo.jwks', private=True)
    kb_public = KeyBundle(source='file://./foo.jwks')
    # All RSA keys
    for k in kb_public.keys():
        if k.kty == 'RSA':
            assert k.d
            assert k.p
            assert k.q
        else:  # MUST be 'EC'
            assert k.d


class TestKeyBundle(object):
    def test_update(self):
        kc = KeyBundle([{"kty": "oct", "key": "supersecret", "use": "sig"}])
        assert len(kc.get("oct")) == 1
        assert len(kc.get("rsa")) == 0
        assert kc.remote is False
        assert kc.source is None

        kc.update()  # Nothing should happen
        assert len(kc.get("oct")) == 1
        assert len(kc.get("rsa")) == 0
        assert kc.remote is False
        assert kc.source is None

    def test_update_RSA(self):
        kc = keybundle_from_local_file(RSAKEY, "rsa", ["ver", "sig"])
        assert kc.remote is False
        assert len(kc.get("oct")) == 0
        assert len(kc.get("RSA")) == 2

        key = kc.get("RSA")[0]
        assert isinstance(key, RSAKey)

        kc.update()
        assert kc.remote is False
        assert len(kc.get("oct")) == 0
        assert len(kc.get("RSA")) == 2

        key = kc.get("RSA")[0]
        assert isinstance(key, RSAKey)


class TestKeyJar(object):
    def test_keyjar_group_keys(self):
        ks = KeyJar()
        ks[""] = KeyBundle([{"kty": "oct", "key": "a1b2c3d4", "use": "sig"},
                            {"kty": "oct", "key": "a1b2c3d4", "use": "ver"}])
        ks["http://www.example.org"] = KeyBundle([
            {"kty": "oct", "key": "e5f6g7h8", "use": "sig"},
            {"kty": "oct", "key": "e5f6g7h8", "use": "ver"}])
        ks["http://www.example.org"].append(
            keybundle_from_local_file(RSAKEY, "rsa", ["ver", "sig"]))

        verified_keys = ks.verify_keys("http://www.example.org")
        assert len(verified_keys) == 6
        assert len([k for k in verified_keys if k.kty == "oct"]) == 4
        assert len([k for k in verified_keys if k.kty == "RSA"]) == 2

    def test_remove_key(self):
        ks = KeyJar()
        ks[""] = KeyBundle([{"kty": "oct", "key": "a1b2c3d4", "use": "sig"},
                            {"kty": "oct", "key": "a1b2c3d4", "use": "ver"}])
        ks["http://www.example.org"] = [
            KeyBundle([
                {"kty": "oct", "key": "e5f6g7h8", "use": "sig"},
                {"kty": "oct", "key": "e5f6g7h8", "use": "ver"}]),
            keybundle_from_local_file(RSAKEY, "rsa", ["enc", "dec"])
        ]
        ks["http://www.example.com"] = keybundle_from_local_file(RSA0, "rsa",
                                                                 ["enc", "dec"])

        coll = ks["http://www.example.org"]
        # coll is list of KeyBundles
        assert len(coll) == 2
        keys = ks.get_encrypt_key(key_type="RSA",
                                  owner="http://www.example.org")
        assert len(keys) == 1
        _key = keys[0]
        ks.remove_key("http://www.example.org", "RSA", _key)

        coll = ks["http://www.example.org"]
        assert len(coll) == 1  # Only one remaining key
        keys = ks.get_encrypt_key(key_type="rsa",
                                  owner="http://www.example.org")
        assert len(keys) == 0

        keys = ks.verify_keys("http://www.example.com")
        assert len(keys) == 2
        assert len([k for k in keys if k.kty == "oct"]) == 2

        keys = ks.decrypt_keys("http://www.example.org")
        assert keys == []

    def test_get_by_kid(self):
        kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwk",
                                       ["ver", "sig"])
        kj = KeyJar()
        kj.issuer_keys["https://example.com"] = [kb]

        _key = kj.get_key_by_kid("abc", "https://example.com")
        assert _key
        assert _key.kid == "abc"

    def test_get_inactive_ver(self):
        ks = KeyJar()
        ks['http://example.com'] = KeyBundle(
            [{"kty": "oct", "key": "a1b2c3d4", "use": "sig"},
             {"kty": "oct", "key": "a1b2c3d4", "use": "ver"}])
        ks['http://example.com'][0]._keys[1].inactive_since = 1
        key = ks.get_verify_key(owner='http://example.com')
        assert len(key) == 2

    def test_get_inactive_sig(self):
        """get_signing_key cannot return inactive `sig` key."""
        ks = KeyJar()
        ks['http://example.com'] = KeyBundle(
            [{"kty": "oct", "key": "a1b2c3d4", "use": "sig"}])
        ks['http://example.com'][0]._keys[0].inactive_since = 1
        key = ks.get_signing_key(owner='http://example.com')

        assert len(key) == 0

    def test_get_inactive_sig_for_ver(self):
        """get_verify_key can return inactive `sig` key."""
        ks = KeyJar()
        ks['http://example.com'] = KeyBundle(
            [{"kty": "oct", "key": "a1b2c3d4", "use": "sig"}])
        ks['http://example.com'][0]._keys[0].inactive_since = 1
        key = ks.get_verify_key(owner='http://example.com')

        assert len(key) == 1

    def test_dump_issuer_keys(self):
        kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwk",
                                       ["ver", "sig"])
        assert len(kb) == 1
        kj = KeyJar()
        kj.issuer_keys[""] = [kb]
        res = kj.dump_issuer_keys("")

        assert len(res) == 1
        assert res[0] == {
            'use': 'sig',
            'e': 'AQAB',
            'kty': 'RSA',
            'alg': 'RS256',
            'n': 'pKybs0WaHU_y4cHxWbm8Wzj66HtcyFn7Fh3n-99qTXu5yNa30MRYIYfSDwe9JVc1JUoGw41yq2StdGBJ40HxichjE-Yopfu3B58Q'
                 'lgJvToUbWD4gmTDGgMGxQxtv1En2yedaynQ73sDpIK-12JJDY55pvf-PCiSQ9OjxZLiVGKlClDus44_uv2370b9IN2JiEOF-a7JB'
                 'qaTEYLPpXaoKWDSnJNonr79tL0T7iuJmO1l705oO3Y0TQ-INLY6jnKG_RpsvyvGNnwP9pMvcP1phKsWZ10ofuuhJGRp8IxQL9Rfz'
                 'T87OvF0RBSO1U73h09YP-corWDsnKIi6TbzRpN5YDw',
            'kid': 'abc'
        }

    def test_no_use(self):
        kb = KeyBundle(JWK0["keys"])
        kj = KeyJar()
        kj.issuer_keys["abcdefgh"] = [kb]
        enc_key = kj.get_encrypt_key("RSA", "abcdefgh")
        assert enc_key != []

    @pytest.mark.network
    def test_provider(self):
        provider_info = {
            "jwks_uri": "https://connect-op.herokuapp.com/jwks.json",
        }

        ks = KeyJar()
        ks.load_keys(provider_info, "https://connect-op.heroku.com")

        assert ks["https://connect-op.heroku.com"][0].keys()

    @freeze_time("2015-12-31")
    def test_issuer_mismatch(self):
        ISSUER = "https://login.microsoftonline.com/b4ea3de6-839e-4ad1-ae78-c78e5c0cdc06/v2.0/"
        kb = KeyBundle(JWK2["keys"])
        kj = KeyJar()
        kj.issuer_keys[ISSUER] = [kb]
        kj.issuer_keys[""] = []

        authz_resp = AuthorizationResponse().from_urlencoded(
            "id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1u"
            "Q19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiIwMTZlZDBlNC1mYzUyLTRlYjgtOWVhYy1lODg1MmM4MjEwNTUiLCJpc3Mi"
            "OiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vYjRlYTNkZTYtODM5ZS00YWQxLWFlNzgtYzc4ZTVjMGNkYzA2L3YyLjAvI"
            "iwiaWF0IjoxNDM5OTIzNDY5LCJuYmYiOjE0Mzk5MjM0NjksImV4cCI6MTQzOTkyNzM2OSwidmVyIjoiMi4wIiwidGlkIjoiYjRlYTNkZT"
            "YtODM5ZS00YWQxLWFlNzgtYzc4ZTVjMGNkYzA2Iiwib2lkIjoiNDJjMzliNWUtYmQwNS00YTlhLTlhNWUtMTY5ZDc2N2ZlZjJmIiwicHJ"
            "lZmVycmVkX3VzZXJuYW1lIjoiaW50ZXJvcEBrYXV0aS5vbm1pY3Jvc29mdC5jb20iLCJzdWIiOiJFWGlaVldjakpsREN1LXZzOUxNb1V3"
            "ZGRNNEJZZ2ZISzBJNk40dWpXZkRFIiwibmFtZSI6ImludGVyb3AiLCJub25jZSI6IlpkSHRxQWwzR3c4QiJ9.tH4FKM4H9YCHX2XF4V64"
            "SsLaKh31c0oLpEVlFxFHw8jxL5HujUthZJDUMwngXZ2mPU_1G152ybKiRCV9DKaBh1rFSlZxTDBp0SV_YTwOkGYOt-sOzFUJyvVCjGmRh"
            "vFkOF1kiT3IYjDoRh72U8pMchj1duWSytLczdOc4LJmg24ya5jwqApuyQu7gVqoDH1kEqBAuhBj3a7ZDwxIt-bTKZklsht0RutZjv4Ckg"
            "8qJpzWnY7rIjSKFKfEpAAfk_LqWvTktvDMKTHXLxEPVZymoskE1LthtC8AYoNmtVPxgxf87yGCqYZBsuAnVChdnsItXP7tPeqUjC8Lm3J"
            "jabV-5g&id_token_expires_in=3599&state=6o3FmQ0QZl1zifsE&session_state=d2c97e8a-497c-4ce1-bb10-5058501164eb"
        )

        try:
            authz_resp.verify(keyjar=kj, skew=100000000)
        except MissingSigningKey:
            authz_resp.verify(keyjar=kj, sender=ISSUER, skew=100000000)


def test_import_jwks():
    kj = KeyJar()
    kj.import_jwks(JWK1, '')
    assert len(kj.get_issuer_keys('')) == 2


def test_get_signing_key_use_undefined():
    kj = KeyJar()
    kj.import_jwks(JWK1, '')
    keys = kj.get_signing_key(kid='rsa1')
    assert len(keys) == 1

    keys = kj.get_signing_key(key_type='rsa')
    assert len(keys) == 1

    keys = kj.get_signing_key(key_type='rsa', kid='rsa1')
    assert len(keys) == 1


KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]


def test_remove_after():
    # initial keyjar
    keyjar = build_keyjar(KEYDEFS)[1]
    _old = [k.kid for k in keyjar.get_issuer_keys('') if k.kid]
    assert len(_old) == 2

    # rotate_keys = create new keys + make the old as inactive
    keyjar = build_keyjar(KEYDEFS, keyjar=keyjar)[1]

    keyjar.remove_after = 1
    # None are remove since none are marked as inactive yet
    keyjar.remove_outdated()

    _interm = [k.kid for k in keyjar.get_issuer_keys('') if k.kid]
    assert len(_interm) == 4

    # Now mark the keys to be inactivated
    _now = time.time()
    for k in keyjar.get_issuer_keys(''):
        if k.kid in _old:
            if not k.inactive_since:
                k.inactive_since = _now

    with freeze_time(dt.now()) as frozen:
        # this should remove all the old ones
        frozen.tick(delta=timedelta(seconds=2))

        keyjar.remove_outdated()

    # The remainder are the new keys
    _new = [k.kid for k in keyjar.get_issuer_keys('') if k.kid]
    assert len(_new) == 2

    # should not be any overlap between old and new
    assert set(_new).intersection(set(_old)) == set()


def test_load_unknown_keytype():
    kj = KeyJar()
    kj.import_jwks(JWK_UK, '')
    assert len(kj.get_issuer_keys('')) == 1


def test_load_spomky_keys():
    kj = KeyJar()
    kj.import_jwks(JWKS_SPO, '')
    assert len(kj.get_issuer_keys('')) == 4


def test_reload():
    """Emulate what happens if you fetch keys from a remote site and you get back the same JWKS as the last time."""
    _jwks = JWK0

    kb = KeyBundle()
    kb.imp_jwks = _jwks
    kb.do_keys(kb.imp_jwks['keys'])

    assert len(kb) == 1

    kb.do_keys(kb.imp_jwks['keys'])

    assert len(kb) == 1


def test_parse_remote_response(caplog):
    """Test parsing Content-Type header for _parse_remote_response."""
    class FakeResponse():
        def __init__(self, header):
            self.headers = {"Content-Type": header}
            self.text = "{}"

    with caplog.at_level(logging.WARNING, logger='oic.utils.keyio'):
        kb_public = KeyBundle(source='file://./foo.jwks')

        res = FakeResponse('application/json;encoding=utf-8')
        kb_public._parse_remote_response(res)
        assert caplog.record_tuples != [
            ('oic.utils.keyio', logging.WARNING, 'Wrong Content_type')
        ]
        caplog.clear()

        res = FakeResponse('application/json')
        kb_public._parse_remote_response(res)
        assert caplog.record_tuples != [
            ('oic.utils.keyio', logging.WARNING, 'Wrong Content_type')
        ]
        caplog.clear()

        res = FakeResponse('Application/json')
        kb_public._parse_remote_response(res)
        assert caplog.record_tuples != [
            ('oic.utils.keyio', logging.WARNING, 'Wrong Content_type')
        ]
        caplog.clear()

        res = FakeResponse('text/plain')
        kb_public._parse_remote_response(res)
        assert caplog.record_tuples == [
            ('oic.utils.keyio', logging.WARNING, 'Wrong Content_type')
        ]


def test_load_null_jwks():
    kj = KeyJar()
    with pytest.raises(JWKSError):
        kj.import_jwks({'keys': [None, None]}, '')


def test_load_jwks_wrong_argtype():
    kj = KeyJar()
    with pytest.raises(JWKSError):
        kj.import_jwks(JWKS_ERR_1, '')
