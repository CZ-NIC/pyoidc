import os
import json
from jwkest.jwe import JWE

__author__ = 'rohe0002'

from oic.utils.keyio import key_export
from oic.utils.keyio import KeyJar
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.keyio import RSAKey

from jwkest.jws import JWS, NoSuitableSigningKeys, WrongTypeOfKey

BASE_PATH = os.path.dirname(__file__)

RSAKEY = "%s/cert.key" % BASE_PATH
RSA0 = "%s/rsa.key" % BASE_PATH

JWK0 = {"keys": [
    {'kty': 'RSA', 'e': 'AQAB', 'kid': "abc",
     'n': 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8'}
]}

JWK1 = {"keys": [
    {"n": "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w", "e": "AQAB", "kty": "RSA", "kid": "5-VBFv40P8D4I-7SFz7hMugTbPs"},
    {"k": "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE", "kty": "oct"},
    ]}


def test_chain_1():
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


def test_chain_2():
    kc = keybundle_from_local_file(RSAKEY, "rsa", ["ver","sig"])
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


# remote testing is tricky
def test1():
    kj = KeyJar()
    url = key_export("http://example.com/keys/", "outbound", "secret",
                     keyjar=kj, sig={"alg": "rsa", "format": ["x509", "jwk"]})

    print(url)
    assert url == "http://example.com/keys/outbound/jwks"

URL = "https://openidconnect.info/jwk/jwk.json"

def test_keyjar_pairkeys():
    ks = KeyJar()
    ks[""] = KeyBundle([{"kty": "oct", "key": "a1b2c3d4", "use": "sig"},
                        {"kty": "oct", "key": "a1b2c3d4", "use": "ver"}])
    ks["http://www.example.org"] = KeyBundle([
        {"kty": "oct", "key": "e5f6g7h8", "use": "sig"},
        {"kty": "oct", "key": "e5f6g7h8", "use": "ver"}])
    ks["http://www.example.org"].append(
        keybundle_from_local_file(RSAKEY, "rsa", ["ver", "sig"]))

    collection = ks.verify_keys("http://www.example.org")
    assert len(collection) == 3
    assert len([k for k in collection if k.kty == "oct"]) == 2
    assert len([k for k in collection if k.kty == "RSA"]) == 1


def test_keyjar_remove_key():
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
    keys = ks.get_encrypt_key(key_type="RSA", owner="http://www.example.org")
    assert len(keys) == 1
    _key = keys[0]
    ks.remove_key("http://www.example.org", "RSA", _key)

    coll = ks["http://www.example.org"]
    assert len(coll) == 1  # Only one remaining key
    keys = ks.get_encrypt_key(key_type="rsa", owner="http://www.example.org")
    assert len(keys) == 0

    keys = ks.verify_keys("http://www.example.com")
    assert len(keys) == 1
    assert len([k for k in keys if k.kty == "oct"]) == 1

    keys = ks.decrypt_keys("http://www.example.org")
    assert keys == []


def test_local_jwk_file():
    kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwk", ["ver", "sig"])
    assert len(kb) == 1
    kj = KeyJar()
    kj.issuer_keys[""] = [kb]
    keys = kj.get_signing_key()
    assert len(keys) == 1
    key = keys[0]
    assert isinstance(key, RSAKey)
    assert key.kid == "abc"


def test_signing():
    # Signing is only possible if key is a private RSA key
    kb = keybundle_from_local_file("%s/rsa.key" % BASE_PATH, "rsa", ["ver", "sig"])
    assert len(kb) == 2
    kj = KeyJar()
    kj.issuer_keys[""] = [kb]
    keys = kj.get_signing_key()
    payload = "Please take a moment to register today"
    _jws = JWS(payload, alg="RS512")
    try:
        _jwt = _jws.sign_compact(keys)
        assert True
    except (NoSuitableSigningKeys, WrongTypeOfKey):
        assert False


def test_kid_usage():
    kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwk", ["ver", "sig"])
    kj = KeyJar()
    kj.issuer_keys["https://example.com"] = [kb]

    _key = kj.get_key_by_kid("abc", "https://example.com")
    assert _key
    assert _key.kid == "abc"


def test_dump_own_keys():
    kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwk",
                                   ["ver", "sig"])
    assert len(kb) == 1
    kj = KeyJar()
    kj.issuer_keys[""] = [kb]
    res = kj.dump_issuer_keys("")

    print(res)
    assert len(res) == 1
    assert res[0] == {
        'use': u'sig',
        'e': b'AQAB',
        'kty': u'RSA',
        'alg': u'RS256',
        'n': b'pKybs0WaHU_y4cHxWbm8Wzj66HtcyFn7Fh3n-99qTXu5yNa30MRYIYfSDwe9JVc1JUoGw41yq2StdGBJ40HxichjE-Yopfu3B58QlgJvToUbWD4gmTDGgMGxQxtv1En2yedaynQ73sDpIK-12JJDY55pvf-PCiSQ9OjxZLiVGKlClDus44_uv2370b9IN2JiEOF-a7JBqaTEYLPpXaoKWDSnJNonr79tL0T7iuJmO1l705oO3Y0TQ-INLY6jnKG_RpsvyvGNnwP9pMvcP1phKsWZ10ofuuhJGRp8IxQL9RfzT87OvF0RBSO1U73h09YP-corWDsnKIi6TbzRpN5YDw',
        'kid': u'abc'}


def test_no_use():
    kb = KeyBundle(JWK0["keys"])
    kj = KeyJar()
    kj.issuer_keys["abcdefgh"] = [kb]
    enc_key = kj.get_encrypt_key("RSA", "abcdefgh")
    assert enc_key != []


def test_enc_hmac():
    payload = {'nonce': 'CYeHPyA6Kmr_jy5HDHXykznu2BpDLm8ngbIJvhBoupI,',
               'sub': 'diana', 'iss': 'https://xenosmilus2.umdc.umu.se:8091/',
               'acr': '2', 'exp': 1401176001, 'iat': 1401096801,
               'aud': ['ApB7TBoKV1tV']}

    _jwe = JWE(json.dumps(payload), alg="A128KW", enc="A128CBC-HS256")

    kb = KeyBundle(JWK1["keys"])
    kj = KeyJar()
    kj.issuer_keys["abcdefgh"] = [kb]
    keys = kj.get_encrypt_key(owner="abcdefgh")

    _enctxt = _jwe.encrypt(keys, context="public")
    assert _enctxt

    # and now for decryption

    msg, state = _jwe.decrypt(_enctxt, keys)

    assert json.loads(msg.decode()) == payload

if __name__ == "__main__":
    test_dump_own_keys()