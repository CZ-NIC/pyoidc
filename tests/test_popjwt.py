import json

from Cryptodome.PublicKey import RSA
from jwkest.jwe import JWE
from jwkest.jwk import KEYS
from jwkest.jwk import RSAKey

from oic.extension.popjwt import PJWT
from oic.extension.popjwt import PopJWT

__author__ = 'roland'

RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCIc+q8Y+q4qjw/SMMRzwyfJ7IvIQ7Q3WSE+x2Z61bwh4luI65H
zARW3X9NkD8kHAh/Vxaz/wS86FXALTGygoKQ8ETOC7WNz/4g/z9VHowcZPO/jwdT
zfo+2nK3Xg9qSAWF6x5jnSaFsuvcotcrxpke9gVCq+MkEDDzeKOAiHJnNwIDAQAB
AoGANM43HyTDpycqHYt5AiFQTx87k4WFiErFJblQYUpz4K1y/86LGXnYjA03wLp7
1OuMVktLm+iq2rhGxxI2U1CyWfgWnJHfvZgojjcUHd4fRm5U16fzCKgnl3ZtC0fG
mxmpbq1f+h1nhgK4cNi6s3boz+GfdrdT5MvshRRT8z/zINECQQC41xgat9yRAHO2
y9+fqrnOQlSL/uObm8NqmuKPiqJRsqBqGPYuDyeJlx1I3mxkCL7Q/WqmfjFlqIeB
Zp4BnmyFAkEAvPwBzUFylaKLwUVcZmGXbHzo9G4oauRe6Vj+um7eXinz1D+X5ReJ
BHa6Su+4xHOE9myEMZ6P80F+BnLuepH/iwJAMRbGywm7ZTMGiCx61k+kCvgotgla
b1AdxOkfdFmwJBxZZ/P7JV5W9L6SQ3D2vlZoPt6efVsUSVhJrH8RRYLKdQJBALzG
HiahkYvW6jMMzdeW9GLyAuDmiIj9xbDhrNEdnhIBZgZF37x/XeaPklb4TmAt5Esi
6omGEdSzPufCNmVJITECQEDD6V9ojDly//wsTTPykgiXmLiETAH9Ff6I6Zp2g5d7
VcNvzfoQ3BegXbYuJzSFanCWNk/2+9GPptlcdMbGjo4=
-----END RSA PRIVATE KEY-----"""


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_pop_jwk():
    jwt = {
        "iss": "https://server.example.com",
        "aud": "https://client.example.org",
        "exp": 1361398824,
        "cnf": {
            "jwk": {
                "kty": "EC",
                "use": "sig",
                "crv": "P-256",
                "x": "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
                "y": "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
            }
        }
    }
    pjwt = PJWT(**jwt)

    s = pjwt.to_json()

    assert s

    de_pjwt = PJWT().from_json(s)
    assert _eq(de_pjwt.keys(), ['iss', 'aud', 'exp', 'cnf'])
    assert list(de_pjwt['cnf'].keys()) == ['jwk']
    assert _eq(de_pjwt['cnf']['jwk'].keys(), ['kty', 'use', 'crv', 'x', 'y'])


rsa = RSA.importKey(RSA_PRIVATE_KEY)


def test_pop_jwe():
    jwk = {"kty": "oct", "alg": "HS256",
           "k": "ZoRSOrFzN_FzUA5XKMYoVHyzff5oRJxl-IXRtztJ6uE"}

    encryption_keys = [RSAKey(use="enc", key=rsa,
                              kid="some-key-id")]
    jwe = JWE(json.dumps(jwk), alg="RSA-OAEP", enc="A256CBC-HS512")
    _jwe = jwe.encrypt(keys=encryption_keys, kid="some-key-id")

    jwt = {
        "iss": "https://server.example.com",
        "aud": "https://client.example.org",
        "exp": 1361398824,
        "cnf": {
            "jwe": _jwe
        }
    }

    pjwt = PJWT(**jwt)

    s = pjwt.to_json()

    de_pjwt = PJWT().from_json(s)
    assert _eq(de_pjwt.keys(), ['iss', 'aud', 'exp', 'cnf'])
    assert list(de_pjwt['cnf'].keys()) == ['jwe']
    _jwe = de_pjwt['cnf']['jwe']
    msg = jwe.decrypt(_jwe, encryption_keys)
    assert msg

    assert json.loads(msg.decode('utf8')) == jwk


def test_pop_kid():
    jwt = {
        "iss": "https://server.example.com",
        "aud": "https://client.example.org",
        "exp": 1361398824,
        "cnf": {
            "kid": "dfd1aa97-6d8d-4575-a0fe-34b96de2bfad"
        }
    }

    pjwt = PJWT(**jwt)

    s = pjwt.to_json()

    assert s

    de_pjwt = PJWT().from_json(s)
    assert _eq(de_pjwt.keys(), ['iss', 'aud', 'exp', 'cnf'])
    assert list(de_pjwt['cnf'].keys()) == ['kid']
    assert de_pjwt['cnf']['kid'] == jwt['cnf']['kid']  # type: ignore


def test_pop_jku():
    jwt = {
        "iss": "https://server.example.com",
        "sub": "17760704",
        "aud": "https://client.example.org",
        "exp": 1440804813,
        "cnf": {
            "jku": "https://keys.example.net/pop-keys.json",
            "kid": "2015-08-28"
        }
    }

    pjwt = PJWT(**jwt)

    s = pjwt.to_json()

    assert s

    de_pjwt = PJWT().from_json(s)
    assert _eq(de_pjwt.keys(), ['iss', 'sub', 'aud', 'exp', 'cnf'])
    assert _eq(de_pjwt['cnf'].keys(), ['jku', 'kid'])
    assert de_pjwt['cnf'].to_dict() == jwt['cnf']


def test_pjwt_with_jwk():
    pj = PopJWT("https://server.example.com", "https://client.example.org",
                sub='12345678')

    jwk = {
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "x": "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
        "y": "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
    }

    pjwt = pj.pack_jwk(jwk)

    s = pjwt.to_json()

    assert s

    de_pjwt = PJWT().from_json(s)
    assert _eq(de_pjwt.keys(), ['iss', 'aud', 'exp', 'cnf', 'sub', 'iat'])
    assert list(de_pjwt['cnf'].keys()) == ['jwk']
    assert _eq(de_pjwt['cnf']['jwk'].keys(), ['kty', 'use', 'crv', 'x', 'y'])


def test_pjwt_with_jwe():
    pj = PopJWT("https://server.example.com", "https://client.example.org",
                sub='12345678')

    jwk = {"kty": "oct", "alg": "HS256",
           "k": "ZoRSOrFzN_FzUA5XKMYoVHyzff5oRJxl-IXRtztJ6uE"}

    encryption_keys = [RSAKey(use="enc", key=rsa,
                              kid="some-key-id")]
    jwe = JWE(json.dumps(jwk), alg="RSA-OAEP", enc="A256CBC-HS512")
    _jwe = jwe.encrypt(keys=encryption_keys, kid="some-key-id")

    pjwt = pj.pack_jwe(jwe=_jwe)

    s = pjwt.to_json()

    de_pjwt = PJWT().from_json(s)
    assert _eq(de_pjwt.keys(), ['iss', 'aud', 'exp', 'cnf', 'sub', 'iat'])
    assert list(de_pjwt['cnf'].keys()) == ['jwe']
    _jwe = de_pjwt['cnf']['jwe']
    msg = jwe.decrypt(_jwe, encryption_keys)
    assert msg

    assert json.loads(msg.decode('utf8')) == jwk


def test_pjwt_with_jwe_jwk():
    keys = KEYS()
    keys.append(RSAKey(use="enc", key=rsa, kid="some-key-id"))

    jwe = JWE(alg="RSA-OAEP", enc="A256CBC-HS512")

    pj = PopJWT("https://server.example.com", "https://client.example.org",
                sub='12345678', jwe=jwe, keys=keys)

    jwk = {"kty": "oct", "alg": "HS256",
           "k": "ZoRSOrFzN_FzUA5XKMYoVHyzff5oRJxl-IXRtztJ6uE"}

    pjwt = pj.pack_jwe(jwk=jwk, kid='some-key-id')

    s = pjwt.to_json()

    de_pjwt = PJWT().from_json(s)
    assert _eq(de_pjwt.keys(), ['iss', 'aud', 'exp', 'cnf', 'sub', 'iat'])
    assert list(de_pjwt['cnf'].keys()) == ['jwe']
    _jwe = de_pjwt['cnf']['jwe']
    msg = jwe.decrypt(_jwe, keys.keys())
    assert msg

    assert json.loads(msg.decode('utf8')) == jwk


def test_pjwt_with_kid():
    pj = PopJWT("https://server.example.com", "https://client.example.org",
                sub='12345678')

    pjwt = pj.pack_kid('some-key-id')

    s = pjwt.to_json()

    assert s

    de_pjwt = PJWT().from_json(s)
    assert _eq(de_pjwt.keys(), ['iss', 'aud', 'exp', 'cnf', 'sub', 'iat'])
    assert list(de_pjwt['cnf'].keys()) == ['kid']
    assert de_pjwt['cnf']['kid'] == 'some-key-id'


def test_pjwt_unpack_jwk():
    pj = PopJWT("https://server.example.com", "https://client.example.org",
                sub='12345678')

    jwk = {
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "x": "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
        "y": "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
    }

    pjwt = pj.pack_jwk(jwk)

    s = pjwt.to_json()

    _jwt = PopJWT().unpack(s)

    assert _eq(_jwt.keys(), ['iss', 'aud', 'exp', 'cnf', 'sub', 'iat'])
    assert list(_jwt['cnf'].keys()) == ['jwk']
    assert _eq(_jwt['cnf']['jwk'].keys(), ['kty', 'use', 'crv', 'x', 'y'])


def test_pjwt_unpack_jwe():
    keys = KEYS()
    keys.append(RSAKey(use="enc", key=rsa, kid="some-key-id"))

    pj = PopJWT("https://server.example.com", "https://client.example.org",
                sub='12345678')

    jwk = {"kty": "oct", "alg": "HS256",
           "k": "ZoRSOrFzN_FzUA5XKMYoVHyzff5oRJxl-IXRtztJ6uE"}

    jwe = JWE(json.dumps(jwk), alg="RSA-OAEP", enc="A256CBC-HS512")
    _jwe = jwe.encrypt(keys=keys.keys(), kid="some-key-id")

    pjwt = pj.pack_jwe(jwe=_jwe)

    s = pjwt.to_json()

    _jwt = PopJWT(jwe=jwe, keys=keys).unpack(s)

    assert _eq(_jwt.keys(), ['iss', 'aud', 'exp', 'cnf', 'sub', 'iat'])
    assert _eq(_jwt['cnf'].keys(), ['jwk', 'jwe'])

    assert _jwt['cnf']['jwk'] == jwk
