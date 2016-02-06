import json
from Crypto.PublicKey import RSA
from oic.extension.popjwt import PJWT, PopJWT
from jwkest.jwe import JWE
from jwkest.jwk import RSAKey, KEYS

__author__ = 'roland'


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


rsa = RSA.importKey(open('rsa_enc', 'r').read())


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
    assert de_pjwt['cnf']['kid'] == jwt['cnf']['kid']


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
