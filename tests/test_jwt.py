from oic.utils.keystore import rsa_load

__author__ = 'rohe0002'

from oic.utils import jwt

def test_1():
    claimset = {"iss":"joe",
                "exp":1300819380,
                "http://example.com/is_root": True}

    _jwt = jwt.pack(claimset)

    part = jwt.unpack(_jwt)
    print part
    assert part[0] == {u'alg': u'none'}
    assert part[1] == \
           '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}'

def test_hmac_256():
    payload = "Please take a moment to register today"
    keycol = {"hmac": "My hollow echo"}

    _jwt = jwt.sign(payload, keycol, "HS256")

    info = jwt.verify(_jwt, keycol)

    assert info == payload

def test_hmac_384():
    payload = "Please take a moment to register today"
    keycol = {"hmac": "My hollow echo"}

    _jwt = jwt.sign(payload, keycol, "HS384")

    info = jwt.verify(_jwt, keycol)

    assert info == payload

def test_hmac_512():
    payload = "Please take a moment to register today"
    keycol = {"hmac": "My hollow echo"}

    _jwt = jwt.sign(payload, keycol, "HS512")

    info = jwt.verify(_jwt, keycol)

    assert info == payload

def test_left_hash_hs256():
    hsh = jwt.left_hash("Please take a moment to register today")
    assert hsh == "rCFHVJuxTqRxOsn2IUzgvA"

def test_left_hash_hs512():
    hsh = jwt.left_hash("Please take a moment to register today", "HS512")
    assert hsh == "_h6feWLt8zbYcOFnaBmekTzMJYEHdVTaXlDgJSWsEeY"

def test_rs256():
    rsapub = rsa_load("../oc3/certs/mycert.key")

    payload = "Please take a moment to register today"
    keycol = {"rsa": [rsapub]}

    _jwt = jwt.sign(payload, keycol, "RS256")

    info = jwt.verify(_jwt, keycol)

    assert info == payload
