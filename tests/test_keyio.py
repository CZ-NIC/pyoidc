__author__ = 'rohe0002'

from oic.utils.keyio import key_export
from oic.utils.keyio import KeyJar
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.keyio import RSA_key

from jwkest.jws import JWS, NoSuitableSigningKeys


RSAKEY = "../oc3/certs/mycert.key"
RSA0 = "rsa.key"


def _eq(l1, l2):
    return set(l1) == set(l2)


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
    assert isinstance(key, RSA_key)

    kc.update()
    assert kc.remote is False
    assert len(kc.get("oct")) == 0
    assert len(kc.get("RSA")) == 2

    key = kc.get("RSA")[0]
    assert isinstance(key, RSA_key)


# remote testing is tricky
def test1():
    kj = KeyJar()
    url = key_export("http://example.com/keys/", "outbound", "secret",
                     keyjar=kj, sig={"alg": "rsa", "format": ["x509", "jwk"]})

    print url
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
    kb = keybundle_from_local_file("file://jwk.json", "jwk", ["ver", "sig"])
    assert len(kb) == 1
    kj = KeyJar()
    kj.issuer_keys[""] = [kb]
    keys = kj.get_signing_key()
    assert len(keys) == 1
    key = keys[0]
    assert isinstance(key, RSA_key)
    assert key.kid == "abc"


def test_signing():
    kb = keybundle_from_local_file("file://jwk.json", "jwk", ["ver", "sig"])
    assert len(kb) == 1
    kj = KeyJar()
    kj.issuer_keys[""] = [kb]
    keys = kj.get_signing_key()
    payload = "Please take a moment to register today"
    _jws = JWS(payload, alg="RS512")
    try:
        _jwt = _jws.sign_compact(keys)
        assert False
    except NoSuitableSigningKeys:
        assert True


if __name__ == "__main__":
    test_keyjar_remove_key()