__author__ = 'rohe0002'

from oic.utils.keyio import key_export
from oic.utils.keyio import KeyJar
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.keyio import RSA_key


RSAKEY = "../oc3/certs/mycert.key"
RSA0 = "rsa.key"


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_chain_1():
    kc = KeyBundle([{"kty":"hmac", "key":"supersecret", "use":"sig"}])
    assert len(kc.get("hmac")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.remote is False
    assert kc.source is None

    kc.update()  # Nothing should happen
    assert len(kc.get("hmac")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.remote is False
    assert kc.source is None


def test_chain_2():
    kc = keybundle_from_local_file(RSAKEY, "rsa", ["ver","sig"])
    assert kc.remote is False
    assert len(kc.get("hmac")) == 0
    assert len(kc.get("rsa")) == 2

    key = kc.get("rsa")[0]
    assert isinstance(key, RSA_key)

    kc.update()
    assert kc.remote is False
    assert len(kc.get("hmac")) == 0
    assert len(kc.get("rsa")) == 2

    key = kc.get("rsa")[0]
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
    ks[""] = KeyBundle([{"kty": "hmac", "key": "a1b2c3d4", "use": "sig"},
                        {"kty": "hmac", "key": "a1b2c3d4", "use": "ver"}])
    ks["http://www.example.org"] = KeyBundle([
        {"kty": "hmac", "key": "e5f6g7h8", "use": "sig"},
        {"kty": "hmac", "key": "e5f6g7h8", "use": "ver"}])
    ks["http://www.example.org"].append(
        keybundle_from_local_file(RSAKEY, "rsa", ["ver", "sig"]))

    collection = ks.verify_keys("http://www.example.org")

    assert _eq(collection.keys(), ["hmac", "rsa"])


def test_keyjar_remove_key():
    ks = KeyJar()
    ks[""] = KeyBundle([{"kty": "hmac", "key": "a1b2c3d4", "use": "sig"},
                        {"kty": "hmac", "key": "a1b2c3d4", "use": "ver"}])
    ks["http://www.example.org"] = [
        KeyBundle([
            {"kty": "hmac", "key": "e5f6g7h8", "use": "sig"},
            {"kty": "hmac", "key": "e5f6g7h8", "use": "ver"}]),
        keybundle_from_local_file(RSAKEY, "rsa", ["enc", "dec"])
    ]
    ks["http://www.example.com"] = keybundle_from_local_file(RSA0, "rsa",
                                                             ["enc", "dec"])

    coll = ks["http://www.example.org"]
    # coll is list of KeyBundles
    assert len(coll) == 2
    key = ks.get_encrypt_key(key_type="rsa", owner="http://www.example.org")
    keys = key["rsa"]
    assert len(key) == 1
    _key = keys[0]
    ks.remove_key("http://www.example.org", "rsa", _key)

    coll = ks["http://www.example.org"]
    assert len(coll) == 1  # Only one remaining key
    key = ks.get_encrypt_key(key_type="rsa", owner="http://www.example.org")
    assert key == {"rsa": []}

    keys = ks.verify_keys("http://www.example.com")
    assert keys.keys() == ['hmac']

    keys = ks.decrypt_keys("http://www.example.org")
    assert keys == {}
