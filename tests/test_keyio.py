import M2Crypto

__author__ = 'rohe0002'

from binascii import hexlify

from jwkest import jwk, jwe
from jwkest.jwk import x509_rsa_loads
from oic.utils.keyio import key_export, KeyJar, KeyBundle

def _eq(l1, l2):
    return set(l1) == set(l2)

def test_chain_1():
    kc = KeyBundle({"hmac": "supersecret"}, usage="sig")
    assert len(kc.get("hmac")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.usage == ["sig"]
    assert kc.remote == False
    assert kc.source is None

    kc.update() # Nothing should happen
    assert len(kc.get("hmac")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.usage == ["sig"]
    assert kc.remote == False
    assert kc.source is None

def test_chain_2():
    kc = KeyBundle(source="file://../oc3/certs/mycert.key", type="rsa",
                  usage=["ver", "sig"])
    assert kc.usage == ["ver", "sig"]
    assert kc.remote == False
    assert kc.source == "../oc3/certs/mycert.key"
    assert len(kc.get("hmac")) == 0
    assert len(kc.get("rsa")) == 1

    key = kc.get("rsa")[0]
    assert isinstance(key, M2Crypto.RSA.RSA)

    kc.update()
    assert kc.usage == ["ver", "sig"]
    assert kc.remote == False
    assert kc.source == "../oc3/certs/mycert.key"
    assert len(kc.get("hmac")) == 0
    assert len(kc.get("rsa")) == 1

    key = kc.get("rsa")[0]
    assert isinstance(key, M2Crypto.RSA.RSA)

def test_chain_3():
    kc = KeyBundle(source="file://../oc3/certs/server.crt", type="rsa",
                  src_type="x509", usage=["sig", "enc"])
    assert kc.usage == ["sig", "enc"]
    assert kc.remote == False
    assert kc.source == "../oc3/certs/server.crt"
    assert len(kc.get("hmac")) == 0
    assert len(kc.get("rsa")) == 1

    key = kc.get("rsa")[0]
    assert isinstance(key, M2Crypto.RSA.RSA)

    kc.update()
    assert kc.usage == ["sig", "enc"]
    assert kc.remote == False
    assert kc.source == "../oc3/certs/server.crt"
    assert len(kc.get("hmac")) == 0
    assert len(kc.get("rsa")) == 1

    key = kc.get("rsa")[0]
    assert isinstance(key, M2Crypto.RSA.RSA)

# remote testing is tricky

def test1():
    kj = KeyJar()
    part,res = key_export("http://example.com/keys/", "outbound", "secret",
                          keyjar=kj,
                          sig={"alg":"rsa", "format":["x509", "jwk"]})

    print part
    print res

    cert = "keys/outbound/cert.pem"
    jwk_def = "keys/outbound/jwk.json"

    _ckey = x509_rsa_loads(open(cert).read())

    _jkey = jwk.loads(open(jwk_def).read())[0][1]


    print jwe.hd2ia(hexlify(_ckey.n))
    print jwe.hd2ia(hexlify(_jkey.n))

    assert _ckey.n == _jkey.n

URL = "https://openidconnect.info/jwk/jwk.json"

def test_keyjar_pairkeys():
    ks = KeyJar()
    ks[""] = KeyBundle({"hmac": "a1b2c3d4"}, usage=["sig", "ver"])
    ks["http://www.example.org"] = KeyBundle({"hmac": "e5f6g7h8"},
                                            usage=["sig", "ver"])
    ks["http://www.example.org"].append(KeyBundle({"rsa": "-rsa-key-"},
                                                 usage=["enc", "dec"]))

    ks["http://www.example.org"].append(KeyBundle({"rsa": "i9j10k11l12"},
                                                 usage=["sig", "ver"]))

    collection = ks.verify_keys("http://www.example.org")

    assert _eq(collection.keys(), ["hmac", "rsa"])


def test_keyjar_remove_key():
    ks = KeyJar()
    ks[""] = KeyBundle({"hmac":"a1b2c3d4"}, usage=["sig", "ver"])
    ks["http://www.example.org"] = [
            KeyBundle({"hmac": "e5f6g7h8"}, usage=["sig", "ver"]),
            KeyBundle({"rsa": "-rsa-key-"}, usage=["enc", "dec"])
    ]
    ks["http://www.example.com"] = KeyBundle({"hmac": "i9j10k11l12"},
                                             usage=["sig", "ver"])

    coll = ks["http://www.example.org"]
    # coll is list of KeyBundles
    assert len(coll) == 2
    key = ks.get_encrypt_key(type="rsa", owner="http://www.example.org")
    assert key == {"rsa": ["-rsa-key-"]}

    ks.remove_key("http://www.example.org", "rsa", "-rsa-key-")

    coll = ks["http://www.example.org"]
    assert len(coll) == 1 # Only one remaining key
    key = ks.get_encrypt_key(type="rsa", owner="http://www.example.org")
    assert key == {"rsa": []}

    keys = ks.verify_keys("http://www.example.com")
    assert keys == {'hmac': ['i9j10k11l12', 'a1b2c3d4']}

    keys = ks.decrypt_keys("http://www.example.org")
    assert keys == {}


