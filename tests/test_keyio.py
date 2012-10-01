__author__ = 'rohe0002'

from binascii import hexlify
from oic.jwt import jwk, jwe
from oic.utils import keyio
from oic.utils.keyio import x509_rsa_loads

def test1():
    jar = keyio.KeyJar(None)
    part,res = jar.key_export("http://example.com/keys/", "outbound", "secret",
                              sig={"alg":"rsa", "format":["x509", "jwk"]})

    print part
    print res

    cert = "keys/outbound/cert.pem"
    jwk_def = "keys/outbound/jwk.json"

    _ckey = x509_rsa_loads(open(cert).read())

    _jkey = jwk.loads(open(jwk_def).read(), {})[0][1]

    _pkey = jar.issuer_keys[""]["ver"][0][1]

    print jwe.hd2ia(hexlify(_ckey.n))
    print jwe.hd2ia(hexlify(_jkey.n))
    print jwe.hd2ia(hexlify(_pkey.n))

    assert _ckey.n == _jkey.n
    assert _ckey.n == _pkey.n