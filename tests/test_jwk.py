from binascii import hexlify
import M2Crypto
from oic.jwt import jwe
from oic.utils.keyio import x509_rsa_loads
from oic.jwt.jwk import kspec, base64_to_long, long_to_mpi

__author__ = 'rohe0002'

def test_1():
    cert = "keys/outbound/cert.pem"

    _ckey = x509_rsa_loads(open(cert).read())
    _jwk = kspec(_ckey, "foo")

    e = base64_to_long(_jwk["exp"])
    n = base64_to_long(_jwk["mod"])

    _jkey = M2Crypto.RSA.new_pub_key((long_to_mpi(e), long_to_mpi(n)))

    cn = jwe.hd2ia(hexlify(_ckey.n))
    jn = jwe.hd2ia(hexlify(_jkey.n))

    assert cn == jn