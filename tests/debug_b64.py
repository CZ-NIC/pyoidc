from binascii import b2a_hex
import json
import M2Crypto
from M2Crypto.__m2crypto import bn_to_mpi, hex_to_bn
from oic.oauth2 import PBase
from oic.utils.keystore import KeyStore

__author__ = 'rohe0002'

import string
ALPHABET = string.ascii_uppercase + string.ascii_lowercase +\
           string.digits + '-_'
ALPHABET_REVERSE = dict((c, i) for (i, c) in enumerate(ALPHABET))
BASE = len(ALPHABET)
TB = 2**24
foo = '0000 0001 0000 0000 0000 0001'
foo_b64 = "QAB="

import base64
import struct

def bytes( long_int ):
    bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        bytes.insert(0, r)
    return bytes

def long_to_base64(n):
    bys = bytes(n)
    data = struct.pack('%sB' % len(bys), *bys)
    #xdata = struct.pack('<%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip('=')
    return s

def b64_set_to_long(s):
    data = base64.urlsafe_b64decode(s + '==')
    n = struct.unpack('>Q', '\x00'* (8-len(data)) + data )
    return n[0]

def base64_to_long(data):
    #if len(data) % 4: # not a multiple of 4
    #    data += '=' * (4 - (len(data) % 4))

    ld = len(data)
    data = str(data)

    lshift = 8 * (3-(ld % 4))

    res = b64_set_to_long(data[0:4])

    if ld > 4:
        if lshift == 24:
            for i in range(4, ld, 4):
                res = (res << 24) + b64_set_to_long(data[i:i+4])
        else:
            for i in range(4, ld-4, 4):
                res = (res << 24) + b64_set_to_long(data[i:i+4])
            i += 4
            res = (res << lshift) + b64_set_to_long(data[i:i+4])

    return res

def long_to_mpi(num):
    """Converts a python integer or long to OpenSSL MPInt used by M2Crypto.
    Borrowed from Snowball.Shared.Crypto"""
    h = hex(num)[2:] # strip leading 0x in string
    if len(h) % 2 == 1:
        h = '0' + h # add leading 0 to get even number of hexdigits
    return bn_to_mpi(hex_to_bn(h)) # convert using OpenSSL BinNum

def mpi_to_long(mpi):
    """Converts an OpenSSL MPint used by M2Crypto to a python integer/long.
    Borrowed from Snowball.Shared.Crypto"""
    return eval("0x%s" % b2a_hex(mpi[4:]))

s = long_to_base64(65537)
n0 = base64_to_long(s)

assert n0 == 65537

s1 = long_to_base64(16384)
n1 = base64_to_long(s1)

assert n1 == 16384

#print decode("QAB")

foo = b64_set_to_long("Dw==")

mod ="pKybs0WaHU_y4cHxWbm8Wzj66HtcyFn7Fh3n-99qTXu5yNa30MRYIYfSDwe9JVc1JUoGw41yq2StdGBJ40HxichjE-Yopfu3B58QlgJvToUbWD4gmTDGgMGxQxtv1En2yedaynQ73sDpIK-12JJDY55pvf-PCiSQ9OjxZLiVGKlClDus44_uv2370b9IN2JiEOF-a7JBqaTEYLPpXaoKWDSnJNonr79tL0T7iuJmO1l705oO3Y0TQ-INLY6jnKG_RpsvyvGNnwP9pMvcP1phKsWZ10ofuuhJGRp8IxQL9RfzT87OvF0RBSO1U73h09YP-corWDsnKIi6TbzRpN5YDw"

num = base64_to_long(mod)
s2 = long_to_mpi(num)
x = long_to_base64(num)

assert mod == x

# =====================

jwk_url = "https://connect.openid4.us/connect4us.jwk"
x509_url = "https://connect.openid4.us/connect4us.pem"

pb = PBase()
ks = KeyStore(pb.http_request)
#ks.load_jwk(jwk_url, "ver", "a")
#jkey = ks.get_verify_key("rsa", "a")[0]

r = ks.http_request(jwk_url, allow_redirects=True)
spec = json.loads(r.text)

xkey = ks.load_x509_cert(x509_url, "dec", "b")

xkln = mpi_to_long(xkey.n)
xkle = mpi_to_long(xkey.e)

xn = long_to_base64(xkln)
xe = long_to_base64(xkle)

kexp = spec["keys"][0]["exp"]
kmod = spec["keys"][0]["mod"]

assert kmod == xn
assert kexp == xe

le = base64_to_long(kexp)
ln = base64_to_long(kmod)
mpi_e = long_to_mpi(le)
mpi_n = long_to_mpi(ln)

assert xkey.e == mpi_e
assert xkey.n == mpi_n

k = M2Crypto.RSA.new_pub_key((mpi_e, mpi_n))

print len(k)