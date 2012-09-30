import base64
import struct
import logging
import json
import M2Crypto

from binascii import b2a_hex
from M2Crypto.__m2crypto import hex_to_bn, bn_to_mpi

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)

def bytes( long_int ):
    bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        bytes.insert(0, r)
    return bytes

def long_to_base64(n):
    bys = bytes(n)
    data = struct.pack('%sB' % len(bys), *bys)
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
            i = 0
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

def dicthash(d):
    return hash(repr(sorted(d.items())))

def kspec(key, usage):
    return {
        "alg": "RSA",
        "mod": long_to_base64(mpi_to_long(key.n)),
        "exp": long_to_base64(mpi_to_long(key.e)),
        "use": usage
    }

# =============================================================================

def loads(txt, spec2key):
    """
    Load and create keys from a JWK representation

    Expects something on this form
    {"keys":
        [
            {"alg":"EC",
             "crv":"P-256",
             "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use":"enc",
            "kid":"1"},

            {"alg":"RSA",
            "mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb....."
            "exp":"AQAB",
            "kid":"2011-04-29"}
        ]
    }

    :param txt: The JWK string representation
    :return: list of tuples containing key, type, usage owner
    """
    spec = json.loads(txt)
    res = []
    for kspec in spec["keys"]:
        if kspec["alg"] == "RSA":
            try:
                k = spec2key[dicthash(kspec)]
            except KeyError:
                e = base64_to_long(kspec["exp"])
                n = base64_to_long(kspec["mod"])

                k = M2Crypto.RSA.new_pub_key((long_to_mpi(e),
                                              long_to_mpi(n)))
                spec2key[dicthash(kspec)] = k

            #                if "kid" in kspec:
            #                    tag = "%s:%s" % ("rsa", kspec["kid"])
            #                else:
            #                    tag = "rsa"

            res.append((k, "rsa"))
        elif kspec["alg"] == "HMAC":
            res.append((kspec["mod"], "hmac"))

    return res

def dumps(keys, use=""):
    """
    Dump to JWK string representation

    :param keys: The keys to dump
    :param use: What the key are expected to be use for
    :return: The JWK string representation or None
    """
    kspecs = []
    for key in keys:
        if isinstance(key, M2Crypto.RSA.RSA):
            kspecs.append(kspec(key, use))

    if kspecs:
        return json.dumps({"keys": kspecs})
    else:
        return None
