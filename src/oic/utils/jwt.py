"""JSON Web Token"""

# Most of the code herein I have borrowed/stolen from other people
# Most notably Jeff Lindsay, Ryan Kelly

import base64
import json
import re
import os
import urlparse

import M2Crypto
import hashlib
import hmac
import struct
#import binascii
#import rsa

from itertools import izip
from M2Crypto.__m2crypto import hex_to_bn, bn_to_mpi
from M2Crypto.util import no_passphrase_callback

JWT_TYPS = (u"JWT", u"http://openid.net/specs/jwt/1.0")

# XXX Should this be a subclass of ValueError?
class Invalid(Exception):
    """The JWT is invalid."""

class BadSyntax(Invalid):
    """The JWT could not be parsed because the syntax is invalid."""
    def __init__(self, value, msg):
        Invalid.__init__(self)
        self.value = value
        self.msg = msg

    def __str__(self):
        return "%s: %r" % (self.msg, self.value)

class BadSignature(Invalid):
    """The signature of the JWT is invalid."""

class Expired(Invalid):
    """The JWT claim has expired or is not yet valid."""

class UnknownAlgorithm(Invalid):
    """The JWT uses an unknown signing algorithm"""

class BadType(Invalid):
    """The JWT has an unexpected "typ" value."""

class MissingKey(Exception):
    """ No usable key """

def b64e(b):
    u"""Base64 encode some bytes.

    Uses the url-safe - and _ characters, and doesn't pad with = characters."""
    return base64.urlsafe_b64encode(b).rstrip(b"=")

_b64_re = re.compile(b"^[A-Za-z0-9_-]*$")
def b64d(b):
    u"""Decode some base64-encoded bytes.

    Raises BadSyntax if the string contains invalid characters or padding."""

    # Python's base64 functions ignore invalid characters, so we need to
    # check for them explicitly.
    if not _b64_re.match(b):
        raise BadSyntax(b, "base64-encoded data contains illegal characters")

    # add padding chars
    m = len(b) % 4
    if m == 1:
        # NOTE: for some reason b64decode raises *TypeError* if the
        # padding is incorrect.
        raise BadSyntax(b, "incorrect padding")
    elif m == 2:
        b += b"=="
    elif m == 3:
        b += b"="
    return base64.urlsafe_b64decode(b)

def split_token(token):
    if token.count(b".") != 2:
        raise BadSyntax(token, "expected token to contain 2 dots, not %d" % token.count(b"."))
    return tuple(token.split(b"."))

# Stolen from Werkzeug
def safe_str_cmp(a, b):
    """Compare two strings in constant time."""
    if len(a) != len(b):
        return False
    r = 0
    for c, d in izip(a, b):
        r |= ord(c) ^ ord(d)
    return r == 0

def sha256_digest(msg):
    return hashlib.sha256(msg).digest()

def sha384_digest(msg):
    return hashlib.sha384(msg).digest()

def sha512_digest(msg):
    return hashlib.sha512(msg).digest()

def left_hash(msg, func="HS256"):
    """ 128 bits == 16 bytes """
    if func == 'HS256':
        return b64e(sha256_digest(msg)[:16])
    elif func == 'HS384':
        return b64e(sha384_digest(msg)[:24])
    elif func == 'HS512':
        return b64e(sha512_digest(msg)[:32])

def mpint(b):
    b = b"\x00" + b
    return struct.pack(">L", len(b)) + b

def mp2bin(b):
    # just ignore the length...
    if b[4] == '\x00':
        return b[5:]
    else:
        return b[4:]

class Signer(object):
    """Abstract base class for signing algorithms."""
    def sign(self, msg, key):
        """Sign ``msg`` with ``key`` and return the signature."""
        raise NotImplementedError

    def verify(self, msg, sig, key):
        """Return True if ``sig`` is a valid signature for ``msg``."""
        raise NotImplementedError

class HMACSigner(Signer):
    def __init__(self, digest):
        self.digest = digest

    def sign(self, msg, key):
        return hmac.new(key, msg, digestmod=self.digest).digest()

    def verify(self, msg, sig, key):
        if not safe_str_cmp(self.sign(msg, key), sig):
            raise BadSignature(repr(sig))
        return

class RSASigner(Signer):
    def __init__(self, digest, algo):
        self.digest = digest
        self.algo = algo

    def sign(self, msg, key):
        return key.sign(self.digest(msg), self.algo)

    def verify(self, msg, sig, key):
        try:
            return key.verify(self.digest(msg), sig, self.algo)
        except M2Crypto.RSA.RSAError, e:
            raise BadSignature(e)

class ECDSASigner(Signer):
    def __init__(self, digest):
        self.digest = digest

    def sign(self, msg, key):
        r, s = key.sign_dsa(self.digest(msg))
        return mp2bin(r).rjust(32, '\x00') + mp2bin(s).rjust(32, '\x00')

    def verify(self, msg, sig, key):
        # XXX check sig length
        half = len(sig) // 2
        r = mpint(sig[:half])
        s = mpint(sig[half:])
        try:
            r = key.verify_dsa(self.digest(msg), r, s)
        except M2Crypto.EC.ECError, e:
            raise BadSignature(e)
        else:
            if not r:
                raise BadSignature

ALGS = {
    u'HS256': HMACSigner(hashlib.sha256),
    u'HS384': HMACSigner(hashlib.sha384),
    u'HS512': HMACSigner(hashlib.sha512),

    u'RS256': RSASigner(sha256_digest, 'sha256'),
    u'RS384': RSASigner(sha384_digest, 'sha384'),
    u'RS512': RSASigner(sha512_digest, 'sha512'),

    u'ES256': ECDSASigner(sha256_digest),
#    u'AES256': AESEncrypter
    }

def unpack(token):
    """
    Unpacks a JWT into its parts and base64 decodes the parts individually

    :param token: The JWT
    :return: A tuple of the header, claim, crypto parts plus the header
        and claims part before base64 decoding
    """
    if isinstance(token, unicode):
        token = str(token)

    header_b64, claim_b64, crypto_b64 = split_token(token)

    header = b64d(header_b64)
    claim = b64d(claim_b64)
    crypto = b64d(crypto_b64)

    header = json.loads(header)

    return header, claim, crypto, header_b64, claim_b64

def verify(token, dkeys):
    """
    Verifies that a token is correctly signed.

    """
    header, claim, crypto, header_b64, claim_b64 = unpack(token)

    if u'typ' in header:
        if header[u'typ'] not in JWT_TYPS:
            raise BadType(header)

    alg = header[u'alg']
    if alg == "none": # not signed
        return claim
    elif alg not in ALGS:
        raise UnknownAlgorithm(alg)


    sigdata = header_b64 + b'.' + claim_b64

    verifier = ALGS[alg]
    if isinstance(verifier, HMACSigner):
        keys = [str(k) for k in dkeys["hmac"]]
    elif isinstance(verifier, RSASigner):
        keys = dkeys["rsa"]
    else:
        keys = dkeys["ec"]

    if not keys:
        raise MissingKey(alg)

    for key in keys:
        try:
            verifier.verify(sigdata, crypto, key)
            return claim
        except Exception, exc:
            pass

    raise

def check(token, key):
    try:
        verify(token, key)
        return True
    except Invalid:
        return False

def pack(payload):
    """
    Unsigned JWT
    """
    header = {'alg': 'none'}

    header_b64 = b64e(json.dumps(header, separators=(",", ":")))
    if isinstance(payload, basestring):
        payload_b64 = b64e(payload)
    else:
        payload_b64 = b64e(json.dumps(payload, separators=(",", ":")))

    token = header_b64 + b"." + payload_b64 + b"."

    return token

def sign(payload, keys, alg=None):
    """Sign the payload with the given algorithm and key.

    The payload can be any JSON-dumpable object.

    Returns a token string."""

    if not alg or alg.lower() == "none":
        return pack(payload)

    if alg not in ALGS:
        raise UnknownAlgorithm(alg)

    header = {u'alg': alg}
    signer = ALGS[alg]
    if isinstance(signer, HMACSigner):
        key = str(keys["hmac"][0])
    elif isinstance(signer, RSASigner):
        key = keys["rsa"][0]
    else:
        key = keys["ec"][0]

    header_b64 = b64e(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64e(payload)

    token = header_b64 + b"." + payload_b64

    sig = signer.sign(token, key)
    token += b"." + b64e(sig)

    return token


def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file."""
    return M2Crypto.RSA.load_key(filename, M2Crypto.util.no_passphrase_callback)

def rsa_loads(key):
    """Read a PEM-encoded RSA key pair from a string."""
    return M2Crypto.RSA.load_key_string(key,
                                        M2Crypto.util.no_passphrase_callback)

def ec_load(filename):
    return M2Crypto.EC.load_key(filename, M2Crypto.util.no_passphrase_callback)

def x509_rsa_loads(string):
    cert = M2Crypto.X509.load_cert_string(string)
    return cert.get_pubkey().get_rsa()

def jwk_loads(txt):
    """
    Expects something on this form
    {"jwk":
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

    """
    res = {}
    spec = json.loads(txt)
    for kspec in spec["jwk"]:
        if kspec["alg"] == "RSA":
            e = my_b64decode(kspec["exp"])
            n = my_b64decode(kspec["mod"])

            k = M2Crypto.RSA.new_pub_key((long_to_mpi(e), long_to_mpi(n)))

            if "kid" in kspec:
                tag = "%s:%s" % ("rsa", kspec["kid"])
            else:
                tag = "rsa"

            res[tag] = k
        elif kspec["alg"] == "HMAC":
            res["hmac"] = kspec["modulus"]

    return res

def rsa_eq(key1, key2):
    # Check if two RSA keys are in fact the same
    if key1.n == key2.n and key1.e == key2.e:
        return True
    else:
        return False

def key_eq(key1, key2):
    if type(key1) == type(key2):
        if isinstance(key1, basestring):
            return key1 == key2
        elif isinstance(key1, M2Crypto.RSA.RSA):
            return rsa_eq(key1, key2)

    return False

def construct_rsa_jwk(key):
    spec = {
        "alg": "RSA",
        "mod": my_b64encode(mpi_to_long(key.n)),
        "exp": my_b64encode(mpi_to_long(key.e)),
        "use": "sig"
    }
    return spec

def construct_jwk(keys):
    kspecs = []
    for key in keys:
        if isinstance(key, M2Crypto.RSA.RSA):
            kspecs.append(construct_rsa_jwk(key))

    if kspecs:
        return json.dumps({"jwk": kspecs})
    else:
        return None

# ========== base64 encoding/decoding large numbers ====

import string
ALPHABET = string.ascii_uppercase + string.ascii_lowercase +\
           string.digits + '-_'
ALPHABET_REVERSE = dict((c, i) for (i, c) in enumerate(ALPHABET))
BASE = len(ALPHABET)

def my_b64encode(n):
    encoded = ''
    while n > 0:
        n, r = divmod(n, BASE)
        encoded = ALPHABET[int(r)] + encoded

    return encoded

def my_b64decode(data):
    decoded = 0
    for i in range(0, len(data)):
        decoded = (decoded << 6) | ALPHABET_REVERSE[data[i]]
    return decoded

from binascii import b2a_hex

def long_to_mpi(num):
    #Converts a python integer or long to OpenSSL MPInt used by M2Crypto.
    h = hex(num)[2:] # strip leading 0x in string
    if len(h) % 2 == 1:
        h = '0' + h # add leading 0 to get even number of hexdigits
    return bn_to_mpi(hex_to_bn(h)) # convert using OpenSSL BinNum

def mpi_to_long(mpi):
    #Converts an OpenSSL MPint used by M2Crypto to a python integer/long.
    return eval("0x%s" % b2a_hex(mpi[4:]))

#def int2mpint(x):
#    """Convert a Python long integer to a string in OpenSSL's MPINT format."""
#    # MPINT is big-endian bytes with a size prefix.
#    hexbytes = hex(x)[2:].rstrip("L")
#    if len(hexbytes) % 2:
#        hexbytes = "0" + hexbytes
#    bytes = binascii.unhexlify(hexbytes)
#    # Add an extra significant byte that's just zero.  I think this is only
#    # necessary if the number has its MSB set, to prevent it being mistaken
#    # for a sign bit.  I do it uniformly since it's valid and simpler.
#    return struct.pack(">I", len(bytes) + 1) + "\x00" + bytes

# ================= create RSA key ======================

def create_and_store_rsa_key_pair(name="pyoidc", path="."):
    #Seed the random number generator with 1024 random bytes (8192 bits)
    M2Crypto.Rand.rand_seed(os.urandom(1024))

    key = M2Crypto.RSA.gen_key(1024, 65537)

    if not path.endswith("/"):
        path += "/"

    key.save_key('%s%s' % (path, name), None, callback=no_passphrase_callback)
    key.save_pub_key('%s%s.pub' % (path, name))

    return key

def proper_path(path):
    if path.startswith("./"):
        pass
    elif path.startswith("/"):
        path = ".%s" % path
    elif path.startswith("."):
        while path.startswith("."):
            path = path[1:]
        if path.startswith("/"):
            path = ".%s" % path
    else:
        path = "./%s" % path

    if not path.endswith("/"):
        path += "/"

    return path

def key_export(baseurl, local_path, vault, **kwargs):
    part = urlparse.urlsplit(baseurl)

    # deal with the export directory
    if part.path.endswith("/"):
        _path = part.path[:-1]
    else:
        _path = part.path[:]

    local_path = proper_path(local_path)
    vault = proper_path(vault)

    if not os.path.exists(vault):
        os.makedirs(vault)

    if not os.path.exists(local_path):
        os.makedirs(local_path)

    res = {}
    # For each usage type
    # type, usage, format (rsa, sign, jwt)
    for usage in ["sign", "enc"]:
        if usage in kwargs:
            if kwargs[usage] is None:
                continue

            _keys = {}

            if kwargs[usage]["format"] == "jwk":
                if usage == "sign":
                    _name = ("jwk.json", "jwk_url")
                else:
                    _name = ("jwk_enc.json", "jwk_encryption_url")
            else: # must be 'x509'
                if usage == "sign":
                    _name = ("x509.pub", "x509_url")
                else:
                    _name = ("x509_enc.pub", "x509_encryption_url")

            # the local filename
            _local_filename = "%s%s" % (local_path, _name[0])

            if kwargs[usage]["alg"] == "rsa":
                try:
                    _keys["rsa"] = rsa_load('%s%s' % (vault, "pyoidc"))
                except Exception:
                    _keys["rsa"] = create_and_store_rsa_key_pair(path=vault)

            if kwargs[usage]["format"] == "jwk":
                _jwk = []
                for typ, key in _keys.items():
                    if typ == "rsa":
                        _jwk.append(construct_rsa_jwk(key))

                _jwk = {"jwk": _jwk}

                f = open(_local_filename, "w")
                f.write(json.dumps(_jwk))
                f.close()

            keyspec = []
            for typ, key in _keys.items():
                keyspec.append([key, typ, usage])
                if usage == "sign":
                    keyspec.append([key, typ, "verify"])
                if usage == "enc":
                    keyspec.append([key, typ, "dec"])

            if _path:
                _url = "%s://%s%s%s" % (part.scheme, part.netloc, _path,
                                       _local_filename[1:])
            else:
                _url = "%s://%s%s" % (part.scheme, part.netloc,
                                        _local_filename[1:])

            res[_name[1]] = (_url, keyspec)

    return part, res
