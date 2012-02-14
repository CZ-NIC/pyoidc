u"""JSON Web Token"""

import base64
import json
import re

import M2Crypto
import hashlib
import hmac

from struct import pack
from itertools import izip

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

def mpint(b):
    b = b"\x00" + b
    return pack(">L", len(b)) + b

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
    }

def unpack(token):
    if isinstance(token, unicode):
        raise TypeError

    header_b64, claim_b64, crypto_b64 = split_token(token)

    header = b64d(header_b64)
    claim = b64d(claim_b64)
    crypto = b64d(crypto_b64)

    header = json.loads(header)

    return header, claim, crypto, header_b64, claim_b64

def verify(token, keys):
    header, claim, crypto, header_b64, claim_b64 = unpack(token)

    if u'typ' in header:
        if header[u'typ'] not in JWT_TYPS:
            raise BadType(header)

    alg = header[u'alg']
    if alg not in ALGS:
        raise UnknownAlgorithm(alg)

    sigdata = header_b64 + b'.' + claim_b64

    verifier = ALGS[alg]
    if isinstance(verifier, HMACSigner):
        keys = str(keys["hmac"])
    elif isinstance(verifier, RSASigner):
        keys = keys["rsa"]
    else:
        keys = keys["ec"]

    if not keys:
        raise MissingKey(alg)

    for key in keys:
        try:
            verifier.verify(sigdata, crypto, key)
            return claim
        except Exception:
            pass

    raise

def check(token, key):
    try:
        verify(token, key)
        return True
    except Invalid:
        return False

def sign(payload, keys, alg):
    """Sign the payload with the given algorithm and key.

    The payload can be any JSON-dumpable object.

    Returns a token string."""

    if alg not in ALGS:
        raise UnknownAlgorithm(alg)

    header = {u'alg': alg}
    signer = ALGS[alg]
    if isinstance(signer, HMACSigner):
        key = str(keys["hmac"])
    elif isinstance(signer, RSASigner):
        key = keys["rsa"]
    else:
        key = keys["ec"]

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