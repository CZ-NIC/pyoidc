"""JSON Web Token"""

# Most of the code herein I have borrowed/stolen from other people
# Most notably Jeff Lindsay, Ryan Kelly

import json
import logging

import M2Crypto
import hashlib
import hmac
import struct

from oic.jwt import b64e
from oic.jwt import safe_str_cmp
from oic.jwt import BadSignature
from oic.jwt import unpack
from oic.jwt import JWT_TYPS
from oic.jwt import BadType
from oic.jwt import UnknownAlgorithm
from oic.jwt import MissingKey
from oic.jwt import Invalid
from oic.jwt import pack

logger = logging.getLogger(__name__)

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

SIGNER_ALGS = {
    u'HS256': HMACSigner(hashlib.sha256),
    u'HS384': HMACSigner(hashlib.sha384),
    u'HS512': HMACSigner(hashlib.sha512),

    u'RS256': RSASigner(sha256_digest, 'sha256'),
    u'RS384': RSASigner(sha384_digest, 'sha384'),
    u'RS512': RSASigner(sha512_digest, 'sha512'),

    u'ES256': ECDSASigner(sha256_digest),
#    u'AES256': AESEncrypter
    }

def alg2keytype(alg):
    if alg.startswith("RS"):
        return "rsa"
    elif alg.startswith("HS"):
        return "hmac"
    elif alg.startswith("ES"):
        return "ec"
    else:
        return None

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
    elif alg not in SIGNER_ALGS:
        raise UnknownAlgorithm(alg)

    sigdata = header_b64 + b'.' + claim_b64

    verifier = SIGNER_ALGS[alg]
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


def sign(payload, keys, alg=None):
    """Sign the payload with the given algorithm and key.

    The payload can be any JSON-dumpable object.

    Returns a token string."""

    if not alg or alg.lower() == "none":
        return pack(payload)

    if alg not in SIGNER_ALGS:
        raise UnknownAlgorithm(alg)

    header = {u'alg': alg}
    signer = SIGNER_ALGS[alg]
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


# =============================================================================

