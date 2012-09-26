# JSON Web Encryption
# Implemented
# draft-ietf-jose-json-web-encryption-05

import json
import os
import M2Crypto
import cStringIO
import hashlib
import logging

from binascii import unhexlify
from binascii import hexlify

from oic.jwt import b64d
from oic.jwt import b64e
from oic.jwt.gcm import gcm_encrypt
from oic.jwt.gcm import gcm_decrypt
from oic.jwt.jws import SIGNER_ALGS

logger = logging.getLogger(__name__)

__author__ = 'rohe0002'

ENC = 1
DEC = 0

class CannotDecode(Exception):
    pass

class NotSupportedAlgorithm(Exception):
    pass

class MethodNotSupported(Exception):
    pass


# ---------------------------------------------------------------------------
# Helper functions
def intarr2bin(arr):
    return unhexlify(''.join(["%02x" % byte for byte in arr]))

def intarr2long(arr):
    return long(''.join(["%02x" % byte for byte in arr]), 16)

def hd2ia(s):
    #half = len(s)/2
    return [int(s[i]+s[i+1], 16) for i in range(0,  len(s), 2)]

def dehexlify(bi):
    s = hexlify(bi)
    return [int(s[i]+s[i+1], 16) for i in range(0,len(s),2)]

# ---------------------------------------------------------------------------
# Base class
class Encrypter(object):
    """Abstract base class for encryption algorithms."""

    def __init__(self):
        pass

    def public_encrypt(self, msg, key):
        """Encrypt ``msg`` with ``key`` and return the encrypted message."""
        raise NotImplementedError

    def public_decrypt(self, msg, key):
        """Return decrypted message."""
        raise NotImplementedError

class RSAEncrypter(Encrypter):

    def public_encrypt(self, msg, key, padding="pkcs1_padding"):
        p = getattr(M2Crypto.RSA, padding)
        return key.public_encrypt(msg, p)

    def private_decrypt(self, msg, key, padding="pkcs1_padding"):
        p = getattr(M2Crypto.RSA, padding)
        try:
            return key.private_decrypt(msg, p)
        except M2Crypto.RSA.RSAError, e:
            raise CannotDecode(e)

# ---------------------------------------------------------------------------

def key_derivation(cmk, label, round=1, length=128, hashsize=256):
    """

    :param cmk: Content Master Key
    :param label: The label
    :param round: which round. An int (1-)
    :param length: length of the return digest
    :param hashsize:
    :return: a hash
    """
    be1 = [0,0,0,round]
    r = be1
    r.extend(cmk)
    r.extend(label)
    if hashsize == 256:
        hv = hashlib.sha256(intarr2bin(r))
    elif hashsize == 384:
        hv = hashlib.sha384(intarr2bin(r))
    elif hashsize == 512:
        hv = hashlib.sha512(intarr2bin(r))
    else:
        raise Exception("Unsupported hash length")

    hd = hv.hexdigest()

    return hd[:(length/4)]

def get_cek(cmk, round=1, length=128, hashsize=256):
    return key_derivation(cmk,
                          [69, 110, 99, 114, 121, 112, 116, 105, 111, 110],
                          round=round,
                          length=length,
                          hashsize=hashsize)

def get_cik(cmk, round=1, length=256, hashsize=256):
    return key_derivation(cmk,
                          [73, 110, 116, 101, 103, 114, 105, 116, 121],
                          round=round,
                          length=length,
                          hashsize=hashsize)

# ---------------------------------------------------------------------------

def cipher_filter(cipher, inf, outf):
    while 1:
        buf=inf.read()
        if not buf:
            break
        outf.write(cipher.update(buf))
    outf.write(cipher.final())
    return outf.getvalue()

def aes_enc(key, str):
    pbuf=cStringIO.StringIO(str)
    cbuf=cStringIO.StringIO()
    ciphertext = cipher_filter(key, pbuf, cbuf)
    pbuf.close()
    cbuf.close()
    return ciphertext

def aes_dec(key, ciptxt):
    pbuf=cStringIO.StringIO()
    cbuf=cStringIO.StringIO(ciptxt)
    plaintext=cipher_filter(key, cbuf, pbuf)
    pbuf.close()
    cbuf.close()
    return plaintext

def keysize(spec):
    if spec.startswith("HS"):
        return int(spec[2:])
    elif spec.startswith("CS"):
        return int(spec[2:])
    elif spec.startswith("A"):
        return int(spec[1:4])
    return 0

ENC2ALG = {"A128CBC": "aes_128_cbc", "A256CBC": "aes_256_cbc"}

SUPPORTED = {
    "alg": ["RSA1_5", "RSA-OAEP"],
    "enc": ["A128CBC", "A256CBC", "A256GCM"],
    "int": ["HS256", "HS384", "HS512"]
}
# ---------------------------------------------------------------------------

def rsa_encrypt(msg, key, alg="RSA-OAEP", enc="A256GCM", int="HS256",
                kdf="CS256", iv="", cmk=""):

    # content master key 256 bit
    if not cmk:
        cmk = os.urandom(32)

    encrypter = RSAEncrypter()

    if alg == "RSA-OAEP":
        ek = encrypter.public_encrypt(cmk, key, 'pkcs1_oaep_padding')
    elif alg == "RSA1_5":
        ek = encrypter.public_encrypt(cmk, key)
    else:
        raise NotSupportedAlgorithm(alg)


    if enc == "A256GCM":
        if not iv:
            iv = os.urandom(12) # 96 bits
        header = json.dumps({"alg":alg, "enc":enc, "iv": b64e(iv)})
        auth_data = b64e(header) + b'.' + b64e(ek)
        ctxt, tag = gcm_encrypt(cmk, iv, msg, auth_data)
        res = auth_data + b'.' + b64e(ctxt)
    elif enc=="A128CBC" or enc=="A256CBC":
        if not iv:
            iv = os.urandom(16) # 128 bits
        _dc = hd2ia(hexlify(cmk))
        cek = get_cek(_dc, length=keysize(enc), hashsize=keysize(kdf))
        cik = get_cik(_dc, length=keysize(int), hashsize=keysize(kdf))
        #logger.info("iv: %s" % dehexlify(iv))
        #logger.info("cek: %s" % cek)
        c = M2Crypto.EVP.Cipher(alg=ENC2ALG[enc], key=cek, iv=iv, op=ENC)
        ctxt = aes_enc(c, msg)
        #t = None
        header = json.dumps({"alg":alg, "enc":enc, "iv": b64e(iv),
                             "int": int})
        res = b64e(header) + b'.' + b64e(ek) + b'.' + b64e(ctxt)
        signer = SIGNER_ALGS[int]
        tag = signer.sign(res, cik)
        #logger.info("t: %s" % hexlify(t))
    else:
        raise NotSupportedAlgorithm(enc)

    res += b'.' + b64e(tag)
    return res

def rsa_decrypt(token, key):
    """
    Does decryption according to the JWE proposal

    :param token: The
    :param key:
    :return:
    """
    header, ek, ctxt, tag = token.split(b".")
    dic = json.loads(b64d(header))
    iv = b64d(str(dic["iv"]))
    encrypter = RSAEncrypter()

    jek = b64d(ek)
    if dic["alg"] == "RSA-OAEP":
        cmk = encrypter.private_decrypt(jek, key, 'pkcs1_oaep_padding')
    elif dic["alg"] == "RSA1_5":
        cmk = encrypter.private_decrypt(jek, key)
    else:
        raise NotSupportedAlgorithm(dic["alg"])

    if dic["enc"] == "A256GCM":
        auth_data = header + b'.' + ek
        msg = gcm_decrypt(cmk, iv, b64d(ctxt), auth_data, b64d(tag))
    elif dic["enc"]=="A128CBC" or dic["enc"]=="A256CBC":
        try:
            kdf = dic["kdf"]
        except KeyError:
            kdf = "CS256"

        _dc = hd2ia(hexlify(cmk))
        cek = get_cek(_dc, length=keysize(dic["enc"]), hashsize=keysize(kdf))
        cik = get_cik(_dc, length=keysize(dic["int"]), hashsize=keysize(kdf))

        c = M2Crypto.EVP.Cipher(alg=ENC2ALG[dic["enc"]], key=cek, iv=iv,
                                op=DEC)

        msg = aes_dec(c, b64d(ctxt))
        verifier = SIGNER_ALGS[dic["int"]]
        verifier.verify(header + b'.' + ek + b'.' + ctxt, b64d(tag), cik)
    else:
        raise MethodNotSupported(dic["enc"])

    return msg

# =============================================================================

def encrypt(payload, keys, alg, enc, **kwargs):
    if alg.startswith("RSA") and alg in ["RSA-OAEP", "RSA1_5"]:
        encrypter = rsa_encrypt
        key = keys["rsa"][0]
    else:
        raise NotSupportedAlgorithm

    token = encrypter(payload, key, alg, enc, **kwargs)

    return token

def decrypt(token, dkeys):

    header, ek, ctxt, tag = token.split(b".")
    dic = json.loads(b64d(header))

    if dic["alg"].startswith("RSA") and dic["alg"] in ["RSA-OAEP", "RSA1_5"]:
        decrypter = rsa_decrypt
        keys = dkeys["rsa"]
    else:
        raise NotSupportedAlgorithm


    for key in keys:
        try:
            msg = decrypter(token, key)
            return msg
        except KeyError:
            pass

    raise