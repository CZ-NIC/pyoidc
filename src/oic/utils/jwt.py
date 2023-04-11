import json
import uuid

from jwcrypto.common import json_encode
from jwcrypto.jwe import JWE as crypto_JWE
from jwcrypto.jws import JWS
from jwcrypto.jws import InvalidJWSObject
from jwcrypto.jws import InvalidJWSSignature
from jwcrypto.jwt import JWT as crypt_JWT
from jwkest import jwe
from jwkest import jws
from jwkest.jws import NoSuitableSigningKeys

from oic.constants import ALLOWED_ALGS
from oic.oic.message import JasonWebToken
from oic.utils.time_util import utc_time_sans_frac

__author__ = "roland"


class JWT(object):
    def __init__(
        self,
        keyjar,
        iss="",
        lifetime=0,
        sign_alg="RS256",
        msgtype=JasonWebToken,
        encrypt=False,
        enc_enc="A128CBC-HS256",
        enc_alg="RSA1_5",
    ):
        self.iss = iss
        self.lifetime = lifetime
        self.sign_alg = sign_alg
        self.keyjar = keyjar  # my signing key
        self.message_type = msgtype
        self.encrypt = encrypt
        self.enc_alg = enc_alg
        self.enc_enc = enc_enc

    def _encrypt(self, payload, cty="JWT"):
        keys = self.keyjar.get_encrypt_key(owner="")
        kwargs = {"alg": self.enc_alg, "enc": self.enc_enc}

        if cty:
            kwargs["cty"] = cty

        # use the clients public key for encryption
        _crypto_jwe = crypto_JWE(payload, json_encode(kwargs), algs=ALLOWED_ALGS)
        for key in keys:
            _crypto_jwe.add_recipient(key)
        return _crypto_jwe.serialize(compact=True)

    def pack_init(self):
        argv = {"iss": self.iss, "iat": utc_time_sans_frac()}
        argv["exp"] = argv["iat"] + self.lifetime
        return argv

    def pack_key(self, owner="", kid=""):
        keys = self.keyjar.get_signing_key(
            jws.alg2keytype(self.sign_alg), owner=owner, kid=kid
        )

        if not keys:
            raise NoSuitableSigningKeys("kid={}".format(kid))

        return keys[0]  # Might be more then one if kid == ''

    def pack(self, kid="", owner="", cls_instance=None, **kwargs):
        _args = self.pack_init()
        if self.sign_alg != "none":
            _key = self.pack_key(owner, kid)
            _args["kid"] = _key.kid
        else:
            _key = None

        try:
            _encrypt = kwargs["encrypt"]
        except KeyError:
            _encrypt = self.encrypt
        else:
            del kwargs["encrypt"]

        _args.update(kwargs)

        if cls_instance:
            cls_instance.update(_args)
            _jwt = cls_instance
        else:
            _jwt = self.message_type(**_args)

        if "jti" in self.message_type.c_param:
            try:
                _jti = kwargs["jti"]
            except KeyError:
                _jti = uuid.uuid4().hex

            _jwt["jti"] = _jti

        _jws = _jwt.to_jwt([_key], self.sign_alg)
        if _encrypt:
            return self._encrypt(_jws)
        else:
            return _jws

    def _verify(self, rj, token):
        _msg = json.loads(rj.objects['payload'])
        if _msg["iss"] == self.iss:
            owner = ""
        else:
            owner = _msg["iss"]

        keys = self.keyjar.get_verify_key(
            jws.alg2keytype(rj.jose_header["alg"]), owner=owner
        )
        allow_none = token.endswith(".")  # No signature, just verify
        for key in keys:
            # Possibly multiple keys... try all of them
            try:
                rj.verify(key, alg=rj.jose_header['alg'])
            except InvalidJWSSignature:
                pass
            else:
                return json.loads(rj.payload.decode())
        raise InvalidJWSSignature()

    def _decrypt(self, token):
        keys = self.keyjar.get_verify_key(owner="")
        ET = crypt_JWT(key=keys[0], jwt=token, expected_type='JWE', algs=ALLOWED_ALGS)
        _rj = JWS().from_jose_token(ET.claims) 
        if not _rj:
            raise KeyError()
        else:
            return self._verify(_rj, msg)

    def unpack(self, token):
        if not token:
            raise KeyError

        try:
            # JWS
            _rj = JWS().from_jose_token(token)
        except InvalidJWSObject:
            # JWT - decrypt first...
            _rj = self._decrypt(token)
        if isinstance(_rj, JWS):
            info = self._verify(_rj, token)
        else:
            # WTF?
            pass

        if self.message_type:
            return self.message_type(**info)
        else:
            return info
