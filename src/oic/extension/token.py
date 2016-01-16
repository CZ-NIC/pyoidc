import json
import uuid
from jwkest import jws
from jwkest import jwe

from jwkest.jwe import JWE

from jwkest.jws import NoSuitableSigningKeys
from jwkest.jws import alg2keytype

from oic.oauth2 import Message
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oic.message import SINGLE_REQUIRED_INT
from oic.utils.jwt import JWT
from oic.utils.sdb import Token

from oic.utils.time_util import utc_time_sans_frac

__author__ = 'roland'


class TokenAssertion(Message):
    c_param = {
        "iss": SINGLE_REQUIRED_STRING,
        "azp": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        'kid': SINGLE_REQUIRED_STRING,
        "exp": SINGLE_REQUIRED_INT,
        'jti': SINGLE_REQUIRED_STRING,
        "aud": OPTIONAL_LIST_OF_STRINGS,  # Array of strings or string
    }


# class JWTToken(Token):
#     def __init__(self, typ, lifetime, iss, sign_alg, keyjar, encrypt=False,
#                  **kwargs):
#         Token.__init__(self, typ, lifetime, **kwargs)
#         self.iss = iss
#         self.lifetime = lifetime
#         self.sign_alg = sign_alg
#         self.keyjar = keyjar  # my signing key
#         self.db = {}
#         self.encrypt = encrypt
#         self.enc_alg = ''
#         self.enc_enc = ''
#         if encrypt:
#             for key, val in {'enc_alg': "RSA1_5",
#                              'enc_enc': "A128CBC-HS256"}.items():
#                 try:
#                     setattr(self, key, kwargs['enc_alg'])
#                 except KeyError:
#                     setattr(self, key, val)
#
#     def _encrypt(self, payload, cty='JWT'):
#         keys = self.keyjar.get_encrypt_key(owner='')
#         kwargs = {"alg": self.enc_alg, "enc": self.enc_enc}
#
#         if cty:
#             kwargs["cty"] = cty
#
#         # use the clients public key for encryption
#         _jwe = JWE(payload, **kwargs)
#         return _jwe.encrypt(keys, context="public")
#
#     def __call__(self, sid, sinfo=None, kid='', **kwargs):
#         keys = self.keyjar.get_signing_key(alg2keytype(self.sign_alg),
#                                            owner='', kid=kid)
#
#         if not keys:
#             raise NoSuitableSigningKeys('kid={}'.format(kid))
#
#         key = keys[0]  # Might be more then one if kid == ''
#
#         rt = ' '.join(sinfo['response_type'])
#         try:
#             exp = utc_time_sans_frac() + self.lifetime[rt]
#         except KeyError:
#             exp = utc_time_sans_frac() + self.lifetime['']
#
#         _jti = '{}-{}'.format(self.type, uuid.uuid4().hex)
#         _tok = TokenAssertion(
#             iss=self.iss,
#             azp=sinfo['client_id'],
#             sub=sinfo['sub'],
#             kid=key.kid,
#             exp=exp,
#             jti=_jti
#         )
#
#         self.db[_jti] = sid
#
#         try:
#             _tok['aud'] = kwargs['aud']
#         except KeyError:
#             pass
#
#         _jws = _tok.to_jwt([key], self.sign_alg)
#         if self.encrypt:
#             return self._encrypt(_jws)
#         else:
#             return _jws
#
#     def _verify(self, rj, token):
#         _msg = json.loads(rj.jwt.part[1].decode('utf8'))
#         if _msg['iss'] == self.iss:
#             owner = ''
#         else:
#             owner = _msg['iss']
#
#         keys = self.keyjar.get_signing_key(alg2keytype(rj.jwt.headers['alg']),
#                                            owner=owner)
#         return rj.verify_compact(token, keys)
#
#     def decrypt(self, rj, token):
#         keys = self.keyjar.get_verify_key(owner='')
#         msg = rj.decrypt(token, keys)
#         _rj = jws.factory(msg)
#         if not _rj:
#             raise KeyError()
#         else:
#             return self._verify(_rj, msg)
#
#     def _unpack_jwt(self, token, only_info=False):
#         if not token:
#             raise KeyError
#
#         _rj = jws.factory(token)
#         if _rj:
#             info = self._verify(_rj, token)
#         else:
#             _rj = jwe.factory(token)
#             if not _rj:
#                 raise KeyError()
#             info = self.decrypt(_rj, token)
#
#         if only_info:
#             return info
#
#         try:
#             sid = self.db[info['jti']]
#         except KeyError:
#             raise
#
#         return sid, info
#
#     def type_and_key(self, token):
#         sid, _ = self._unpack_jwt(token)
#         return self.type, sid
#
#     def get_key(self, token):
#         sid, _ = self._unpack_jwt(token)
#         return sid
#
#     def get_type(self, token):
#         self._unpack_jwt(token)
#         return self.type
#
#     def expires_at(self):
#         return utc_time_sans_frac() + self.lifetime
#
#     def valid(self, token):
#         _, info = self._unpack_jwt(token)
#
#         if info['jti'] in self.db:
#             if info['exp'] >= utc_time_sans_frac():
#                 return True
#
#         return False
#
#     def invalidate(self, token):
#         _, info = self._unpack_jwt(token)
#         del self.db[info['jti']]
#
#     def get_info(self, token):
#         return self._unpack_jwt(token, only_info=True)


class JWTToken(Token, JWT):
    def __init__(self, typ, keyjar, lifetime, **kwargs):
        self.type = typ
        JWT.__init__(self, keyjar, lifetime=lifetime, msgtype=TokenAssertion,
                     **kwargs)
        Token.__init__(self, typ, lifetime=lifetime, **kwargs)
        self.db = {}
        self.session_info = {}
        self.exp_args = ['sinfo']

    def __call__(self, sid, *args, **kwargs):
        """
        Return a token.

        :return:
        """
        exp = self.do_exp(**kwargs['sinfo'])
        del kwargs['sinfo']
        _jti = '{}-{}'.format(self.type, uuid.uuid4().hex)
        _jwt = self.pack(sid=sid, jti=_jti, exp=exp, **kwargs)
        self.db[_jti] = sid
        return _jwt

    def do_exp(self, **kwargs):
        rt = ' '.join(kwargs['response_type'])
        try:
            return utc_time_sans_frac() + self.lifetime[rt]
        except KeyError:
            return utc_time_sans_frac() + self.lifetime['']

    def type_and_key(self, token):
        """
        Return type of Token (A=Access code, T=Token, R=Refresh token) and
        the session id.

        :param token: A token
        :return: tuple of token type and session id
        """
        msg = self.unpack(token)
        return self.type, self.db[msg['jti']]

    def get_key(self, token):
        """
        Return session id

        :param token: A token
        :return: The session id
        """
        msg = self.unpack(token)
        return self.db[msg['jti']]

    def get_type(self, token):
        """
        Return token type

        :param token: A token
        :return: Type of Token (A=Access code, T=Token, R=Refresh token)
        """
        self.unpack(token)
        return self.type

    def invalidate(self, token):
        info = self.unpack(token)
        del self.db[info['jti']]

    def valid(self, token):
        info = self.unpack(token)

        if info['jti'] in self.db:
            if info['exp'] >= utc_time_sans_frac():
                return True

        return False

    def get_info(self, token):
        return self.unpack(token)
