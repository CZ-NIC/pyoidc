import uuid

from jwkest.jws import factory
from jwkest.jws import NoSuitableSigningKeys
from jwkest.jws import alg2keytype

from oic.oauth2 import Message
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oic.message import SINGLE_REQUIRED_INT
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


class JWTToken(Token):
    def __init__(self, typ, lifetime, iss, sign_alg, keyjar, **kwargs):
        Token.__init__(self, typ, lifetime, **kwargs)
        self.iss = iss
        self.lifetime = lifetime
        self.sign_alg = sign_alg
        self.keyjar = keyjar  # my signing key
        self.db = {}

    def __call__(self, sid, sinfo=None, kid='', **kwargs):
        keys = self.keyjar.get_signing_key(alg2keytype(self.sign_alg),
                                           owner='', kid=kid)

        if not keys:
            raise NoSuitableSigningKeys('kid={}'.format(kid))

        key = keys[0]  # Might be more then one if kid == ''

        rt = ' '.join(sinfo['response_type'])
        try:
            exp = utc_time_sans_frac() + self.lifetime[rt]
        except KeyError:
            exp = utc_time_sans_frac() + self.lifetime['']

        _jti = '{}-{}'.format(self.type, uuid.uuid4().hex)
        _tok = TokenAssertion(
            iss=self.iss,
            azp=sinfo['client_id'],
            sub=sinfo['sub'],
            kid=key.kid,
            exp=exp,
            jti=_jti
        )

        self.db[_jti] = sid

        try:
            _tok['aud'] = kwargs['aud']
        except KeyError:
            pass

        return _tok.to_jwt([key], self.sign_alg)

    def _unpack_jwt(self, token):
        if not token:
            raise KeyError

        _rj = factory(token)
        keys = self.keyjar.get_signing_key(alg2keytype(_rj.jwt.headers['alg']))
        info = _rj.verify_compact(token, keys)
        try:
            sid = self.db[info['jti']]
        except KeyError:
            raise

        return sid, info

    def type_and_key(self, token):
        sid, _ = self._unpack_jwt(token)
        return self.type, sid

    def get_key(self, token):
        sid, _ = self._unpack_jwt(token)
        return sid

    def get_type(self, token):
        self._unpack_jwt(token)
        return self.type

    def expires_at(self):
        return utc_time_sans_frac() + self.lifetime

    def valid(self, token):
        _, info = self._unpack_jwt(token)

        if info['jti'] in self.db:
            if info['exp'] >= utc_time_sans_frac():
                return True

        return False

    def invalidate(self, token):
        _, info = self._unpack_jwt(token)
        del self.db[info['jti']]
