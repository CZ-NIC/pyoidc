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
        _sinfo = kwargs['sinfo']
        exp = self.do_exp(**_sinfo)

        _cid = _sinfo['client_id']
        if 'aud' in kwargs:
            if _cid not in kwargs['aud']:
                kwargs['aud'].append(_cid)
        else:
            kwargs['aud'] = [_cid]

        if 'azr' not in kwargs:
            kwargs['azr'] = _cid

        if 'scope' not in kwargs:
            _scope = None
            try:
                _scope = _sinfo['scope']
            except KeyError:
                ar = json.loads(_sinfo['authzreq'])
                try:
                    _scope = ar['scope']
                except KeyError:
                    pass
            if _scope:
                kwargs['scope'] = ' ' .join(_scope)

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

    def is_valid(self, info):
        if info['jti'] in self.db:
            if info['exp'] >= utc_time_sans_frac():
                return True

        return False

    def valid(self, token):
        info = self.unpack(token)
        return self.is_valid(info)

    def get_info(self, token):
        return self.unpack(token)
