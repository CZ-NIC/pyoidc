import json
from Crypto.PublicKey import RSA
from future.backports.urllib.parse import urlparse
from future.backports.urllib.parse import parse_qs
from jwkest import b64e
from jwkest.jwk import RSAKey, load_jwks
from oic.utils.keyio import KeyBundle
from oic.extension.signed_http_req import SignedHttpRequest
from oic.utils.jwt import JWT
from oic.extension.message import TokenIntrospectionResponse

__author__ = 'roland'


def sign_http_args(method, url, headers, body=''):
    p = urlparse(url)

    kwargs = {'path': p.path, 'host': p.netloc, 'headers': headers,
              'method': method}

    if body:
        kwargs['body'] = body

    query_params = parse_qs(p.query)
    kwargs['query_params'] = query_params
    return kwargs


class PoPClient(object):
    def __init__(self, key_size=2048, sign_alg='RS256'):
        self.key_size = key_size
        self.state2key = {}
        self.token2key = {}
        self.alg = sign_alg

    def update(self, msg, state, key_size=0):
        """
        Used to 'update' the AccessToken Request

        :param msg:
        :param state: Used to map access token response to this request
        :param key_size:
        :return:
        """
        if not key_size:
            key_size = self.key_size

        key = RSAKey(key=RSA.generate(key_size))
        self.state2key[state] = key
        msg['key'] = json.dumps(key.serialize())
        return msg

    def handle_access_token_response(self, resp):
        """
        Maps access token to a keypair
        :param resp: AccessTokenResponse instance
        """

        self.token2key[resp['access_token']] = self.state2key[resp['state']]

    def auth_token(self, method, access_token, url, headers, body=''):
        kwargs = sign_http_args(method, url, headers, body)
        shr = SignedHttpRequest(self.token2key[access_token])
        return shr.sign(alg=self.alg, **kwargs)


class PoPAS(object):
    def __init__(self, me):
        self.fingerprint2key = {}
        self.keyjar = None
        self.me = me

    def store_key(self, key):
        kb = KeyBundle()
        kb.do_keys([key])

        # Store key with fingerprint as key
        key_fingerprint = b64e(kb.keys()[0].fingerprint('SHA-256')).decode(
            'utf8')
        self.fingerprint2key[key_fingerprint] = key
        return key_fingerprint

    def create_access_token(self, key_fingerprint):
        # creating the access_token
        jwt_constructor = JWT(self.keyjar, iss=self.me)
        # Audience is myself
        return jwt_constructor.pack(
            kid='abc', cnf={'kid': key_fingerprint}, aud=self.me)

    def token_introspection(self, token):
        jwt_constructor = JWT(self.keyjar, iss=self.me)
        res = jwt_constructor.unpack(token)

        tir = TokenIntrospectionResponse(active=True)
        tir['key'] = json.dumps(self.fingerprint2key[res['cnf']['kid']])

        return tir


class PoPRS(object):
    def __init__(self):
        self.token2key = {}

    def store_key(self, access_token, tir):
        """
        Store key that was returned in response from token introspection
        :param access_token: The token that was introspected
        :param tir: TokenIntrospectionResponse instance
        """
        key = load_jwks(json.dumps({'keys': [json.loads(tir['key'])]}))
        self.token2key[access_token] = key

    def eval_signed_http_request(self, pop_token, access_token, method, url,
                                 headers, body=''):
        kwargs = sign_http_args(method, url, headers, body)

        shr = SignedHttpRequest(self.token2key[access_token][0])
        return shr.verify(signature=pop_token,
                          strict_query_params_verification=True,
                          strict_headers_verification=True, **kwargs)
