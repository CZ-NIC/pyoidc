import json
from Crypto.PublicKey import RSA
from future.backports.urllib.parse import urlparse, parse_qs
from jwkest.jwk import RSAKey, load_jwks
from oic.extension.message import TokenIntrospectionResponse
from oic.extension.signed_http_req import SignedHttpRequest

__author__ = 'roland'


def sign_http_args(method, url, headers):
    p = urlparse(url)

    kwargs = {'path': p.path, 'host': p.netloc, 'headers': headers,
              'method': method}

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

    def auth_token(self, method, access_token, url, headers):
        kwargs = sign_http_args(method, url, headers)
        shr = SignedHttpRequest(self.token2key[access_token])
        return shr.sign(alg=self.alg, **kwargs)


class PoPAS():
    def __init__(self):
        self.token2key = {}

    def update(self, msg, access_token):
        """
        Used to 'update' the AccessToken Request

        :param msg: TokenIntrospectionResponse
        :param key_size:
        :return:
        """
        msg['key'] = self.token2key[access_token]
        return msg


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
                                 headers):
        kwargs = sign_http_args(method, url, headers)

        shr = SignedHttpRequest(self.token2key[access_token][0])
        return shr.verify(signature=pop_token,
                          strict_query_params_verification=True,
                          strict_headers_verification=True, **kwargs)
