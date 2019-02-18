import json
import logging
import time
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from testfixtures import LogCapture

from oic.oauth2.consumer import Consumer
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.provider import Provider
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit
from oic.utils.http_util import Response

CLIENT_CONFIG = {
    "client_id": "client1",
    'config': {'issuer': 'https://example.com/as'}
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "flow_type": "code",
    "scope": [],
    "response_type": "code",
}

ISSUER = "https://connect-op.heroku.com"
SERVER_INFO = {
    "version": "3.0",
    "issuer": ISSUER,
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        'response_types': ['code', 'token'],
        "redirect_uris": [("http://example.com", None)],
    },
    "client1": {
        "client_secret": "hemlighet",
        "redirect_uris": [("http://localhost:8087/authz", None)],
        'token_endpoint_auth_method': 'client_secret_post',
        'response_types': ['code', 'token']
    }
}


def _eq(l1, l2):
    return set(l1) == set(l2)


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}, time.time()


class NoCookieAuthn(DummyAuthn):
    """Authn that doesn't create cookies."""

    def create_cookie(self, value, typ, cookie_name=None, ttl=-1, kill=False):
        pass


def verify_outcome(msg, prefix, lista):
    """
    Compare message to list of claims: values.

    :param prefix: prefix string
    :param lista: list of claims=value
    :return: list of possible strings
    """
    assert msg.startswith(prefix)
    qsl = ['{}={}'.format(k, v[0]) for k, v in
           parse_qs(msg[len(prefix):]).items()]
    return set(qsl) == set(lista)


AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))
AUTHN_BROKER2 = AuthnBroker()
AUTHN_BROKER2.add('UNDEFINED', NoCookieAuthn(None, 'username'))
# dealing with authorization
AUTHZ = Implicit()


class TestProvider(object):
    @pytest.fixture(autouse=True)
    def create_provider(self, session_db_factory):
        self.provider = Provider("pyoicserv",
                                 session_db_factory(ISSUER), CDB,
                                 AUTHN_BROKER, AUTHZ, verify_client,
                                 baseurl='https://example.com/as')

    def test_init(self, session_db_factory):
        provider = Provider("pyoicserv", session_db_factory(ISSUER),
                            CDB,
                            AUTHN_BROKER, AUTHZ, verify_client)
        assert provider

        provider = Provider("pyoicserv", session_db_factory(ISSUER),
                            CDB,
                            AUTHN_BROKER, AUTHZ, verify_client,
                            urlmap={"client1": ["https://example.com/authz"]})
        assert provider.urlmap["client1"] == ["https://example.com/authz"]

    def test_authorization_endpoint_faulty_redirect_uri(self):
        bib = {"scope": ["openid"],
               "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               "redirect_uri": "http://localhost:8087/authz",
               # faulty redirect uri
               "response_type": ["code"],
               "client_id": "a1b2c3"}

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authorization_endpoint_wronge_response_mode(self):
        bib = {"scope": ["openid"],
               "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               "redirect_uri": "http://example.com",
               "response_type": ["code"],
               "response_mode": "fragment",
               "client_id": "a1b2c3"}

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authorization_endpoint_faulty_redirect_uri_nwalker(self):
        bib = {"scope": ["openid"],
               "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               "redirect_uri": " https://example.com.evil.com",
               # faulty redirect uri
               "response_type": ["code"],
               "client_id": "a1b2c3"}

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authorization_endpoint_missing_client_id(self):
        # Url encoded request with missing client_id
        arq = 'scope=openid&state=id-6da9ca0cc23959f5f33e8becd9b08cae&' \
              'redirect_uri=+https%3A%2F%2Fexample.com&response_type=code'
        resp = self.provider.authorization_endpoint(request=arq)
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authenticated(self):
        _session_db = {}
        cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                        server_info=SERVER_INFO, **CONSUMER_CONFIG)

        sid, location = cons.begin("http://localhost:8087",
                                   "http://localhost:8088/authorization")

        resp = self.provider.authorization_endpoint(urlparse(location).query)
        assert resp.status_code == 303
        resp = urlparse(resp.message).query
        with LogCapture(level=logging.DEBUG) as logcap:
            aresp = cons.handle_authorization_response(query=resp)

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ['state', 'code', 'client_id', 'iss'])
        assert _eq(cons.grant[sid].keys(), ['tokens', 'code', 'exp_in',
                                            'seed', 'id_token',
                                            'grant_expiration_time'])

        state = aresp['state']
        assert _eq(logcap.records[0].msg, '- authorization - code flow -')
        assert verify_outcome(logcap.records[1].msg,
                              'QUERY: ',
                              ['state={}'.format(state), 'code=<REDACTED>',
                               'client_id=client1',
                               'iss=https://example.com/as'])

        expected = {'iss': 'https://example.com/as',
                    'state': state, 'code': '<REDACTED>',
                    'client_id': 'client1'}
        # Eval here to avoid intermittent failures due to dict ordering
        assert _eq(eval(logcap.records[2].msg[29:-1]), expected)
        expected = ["'client_id': 'client1'", "'iss': 'https://example.com/as'",
                    "'keyjar': <KeyJar(issuers=[])>"]
        assert _eq(sorted(logcap.records[3].msg[22:-1].split(', ')), expected)

    def test_authenticated_token(self):
        _session_db = {}
        cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                        server_info=SERVER_INFO, **CONSUMER_CONFIG)

        sid, location = cons.begin("http://localhost:8087",
                                   "http://localhost:8088/authorization",
                                   "token")

        QUERY_STRING = location.split("?")[1]
        resp = self.provider.authorization_endpoint(QUERY_STRING)
        auth_resp = parse_qs(urlparse(resp.message).fragment)

        assert "access_token" in auth_resp
        assert auth_resp["token_type"][0] == "Bearer"

    def test_token_endpoint(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz"
        }

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client1",
                                  client_secret="hemlighet",
                                  grant_type='authorization_code')
        with LogCapture(level=logging.DEBUG) as logcap:
            resp = self.provider.token_endpoint(request=areq.to_urlencoded())

        atr = AccessTokenResponse().deserialize(resp.message, "json")
        assert _eq(atr.keys(), ['access_token', 'token_type', 'refresh_token'])

        expected = (
            'body: code=<REDACTED>&client_secret=<REDACTED>&grant_type'
            '=authorization_code'
            '   &client_id=client1&redirect_uri=http%3A%2F%2Fexample.com'
            '%2Fauthz')
        assert _eq(parse_qs(logcap.records[1].msg[6:]), parse_qs(expected[6:]))
        expected = {u'code': '<REDACTED>', u'client_secret': '<REDACTED>',
                    u'redirect_uri': u'http://example.com/authz',
                    u'client_id': 'client1',
                    u'grant_type': 'authorization_code'}
        # Don't try this at home, kids!
        # We have to eval() to a dict here because otherwise the arbitrary
        # ordering of the string causes the test to fail intermittently.
        assert _eq(eval(logcap.records[2].msg[4:]), expected)
        assert _eq(logcap.records[3].msg, 'Verified Client ID: client1')
        expected = {'redirect_uri': u'http://example.com/authz',
                    'client_secret': '<REDACTED>',
                    'code': u'<REDACTED>', 'client_id': 'client1',
                    'grant_type': 'authorization_code'}
        assert eval(logcap.records[4].msg[20:]) == expected
        expected = {'code': '<REDACTED>', 'authzreq': '', 'sub': 'sub',
                    'access_token': '<REDACTED>',
                    'token_type': 'Bearer',
                    'redirect_uri': 'http://example.com/authz',
                    'code_used': True, 'client_id': 'client1',
                    'oauth_state': 'token',
                    'refresh_token': '<REDACTED>', 'access_token_scope': '?'}
        assert _eq(eval(logcap.records[5].msg[7:]), expected)
        expected = {'access_token': u'<REDACTED>', 'token_type': 'Bearer',
                    'refresh_token': '<REDACTED>'}
        assert _eq(eval(logcap.records[6].msg[21:]), expected)

    def test_token_endpoint_no_cache(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz"
        }

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client1",
                                  client_secret="hemlighet",
                                  grant_type='authorization_code')
        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        assert resp.headers == [('Pragma', 'no-cache'), ('Cache-Control', 'no-store'),
                                ('Content-type', 'application/json')]

    def test_token_endpoint_unauth(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz"
        }

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id='<REDACTED>',
                                  client_secret="hemlighet",
                                  grant_type='authorization_code')

        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert _eq(atr.keys(), ['error_description', 'error'])

    @pytest.mark.parametrize("response_types", [
        ['token id_token', 'id_token'],
        ['id_token token']
    ])
    def test_response_types(self, response_types):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1",
                                       response_type='id_token token')

        self.provider.cdb = {
            "client1": {
                "client_secret": "hemlighet",
                "redirect_uris": [("http://example.com/authz", None)],
                'token_endpoint_auth_method': 'client_secret_post',
                'response_types': response_types
            }
        }

        res = self.provider.auth_init(authreq.to_urlencoded())
        assert isinstance(res, dict) and "areq" in res

    @pytest.mark.parametrize("response_types", [
        ['token id_token', 'id_token'],
        ['id_token token'],
        ['code id_token'],
        ['id_token code']
    ])
    def test_response_types_fail(self, response_types):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1",
                                       response_type='code')

        self.provider.cdb = {
            "client1": {
                "client_secret": "hemlighet",
                "redirect_uris": [("http://example.com/authz", None)],
                'token_endpoint_auth_method': 'client_secret_post',
                'response_types': response_types
            }
        }

        res = self.provider.auth_init(authreq.to_urlencoded())
        assert isinstance(res, Response)

        _res = json.loads(res.message)
        assert _res['error'] == 'invalid_request'

    def test_complete_authz_no_cookie(self, session_db_factory):
        provider = Provider("pyoicserver", session_db_factory(ISSUER), CDB, AUTHN_BROKER2, AUTHZ, verify_client,
                            baseurl='https://example.com/as')
        areq = {'client_id': 'client1',
                'response_type': ['code'],
                'redirect_uri': 'http://localhost:8087/authz'}
        sid = provider.sdb.access_token.key(user='sub', areq=areq)
        access_code = provider.sdb.access_token(sid=sid)
        provider.sdb[sid] = {'oauth_state': 'authz',
                             'sub': 'sub',
                             'client_id': 'client1',
                             'code': access_code,
                             'redirect_uri': 'http://localhost:8087/authz'}
        response, header, redirect, fragment = provider._complete_authz('sub', areq, sid)
        assert header == []
        assert not fragment
        assert redirect == 'http://localhost:8087/authz'
        assert 'code' in response

    def test_complete_authz_cookie(self, session_db_factory):
        provider = Provider("pyoicserver", session_db_factory(ISSUER), CDB, AUTHN_BROKER, AUTHZ, verify_client,
                            baseurl='https://example.com/as')
        areq = {'client_id': 'client1',
                'response_type': ['code'],
                'redirect_uri': 'http://localhost:8087/authz'}
        sid = provider.sdb.access_token.key(user='sub', areq=areq)
        access_code = provider.sdb.access_token(sid=sid)
        provider.sdb[sid] = {'oauth_state': 'authz',
                             'sub': 'sub',
                             'client_id': 'client1',
                             'code': access_code,
                             'redirect_uri': 'http://localhost:8087/authz'}
        response, header, redirect, fragment = provider._complete_authz('sub', areq, sid)
        assert len(header) == 1
        cookie_header = header[0]
        assert cookie_header[0] == 'Set-Cookie'
        assert cookie_header[1].startswith('pyoidc_sso="sub][client1')
        assert not fragment
        assert redirect == 'http://localhost:8087/authz'
        assert 'code' in response

    def test_complete_authz_other_cookie_exists(self, session_db_factory):
        provider = Provider("pyoicserver", session_db_factory(ISSUER), CDB, AUTHN_BROKER, AUTHZ, verify_client,
                            baseurl='https://example.com/as')
        areq = {'client_id': 'client1',
                'response_type': ['code'],
                'redirect_uri': 'http://localhost:8087/authz'}
        sid = provider.sdb.access_token.key(user='sub', areq=areq)
        access_code = provider.sdb.access_token(sid=sid)
        provider.sdb[sid] = {'oauth_state': 'authz',
                             'sub': 'sub',
                             'client_id': 'client1',
                             'code': access_code,
                             'redirect_uri': 'http://localhost:8087/authz'}
        cookie = 'Some-cookie=test::test'
        response, header, redirect, fragment = provider._complete_authz('sub', areq, sid, cookie=cookie)
        assert len(header) == 1
        cookie_header = header[0]
        assert cookie_header[1].startswith('pyoidc_sso="sub][client1')
        assert not fragment
        assert redirect == 'http://localhost:8087/authz'
        assert 'code' in response

    def test_complete_authz_pyoidc_cookie_exists(self, session_db_factory):
        provider = Provider("pyoicserver", session_db_factory(ISSUER), CDB, AUTHN_BROKER, AUTHZ, verify_client,
                            baseurl='https://example.com/as')
        areq = {'client_id': 'client1',
                'response_type': ['code'],
                'redirect_uri': 'http://localhost:8087/authz'}
        sid = provider.sdb.access_token.key(user='sub', areq=areq)
        access_code = provider.sdb.access_token(sid=sid)
        provider.sdb[sid] = {'oauth_state': 'authz',
                             'sub': 'sub',
                             'client_id': 'client1',
                             'code': access_code,
                             'redirect_uri': 'http://localhost:8087/authz'}
        cookie = 'pyoidc_sso=test::test'
        response, header, redirect, fragment = provider._complete_authz('sub', areq, sid, cookie=cookie)
        assert len(header) == 0
        assert not fragment
        assert redirect == 'http://localhost:8087/authz'
        assert 'code' in response
