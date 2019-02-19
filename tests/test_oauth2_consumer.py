from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest

from oic import rndstr
from oic.exception import AuthzError
from oic.oauth2.consumer import Consumer
from oic.oauth2.consumer import factory
from oic.oauth2.consumer import stateID
from oic.oauth2.message import SINGLE_OPTIONAL_INT
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationErrorResponse
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import TokenErrorResponse
from oic.utils.http_util import make_cookie

__author__ = 'rohe0002'

CLIENT_CONFIG = {
    "client_id": "number5",
    "verify_ssl": "/usr/local/etc/oic/ca_certs.txt",
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "flow_type": "code",
    "scope": ["openid"],
    "response_type": "code",
}

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://connect-op.heroku.com",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

BASE_ENVIRON = {'SERVER_PROTOCOL': 'HTTP/1.1',
                'REQUEST_METHOD': 'GET',
                'QUERY_STRING': '',
                'HTTP_CONNECTION': 'keep-alive',
                'REMOTE_ADDR': '127.0.0.1',
                'wsgi.url_scheme': 'http',
                'SERVER_PORT': '8087',
                'PATH_INFO': '/register',
                'HTTP_HOST': 'localhost:8087',
                'HTTP_ACCEPT': 'text/html,application/xhtml+xml,'
                               'application/xml;q=0.9,*/*;q=0.8',
                'HTTP_ACCEPT_LANGUAGE': 'sv-se',
                'CONTENT_TYPE': 'text/plain',
                'REMOTE_HOST': '1.0.0.127.in-addr.arpa',
                'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
                'COMMAND_MODE': 'unix2003'}


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_stateID():
    seed = rndstr().encode("utf-8")
    sid0 = stateID("http://example.com/home", seed)
    sid1 = stateID("http://example.com/home", seed)
    assert sid0
    assert sid1
    assert sid0 != sid1


def test_factory():
    sdb = {}
    consumer = Consumer(sdb, client_config=CLIENT_CONFIG,
                        server_info=SERVER_INFO, **CONSUMER_CONFIG)
    sid = stateID("https://example.org/", consumer.seed)
    _state = sid
    consumer._backup(sid)
    consumer.sdb["seed:%s" % consumer.seed] = sid

    kaka = make_cookie(CLIENT_CONFIG["client_id"], _state, consumer.seed,
                       expire=360, path="/")

    _oac = factory(kaka[1], sdb, CLIENT_CONFIG["client_id"],
                   client_config=CLIENT_CONFIG, server_info=SERVER_INFO,
                   **CONSUMER_CONFIG)

    assert _oac.client_id == consumer.client_id
    assert _oac.seed == consumer.seed


class TestConsumer(object):
    @pytest.fixture(autouse=True)
    def create_consumer(self):
        self.consumer = Consumer({}, client_config=CLIENT_CONFIG,
                                 server_info=SERVER_INFO,
                                 **CONSUMER_CONFIG)

    def test_init(self):
        cons = Consumer({}, client_config=CLIENT_CONFIG,
                        server_info=SERVER_INFO,
                        **CONSUMER_CONFIG)
        cons._backup("123456")
        assert "123456" in cons.sdb

        cons = Consumer({}, client_config=CLIENT_CONFIG, **CONSUMER_CONFIG)
        assert cons.authorization_endpoint is None

        cons = Consumer({}, **CONSUMER_CONFIG)
        assert cons.authorization_endpoint is None

    def test_begin(self):
        sid, loc = self.consumer.begin("http://localhost:8087",
                                       "http://localhost:8088/authorization")

        # state is dynamic
        params = {"scope": "openid",
                  "state": sid,
                  "redirect_uri": "http://localhost:8087/authz",
                  "response_type": "code",
                  "client_id": "number5"}

        url = "http://localhost:8088/authorization?{}".format(urlencode(params))
        assert url_compare(loc, url)

    def test_handle_authorization_response(self):
        sid, loc = self.consumer.begin("http://localhost:8087",
                                       "http://localhost:8088/authorization")

        atr = AuthorizationResponse(code="SplxlOBeZQQYbYS6WxSbIA",
                                    state=sid)

        res = self.consumer.handle_authorization_response(
            query=atr.to_urlencoded())

        assert isinstance(res, AuthorizationResponse)
        assert self.consumer.grant[sid].code == "SplxlOBeZQQYbYS6WxSbIA"

    def test_parse_authz_without_code(self):
        sid, loc = self.consumer.begin("http://localhost:8087",
                                       "http://localhost:8088/authorization")

        atr = AuthorizationResponse(code="SplxlOBeZQQYbYS6WxSbIA",
                                    state=sid)

        adict = atr.to_dict()
        del adict["code"]

        with pytest.raises(MissingRequiredAttribute):
            self.consumer.handle_authorization_response(query=urlencode(adict))

    def test_parse_authz_access_denied(self):
        sid, loc = self.consumer.begin("http://localhost:8087",
                                       "http://localhost:8088/authorization")

        atr = AuthorizationErrorResponse(error="access_denied", state=sid)

        with pytest.raises(AuthzError):
            self.consumer.handle_authorization_response(
                query=atr.to_urlencoded())

    def test_parse_access_token(self):
        # implicit flow test
        self.consumer.response_type = ["token"]
        sid, loc = self.consumer.begin("http://localhost:8087",
                                       "http://localhost:8088/authorization")

        atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                  token_type="example",
                                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                  example_parameter="example_value",
                                  state=sid)

        res = self.consumer.handle_authorization_response(
            query=atr.to_urlencoded())

        assert isinstance(res, AccessTokenResponse)
        grant = self.consumer.grant[sid]
        assert len(grant.tokens) == 1
        token = grant.tokens[0]
        assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"

    def test_parse_authz_invalid_client(self):
        self.consumer.begin("http://localhost:8087",
                            "http://localhost:8088/authorization")

        atr = TokenErrorResponse(error="invalid_client")

        with pytest.raises(AuthzError):
            self.consumer.handle_authorization_response(
                query=atr.to_urlencoded())

    def test_consumer_client_auth_info(self):
        self.consumer.client_secret = "secret0"
        ra, ha, extra = self.consumer.client_auth_info()
        assert ra == {'client_secret': 'secret0', 'client_id': 'number5'}
        assert ha == {}
        assert extra == {'auth_method': 'bearer_body'}

    def test_client_get_access_token_request(self):
        self.consumer.client_secret = "secret0"
        _state = "state"
        self.consumer.redirect_uris = ["https://www.example.com/oic/cb"]

        resp1 = AuthorizationResponse(code="auth_grant", state=_state)
        self.consumer.parse_response(AuthorizationResponse,
                                     resp1.to_urlencoded(),
                                     "urlencoded")
        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state=_state)
        self.consumer.parse_response(AccessTokenResponse, resp2.to_urlencoded(),
                                     "urlencoded")

        url, body, http_args = self.consumer.get_access_token_request(_state)
        assert url_compare(url, "http://localhost:8088/token")
        expected_params = 'redirect_uri=https%3A%2F%2Fwww.example.com%2Foic%2Fcb&client_id=number5&state=state&' \
                          'code=auth_grant&grant_type=authorization_code&client_secret=secret0'

        assert query_string_compare(body, expected_params)
        assert http_args == {'headers': {
            'Content-Type': 'application/x-www-form-urlencoded'}}

    def test_access_token_storage_with_custom_response_class(self):
        _state = "state"

        # AccessTokenResponse custom class
        class AccessTokenResponseWrapper(AccessTokenResponse):
            """Response wrapper to get "expires_in" in hours."""

            c_param = AccessTokenResponse.c_param.copy()
            c_param.update({"expires_in_hours": SINGLE_OPTIONAL_INT})

            def __init__(self, *args, **kwargs):
                super(AccessTokenResponseWrapper, self).__init__(*args, **kwargs)
                if "expires_in" in self and self["expires_in"]:
                    self["expires_in_hours"] = self["expires_in"] // 3600

        resp = AccessTokenResponseWrapper(access_token="2YotnFZFEjr1zCsiAB",
                                          token_type="Bearer",
                                          expires_in=3600,
                                          state=_state)
        self.consumer.parse_response(AccessTokenResponseWrapper,
                                     resp.to_urlencoded(),
                                     "urlencoded")

        grant = self.consumer.grant[_state]
        assert len(grant.tokens) == 1
        assert grant.tokens[0].access_token == "2YotnFZFEjr1zCsiAB"
        assert grant.tokens[0].expires_in == 3600
        assert grant.tokens[0].expires_in_hours == 1
