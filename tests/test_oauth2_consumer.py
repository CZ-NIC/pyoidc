
__author__ = 'rohe0002'
import urllib

from pytest import raises

from oic.oauth2 import rndstr

from oic.oauth2.consumer import Consumer
from oic.oauth2.consumer import stateID
from oic.oauth2.consumer import factory

from oic.utils.http_util import make_cookie
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import AuthorizationErrorResponse
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import TokenErrorResponse

from oic.oauth2.consumer import AuthzError

#from oic.oauth2.message import

# client_id=None, ca_certs=None,grant_expire_in=600, client_timeout=0,
# jwt_keys=None
CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "grant_expire_in":600,
    "client_timeout":0
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "flow_type": "code",
    #"password": args.passwd,
    "scope": ["openid"],
    "response_type": "code",
    #"expire_in": 600,
}

SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://connect-op.heroku.com",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
    #"userinfo_endpoint":"http://localhost:8088/user_info",
    #"check_id_endpoint":"http://localhost:8088/id_token",
    #"registration_endpoint":"https://connect-op.heroku.com/connect/client",
    #"scopes_supported":["openid","profile","email","address","PPID"],
    "flows_supported":["code","token","code token"],
    #"identifiers_supported":["public","ppid"],
    #"x509_url":"https://connect-op.heroku.com/cert.pem"
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
               'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'HTTP_ACCEPT_LANGUAGE': 'sv-se',
               'CONTENT_TYPE': 'text/plain',
               'REMOTE_HOST': '1.0.0.127.in-addr.arpa',
               'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
               'COMMAND_MODE': 'unix2003'}


def test_stateID():
    seed = rndstr()
    sid0  = stateID("http://example.com/home", seed)
    sid1  = stateID("http://example.com/home", seed)
    assert sid0
    assert sid1
    assert sid0 != sid1


def test_init_consumer():

    cons = Consumer({}, client_config = CLIENT_CONFIG, server_info=SERVER_INFO,
                      **CONSUMER_CONFIG)
    assert cons

    cons._backup("123456")

    assert "123456" in cons.sdb

    cons = Consumer({}, client_config = CLIENT_CONFIG, **CONSUMER_CONFIG)
    assert cons.authorization_endpoint is None

    cons = Consumer({}, **CONSUMER_CONFIG)
    assert cons.authorization_endpoint is None
    

def test_factory():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)

    sid = stateID("https://example.org/", cons.seed)
    cons.state = sid
    cons._backup(sid)
    cons.sdb["seed:%s" % cons.seed] = sid

    kaka = make_cookie(CLIENT_CONFIG["client_id"], cons.state, cons.seed,
                            expire=360, path="/")

    _oac = factory(kaka[1], _session_db, CLIENT_CONFIG["client_id"],
                   client_config= CLIENT_CONFIG, server_info=SERVER_INFO,
                   **CONSUMER_CONFIG)

    assert _oac
    assert _oac.state == cons.state
    assert _oac.seed == cons.seed


def test_consumer_begin():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)

    loc = cons.begin("http://localhost:8087",
                     "http://localhost:8088/authorization")

    # state is dynamic
    params = {"scope": "openid",
              "state": cons.state,
              "redirect_uri": "http://localhost:8087/authz",
              "response_type": "code",
              "client_id": "number5"}

    url = "http://localhost:8088/authorization?%s" % urllib.urlencode(params)
    
    assert loc == url

def test_consumer_handle_authorization_response():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    _ = cons.begin("http://localhost:8087",
                   "http://localhost:8088/authorization")

    atr = AuthorizationResponse(code="SplxlOBeZQQYbYS6WxSbIA",
                                state=cons.state)

    res = cons.handle_authorization_response(query=atr.to_urlencoded())

    assert res.type() == "AuthorizationResponse"
    print cons.grant[cons.state]
    grant = cons.grant[cons.state]
    assert grant.code == "SplxlOBeZQQYbYS6WxSbIA"

def test_consumer_parse_authz_exception():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    _ = cons.begin("http://localhost:8087",
                   "http://localhost:8088/authorization")

    atr = AuthorizationResponse(code="SplxlOBeZQQYbYS6WxSbIA",
                                state=cons.state)
    
    adict = atr.to_dict()
    del adict["code"]
    QUERY_STRING = urllib.urlencode(adict)

    raises(MissingRequiredAttribute,
           "cons.handle_authorization_response(query=QUERY_STRING)")

def test_consumer_parse_authz_error():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    _ = cons.begin("http://localhost:8087",
                   "http://localhost:8088/authorization")

    atr = AuthorizationErrorResponse(error="access_denied", state=cons.state)
    
    QUERY_STRING = atr.to_urlencoded()

    raises(AuthzError,
           "cons.handle_authorization_response(query=QUERY_STRING)")

def test_consumer_parse_access_token():
    # implicit flow test
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    environ = BASE_ENVIRON

    cons.response_type = ["token"]
    _ = cons.begin("http://localhost:8087",
                   "http://localhost:8088/authorization")

    atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                              token_type="example",
                              refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                              example_parameter="example_value",
                              state=cons.state)

    res = cons.handle_authorization_response(query=atr.to_urlencoded())

    assert res.type() == "AccessTokenResponse"
    print cons.grant[cons.state]
    grant = cons.grant[cons.state]
    assert len(grant.tokens) == 1
    token = grant.tokens[0]
    assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"

def test_consumer_parse_authz_error_2():
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    _ = cons.begin("http://localhost:8087",
                   "http://localhost:8088/authorization")

    atr = TokenErrorResponse(error="invalid_client")
    QUERY_STRING = atr.to_urlencoded()

    raises(AuthzError,
           "cons.handle_authorization_response(query=QUERY_STRING)")

def test_consumer_client_auth_info():
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.client_secret = "secret0"
    ra, ha, extra = cons.client_auth_info()
    assert ra == {'client_secret': 'secret0', 'client_id': 'number5'}
    assert ha == {}
    assert extra == {'auth_method': 'bearer_body'}

def test_consumer_client_get_access_token_reques():
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.client_secret = "secret0"
    cons.state = "state"
    cons.redirect_uris = ["https://www.example.com/oic/cb"]

    resp1 = AuthorizationResponse(code="auth_grant", state="state")
    cons.parse_response(AuthorizationResponse, resp1.to_urlencoded(),
                          "urlencoded")
    resp2 = AccessTokenResponse(access_token="token1",
                                token_type="Bearer", expires_in=0,
                                state="state")
    cons.parse_response(AccessTokenResponse, resp2.to_urlencoded(),
                          "urlencoded")

    url, body, http_args = cons.get_access_token_request()
    assert url == "http://localhost:8088/token"
    print body
    assert body == "code=auth_grant&redirect_uri=https%3A%2F%2Fwww.example.com%2Foic%2Fcb&client_id=number5&scope=openid&client_secret=secret0&grant_type=authorization_code"
    assert http_args == {'headers': {'content-type':
                               'application/x-www-form-urlencoded'}}

