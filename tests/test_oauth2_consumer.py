__author__ = 'rohe0002'
import sys
import urllib

from pytest import raises

from oic.oauth2.consumer import Consumer
from oic.oauth2.consumer import stateID
from oic.oauth2.consumer import rndstr
from oic.oauth2.consumer import factory

from oic.utils import http_util
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import AuthorizationErrorResponse
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.consumer import AuthzError

class LOG():
    def info(self, txt):
        print >> sys.stdout, "INFO: %s" % txt

    def error(self, txt):
        print >> sys.stdout, "ERROR: %s" % txt

    def debug(self, txt):
        print >> sys.stdout, "DEBUG: %s" % txt

def start_response():
    return 

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "disable_ssl_certificate_validation":False,
    "key":None,
    "algorithm":"HS256",
    "grant_expire_in":600,
    "client_secret":"",
    "client_timeout":0
}

CONSUMER_CONFIG = {
    "debug": 1,
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
    #"user_info_endpoint":"http://localhost:8088/user_info",
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

    kaka = http_util.cookie(CLIENT_CONFIG["client_id"], cons.state, cons.seed,
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
    environ = BASE_ENVIRON

    loc = cons.begin(environ, start_response, LOG())

    # state is dynamic
    params = {"scope":"openid",
            "state": cons.state,
            "redirect_uri":"http://localhost:8087/authz",
            "response_type":"code",
            "client_id":"number5"}

    url = "http://localhost:8088/authorization?%s" % urllib.urlencode(params)
    
    assert loc == url

def test_consumer_parse_authz():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    environ = BASE_ENVIRON

    _ = cons.begin(environ, start_response, LOG())

    atr = AuthorizationResponse("SplxlOBeZQQYbYS6WxSbIA", cons.state)
    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = atr.get_urlencoded()

    res = cons.parse_authz(environ, start_response, LOG())

    assert isinstance(res, AuthorizationResponse)
    print cons.grant[cons.state]
    grant = cons.grant[cons.state]
    assert grant.code == "SplxlOBeZQQYbYS6WxSbIA"

def test_consumer_parse_authz_exception():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    environ = BASE_ENVIRON

    _ = cons.begin(environ, start_response, LOG())

    atr = AuthorizationResponse("SplxlOBeZQQYbYS6WxSbIA", cons.state)
    adict = atr.dictionary()
    del adict["code"]
    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = urllib.urlencode(adict)

    raises(ValueError, "cons.parse_authz(environ, start_response, LOG())")

def test_consumer_parse_authz_error():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    environ = BASE_ENVIRON

    _ = cons.begin(environ, start_response, LOG())

    atr = AuthorizationErrorResponse("access_denied", cons.state)
    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = atr.get_urlencoded()

    raises(AuthzError, "cons.parse_authz(environ, start_response, LOG())")

def test_consumer_parse_access_token():
    # implicit flow test
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    environ = BASE_ENVIRON

    cons.response_type = ["token"]
    _ = cons.begin(environ, start_response, LOG())

    atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                              token_type="example",
                              refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                              example_parameter="example_value",
                              state=cons.state)

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = atr.get_urlencoded()

    res = cons.parse_authz(environ, start_response, LOG())

    assert isinstance(res, AccessTokenResponse)
    print cons.grant[cons.state]
    grant = cons.grant[cons.state]
    assert len(grant.tokens) == 1
    token = grant.tokens[0]
    assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"

def test_consumer_parse_authz_error_2():
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    environ = BASE_ENVIRON

    _ = cons.begin(environ, start_response, LOG())

    atr = TokenErrorResponse("invalid_client")
    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = atr.get_urlencoded()

    raises(AuthzError, "cons.parse_authz(environ, start_response, LOG())")
