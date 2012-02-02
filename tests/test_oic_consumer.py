__author__ = 'rohe0002'

import time

from oic.oic import Server
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationResponse
from oic.oic.message import OpenIDSchema
#from oic.oic.message import RegistrationResponse
from oic.oic.message import ProviderConfigurationResponse
#from oic.oic import Grant
from oic.oauth2 import rndstr

from oic.oic.consumer import Consumer
from oic.oic.consumer import IGNORE
from oic.oic.consumer import clean_response

from oic.utils.sdb import SessionDB

from fakeoicsrv import MyFakeOICServer

JWT_KEY = {"hmac":"abcdefghijklmop"}

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

SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://localhost:8088",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
    "userinfo_endpoint":"http://localhost:8088/userinfo",
    "flows_supported":["code","token"],
}

CONFIG = {
    "authz_page": "authz",
    "scope": ["openid"],
    "response_type": "code",
    "key": JWT_KEY,
    "request_method": "parameter",
    #"temp_dir": "./tmp",
    #"flow_type":
    "password":"hemligt",
    #client_secret
}

CLIENT_CONFIG = {
    "client_id": "client0"
}

def start_response(status=200, headers=None):
    if headers is None:
        return "status=%s, headers={}" % (status, )
    else:
        return "status=%s, headers=%s" % (status, headers)

def _eq(l1, l2):
    return set(l1) == set(l2)

class DEVNULL():
    #noinspection PyUnusedLocal
    def info(self, txt):
        return

def redirect_environment(query):
    environ = BASE_ENVIRON.copy()
    environ["REQUEST_METHOD"] = "GET"
    environ["QUERY_STRING"] = query

    return environ


def test_clean_response():
    atr = AccessTokenResponse(access_token="access_token",
                              token_type="bearer", expires_in=600,
                              refresh_token="refresh", steps=39,
                              stalls="yes")

    catr = clean_response(atr)
    atr_keys = atr.keys()
    catr_keys = catr.keys()
    assert _eq(atr_keys, ['token_type', 'access_token', 'expires_in',
                          'refresh_token', 'steps', 'stalls'])
    assert _eq(catr_keys, ['token_type', 'access_token', 'expires_in',
                          'refresh_token'])


class TestOICConsumer():

    def setup_class(self):
        self.consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG,
                                 SERVER_INFO)

    def test_init(self):
        assert self.consumer

    def test_backup_keys(self):
        keys = self.consumer.__dict__.keys()
        print keys
        _dict = self.consumer.dictionary()
        print _dict.keys()
        dkeys = [key for key in keys if key not in _dict.keys()]
        print dkeys
        assert _eq(dkeys, IGNORE)

    def test_backup_restore(self):

        _dict = self.consumer.__dict__.items()

        self.consumer._backup("sid")
        self.consumer.restore("sid")

        assert _dict == self.consumer.__dict__.items()

        self.consumer.authorization_endpoint = "http://example.com/authorization"

        assert _dict != self.consumer.__dict__.items()

        self.consumer.restore("sid")

        assert _dict == self.consumer.__dict__.items()

    def test_backup_restore_update(self):

        self.consumer.authorization_endpoint = "http://example.com/authorization"
        self.consumer.token_endpoint = "http://example.com/token"
        self.consumer.userinfo_endpoint = "http://example.com/userinfo"

        self.consumer._backup("sid")

        self.consumer.authorization_endpoint = "http://example.org/authorization"
        self.consumer.token_endpoint = "http://example.org/token"
        self.consumer.userinfo_endpoint = ""

        assert self.consumer.authorization_endpoint == "http://example.org/authorization"
        assert self.consumer.token_endpoint == "http://example.org/token"
        assert self.consumer.userinfo_endpoint == ""

        self.consumer.update("sid")

        assert self.consumer.authorization_endpoint == "http://example.org/authorization"
        assert self.consumer.token_endpoint == "http://example.org/token"
        assert self.consumer.userinfo_endpoint == "http://example.com/userinfo"

    def test_begin(self):
        self.consumer.authorization_endpoint = "http://example.com/authorization"
        srv = Server()
        location = self.consumer.begin(BASE_ENVIRON, start_response, DEVNULL())
        print location
        authreq = srv.parse_authorization_request(url=location)
        print authreq.keys()
        assert _eq(authreq.keys(), ['nonce', 'request', 'state',
                                    'redirect_uri', 'response_type',
                                    'client_id', 'scope'])
        
        assert authreq.state == self.consumer.state
        assert authreq.scope == self.consumer.config["scope"]
        assert authreq.client_id == self.consumer.client_id
        assert authreq.nonce == self.consumer.nonce


    def test_begin_file(self):
        self.consumer.config["request_method"] = "file"
        self.consumer.config["temp_dir"] = "./file"
        self.consumer.config["temp_path"] = "/tmp/"
        srv = Server()
        location = self.consumer.begin(BASE_ENVIRON, start_response, DEVNULL())
        print location
        authreq = srv.parse_authorization_request(url=location)
        print authreq.keys()
        assert _eq(authreq.keys(), ['nonce', 'request_uri', 'state',
                                    'redirect_uri', 'response_type',
                                    'client_id', 'scope'])

        assert authreq.state == self.consumer.state
        assert authreq.scope == self.consumer.config["scope"]
        assert authreq.client_id == self.consumer.client_id
        assert authreq.nonce == self.consumer.nonce
        assert authreq.request_uri.startswith("http://localhost:8087/tmp/")

    def test_complete(self):
        self.consumer.http = MyFakeOICServer()
        self.consumer.state = "state0"
        self.consumer.nonce = rndstr()
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
                                                    state=self.consumer.state,
                                                    request_args=args)
        assert result.status == 302
        assert result.location.startswith(self.consumer.redirect_uri)
        _, query = result.location.split("?")

        self.consumer.parse_response(AuthorizationResponse, info=query,
                                   format="urlencoded")

        resp = self.consumer.complete(DEVNULL())
        print resp
        assert isinstance(resp, AccessTokenResponse)
        print resp.keys()
        assert _eq(resp.keys(), ['token_type', 'state', 'access_token',
                                 'scope', 'expires_in', 'refresh_token'])

        assert resp.state == self.consumer.state

    def test_parse_authz(self):
        self.consumer.http = MyFakeOICServer()
        self.consumer.state = "state0"
        self.consumer.nonce = rndstr()
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
                                                    state=self.consumer.state,
                                                    request_args=args)

        environ = redirect_environment(result.location)

        part = self.consumer.parse_authz(environ, start_response, DEVNULL())
        print part
        atr = part[0]
        assert part[1] is None
        assert part[2] is None

        assert isinstance(atr, AuthorizationResponse)
        assert atr.state == "state0"
        assert "code" in atr

    def test_parse_authz_implicit(self):
        self.consumer.config["response_type"] = "implicit"
        
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "implicit",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
                                                    state=self.consumer.state,
                                                    request_args=args)

        environ = redirect_environment(result.location)

        part = self.consumer.parse_authz(environ, start_response, DEVNULL())
        print part
        assert part[0] is None
        atr = part[1]
        assert part[2] is None

        assert isinstance(atr, AccessTokenResponse)
        assert atr.state == "state0"
        assert "access_token" in atr

def test_complete_secret_auth():
    consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG, SERVER_INFO)
    consumer.http = MyFakeOICServer()
    consumer.redirect_uri = "http://example.com/authz"
    consumer.state = "state0"
    consumer.nonce = rndstr()
    consumer.client_secret = "hemlig"
    consumer.secret_type = "basic"
    del consumer.config["password"]

    args = {
        "client_id": consumer.client_id,
        "response_type": "code",
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=consumer.state,
                                               request_args=args)
    assert result.status == 302
    assert result.location.startswith(consumer.redirect_uri)
    _, query = result.location.split("?")

    consumer.parse_response(AuthorizationResponse, info=query,
                            format="urlencoded")

    resp = consumer.complete(DEVNULL())
    print resp
    assert isinstance(resp, AccessTokenResponse)
    print resp.keys()
    assert _eq(resp.keys(), ['token_type', 'state', 'access_token',
                             'scope', 'expires_in', 'refresh_token'])

    assert resp.state == consumer.state

def test_complete_auth_token():
    consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG, SERVER_INFO)
    consumer.http = MyFakeOICServer()
    consumer.redirect_uri = "http://example.com/authz"
    consumer.state = "state0"
    consumer.nonce = rndstr()
    consumer.client_secret = "hemlig"
    consumer.secret_type = "basic"
    consumer.config["response_type"] = ["code", "token"]
    
    args = {
        "client_id": consumer.client_id,
        "response_type": consumer.config["response_type"],
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=consumer.state,
                                               request_args=args)
    consumer._backup("state0")

    assert result.status == 302
    assert result.location.startswith(consumer.redirect_uri)
    _, query = result.location.split("?")
    print query
    environ = redirect_environment(query)

    part = consumer.parse_authz(environ, start_response, DEVNULL())
    print part
    auth = part[0]
    acc = part[1]
    assert part[2] is None

    #print auth.dictionary()
    #print acc.dictionary()
    assert isinstance(auth, AuthorizationResponse)
    assert isinstance(acc, AccessTokenResponse)
    print auth.keys()
    assert _eq(auth.keys(), ['nonce', 'code', 'access_token', 'expires_in',
                             'token_type', 'state', 'scope', 'refresh_token'])
    assert _eq(acc.keys(), ['token_type', 'state', 'access_token', 'scope',
                            'expires_in', 'refresh_token'])


def test_userinfo():
    consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG, SERVER_INFO)
    consumer.http = MyFakeOICServer()
    consumer.redirect_uri = "http://example.com/authz"
    consumer.state = "state0"
    consumer.nonce = rndstr()
    consumer.client_secret = "hemlig"
    consumer.secret_type = "basic"

    args = {
        "client_id": consumer.client_id,
        "response_type": "code",
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=consumer.state,
                                               request_args=args)
    assert result.status == 302
    assert result.location.startswith(consumer.redirect_uri)
    _, query = result.location.split("?")

    consumer.parse_response(AuthorizationResponse, info=query,
                            format="urlencoded")

    consumer.complete(DEVNULL())

    result = consumer.userinfo(DEVNULL())
    print result
    assert isinstance(result, OpenIDSchema)
    assert _eq(result.keys(), ['name', 'email', 'verified', 'nickname'])

def real_test_discover():
    c = Consumer(None, None)

    principal = "nav@connect-op.heroku.com"

    res = c.discover(principal)
    print res
    assert isinstance(res, ProviderConfigurationResponse)
    print res.keys()
    assert _eq(res.keys(), ['registration_endpoint', 'scopes_supported',
                            'identifiers_supported', 'token_endpoint',
                            'flows_supported', 'version', 'userinfo_endpoint',
                            'authorization_endpoint', 'x509_url', 'issuer'])
    assert res.version == "3.0"
    print res.flows_supported
    assert _eq(res.flows_supported, ['code', 'token', 'id_token',
                                     'code token', 'code id_token',
                                     'id_token token'])

def test_discover():
    c = Consumer(None, None)
    c.http = MyFakeOICServer()
    
    principal = "foo@example.com"

    res = c.discover(principal)
    assert res == "http://example.com/providerconf"

def test_discover_redirect():
    c = Consumer(None, None)
    c.http = MyFakeOICServer()

    principal = "bar@example.org"

    res = c.discover(principal)
    assert res == "http://example.net/providerconf"

def test_provider_config():
    c = Consumer(None, None)
    c.http = MyFakeOICServer()

    principal = "foo@example.com"

    res = c.discover(principal)
    info = c.provider_config(res)
    assert isinstance(info, ProviderConfigurationResponse)
    print info.keys()
    assert _eq(info.keys(), ['refresh_session_endpoint', 'token_endpoint',
                             'version', 'registration_endpoint',
                             'scopes_supported', 'end_session_endpoint',
                             'authorization_endpoint'])

    assert info.end_session_endpoint == "http://example.com/end_session"

def test_client_register():
    c = Consumer(None, None)

    c.application_type = "web"
    c.application_name = "My super service"
    c.redirect_uri = "http://example.com/authz"
    c.contact = ["foo@example.com"]

    c.http = MyFakeOICServer()
    location = c.discover("foo@example.com")
    info = c.provider_config(location)

    c.register(info["registration_endpoint"])
    assert c.client_id is not None
    assert c.client_secret is not None
    assert c.registration_expires > time.time()