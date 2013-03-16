from oic.oic.message import AccessTokenResponse, AuthorizationResponse
from oic.utils.keyio import KeyBundle, keybundle_from_local_file
from oic.utils.keyio import KeyJar

__author__ = 'rohe0002'

from oic.oic import Server
from oic.oauth2 import rndstr

from oic.oic.consumer import Consumer
from oic.oic.consumer import IGNORE
from oic.oic.consumer import clean_response

from oic.utils.time_util import utc_time_sans_frac
from oic.utils.sdb import SessionDB

from fakeoicsrv import MyFakeOICServer

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_HMAC_VS = KeyBundle({"kty": "hmac", "key": "abcdefghijklmnop", "use": "ver"})
KC_HMAC_S = KeyBundle({"kty": "hmac", "key": "abcdefghijklmnop", "use": "sig"})

KC_RSA = keybundle_from_local_file("../oc3/certs/mycert.key", "rsa",
                                   ["ver", "sig"])

SRVKEYS = KeyJar()
SRVKEYS[""] = [KC_RSA]
SRVKEYS["client_1"] = [KC_HMAC_VS, KC_RSA]

CLIKEYS = KeyJar()
CLIKEYS["http://localhost:8088"] = [KC_RSA]
CLIKEYS[""] = [KC_HMAC_VS]
CLIKEYS["http://example.com"] = [KC_RSA]

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
    "request_method": "parameter",
    #"temp_dir": "./tmp",
    #"flow_type":
    "password":"hemligt",
    "max_age": 3600,
    #client_secret
    "user_info":{
        "claims": {
            "name":None,
            },
        "format": "signed"
    }
}

CLIENT_CONFIG = {"client_id": CLIENT_ID, "jwt_keys": CLIKEYS}

def start_response(status=200, headers=None):
    if headers is None:
        return "status=%s, headers={}" % (status, )
    else:
        return "status=%s, headers=%s" % (status, headers)

def _eq(l1, l2):
    return set(l1) == set(l2)


def test_clean_response():
    atr = AccessTokenResponse(access_token="access_token",
                            token_type="bearer", expires_in=600,
                            refresh_token="refresh", steps=39, stalls="yes")

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
        self.consumer.client_secret = CLIENT_SECRET

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
        self.consumer.keyjar[""].append(KC_RSA)
        #self.consumer.keyjar.set_sign_key(rsapub, "rsa")
        #self.consumer.keyjar.set_verify_key(rsapub, "rsa")

        srv = Server()
        srv.keyjar = SRVKEYS
        print "redirect_uris",self.consumer.redirect_uris
        print "config", self.consumer.config
        location = self.consumer.begin("openid", "code")
        print location
        authreq = srv.parse_authorization_request(url=location)
        print authreq.keys()
        assert _eq(authreq.keys(), ['request', 'state',
                                    'redirect_uri', 'response_type',
                                    'client_id', 'scope'])
        
        assert authreq["state"] == self.consumer.state
        assert authreq["scope"] == self.consumer.config["scope"]
        assert authreq["client_id"] == self.consumer.client_id


    def test_begin_file(self):
        self.consumer.config["request_method"] = "file"
        self.consumer.config["temp_dir"] = "./file"
        self.consumer.config["temp_path"] = "/tmp/"
        self.consumer.config["authz_page"] = "/authz"
        srv = Server()
        srv.keyjar = SRVKEYS

        location = self.consumer.begin("openid", "code",
                                       path="http://localhost:8087")
        print location
        #vkeys = {".":srv.keyjar.get_verify_key()}
        authreq = srv.parse_authorization_request(url=location)
        print authreq.keys()
        assert _eq(authreq.keys(), ['state', 'redirect_uri',
                                    'response_type', 'client_id', 'scope',
                                    'request_uri'])

        assert authreq["state"] == self.consumer.state
        assert authreq["scope"] == self.consumer.config["scope"]
        assert authreq["client_id"] == self.consumer.client_id
        assert authreq["redirect_uri"].startswith("http://localhost:8087/authz")

    def test_complete(self):
        mfos = MyFakeOICServer("http://localhost:8088")
        mfos.keyjar = SRVKEYS

        self.consumer.http_request = mfos.http_request
        self.consumer.state = "state0"
        self.consumer.nonce = rndstr()
        self.consumer.redirect_uris = ["https://example.com/cb"]
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
            state=self.consumer.state, request_args=args)
        assert result.status_code == 302
        print "redirect_uris", self.consumer.redirect_uris
        print result.headers["location"]

        assert result.headers["location"].startswith(
            self.consumer.redirect_uris[0])
        _, query = result.headers["location"].split("?")

        #vkeys = {".": self.consumer.keyjar.get_verify_key()}

        self.consumer.parse_response(AuthorizationResponse, info=query,
                                     sformat="urlencoded")

        resp = self.consumer.complete()
        print resp
        assert resp.type() == "AccessTokenResponse"
        print resp.keys()
        assert _eq(resp.keys(), ['token_type', 'state', 'access_token',
                                 'scope', 'expires_in', 'refresh_token'])

        assert resp["state"] == self.consumer.state

    def test_parse_authz(self):
        mfos = MyFakeOICServer("http://localhost:8088")
        mfos.keyjar = SRVKEYS

        self.consumer.http_request = mfos.http_request
        self.consumer.state = "state0"
        self.consumer.nonce = rndstr()
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
            state=self.consumer.state,request_args=args)

        print self.consumer.sdb.keys()
        print self.consumer.sdb["state0"].keys()
        part = self.consumer.parse_authz(query=result.headers["location"])
        print part
        atr = part[0]
        assert part[1] is None
        assert part[2] is None

        assert atr.type() ==  "AuthorizationResponse"
        assert atr["state"] == "state0"
        assert "code" in atr

    def test_parse_authz_implicit(self):
        self.consumer.config["response_type"] = "implicit"
        
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "implicit",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
            state=self.consumer.state, request_args=args)

        part = self.consumer.parse_authz(query=result.headers["location"])
        print part
        assert part[0] is None
        atr = part[1]
        assert part[2] is None

        assert atr.type() == "AccessTokenResponse"
        assert atr["state"] == "state0"
        assert "access_token" in atr

def test_complete_secret_auth():
    consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG, SERVER_INFO)
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
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
    assert result.status_code == 302
    assert result.headers["location"].startswith(consumer.redirect_uris[0])
    _, query = result.headers["location"].split("?")

    consumer.parse_response(AuthorizationResponse, info=query,
                            sformat="urlencoded")

    resp = consumer.complete()
    print resp
    assert resp.type() == "AccessTokenResponse"
    print resp.keys()
    assert _eq(resp.keys(), ['token_type', 'state', 'access_token',
                             'scope', 'expires_in', 'refresh_token'])

    assert resp["state"] == consumer.state

def test_complete_auth_token():
    consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG, SERVER_INFO)
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
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

    assert result.status_code == 302
    #assert result.location.startswith(consumer.redirect_uri[0])
    _, query = result.headers["location"].split("?")
    print query
    part = consumer.parse_authz(query=query)
    print part
    auth = part[0]
    acc = part[1]
    assert part[2] is None

    #print auth.dictionary()
    #print acc.dictionary()
    assert auth.type() == "AuthorizationResponse"
    assert acc.type() == "AccessTokenResponse"
    print auth.keys()
    assert _eq(auth.keys(), ['nonce', 'code', 'access_token', 'expires_in',
                             'token_type', 'state', 'scope', 'refresh_token'])
    assert _eq(acc.keys(), ['token_type', 'state', 'access_token', 'scope',
                            'expires_in', 'refresh_token'])

def test_complete_auth_token_idtoken():
    consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG, SERVER_INFO)
    consumer.keyjar = CLIKEYS
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
    consumer.state = "state0"
    consumer.nonce = rndstr()
    consumer.client_secret = "hemlig"
    consumer.secret_type = "basic"
    consumer.config["response_type"] = ["id_token", "token"]

    args = {
        "client_id": consumer.client_id,
        "response_type": consumer.config["response_type"],
        "scope": ["openid"],
        }

    result = consumer.do_authorization_request(state=consumer.state,
                                               request_args=args)
    consumer._backup("state0")

    assert result.status_code == 302
    #assert result.location.startswith(consumer.redirect_uri[0])
    _, query = result.headers["location"].split("?")
    print query
    part = consumer.parse_authz(query=query)
    print part
    auth = part[0]
    acc = part[1]
    assert part[2] is None

    #print auth.dictionary()
    #print acc.dictionary()
    assert auth is None
    assert acc.type() == "AccessTokenResponse"
    assert _eq(acc.keys(), ['access_token', 'id_token', 'expires_in',
                            'token_type', 'state', 'scope'])

def test_userinfo():
    consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG, SERVER_INFO)
    consumer.keyjar = CLIKEYS
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
    consumer.state = "state0"
    consumer.nonce = rndstr()
    consumer.secret_type = "basic"
    consumer.set_client_secret("hemligt")
    consumer.keyjar = CLIKEYS

    args = {
        "client_id": consumer.client_id,
        "response_type": "code",
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=consumer.state,
                                               request_args=args)
    assert result.status_code == 302
    assert result.headers["location"].startswith(consumer.redirect_uris[0])
    _, query = result.headers["location"].split("?")

    consumer.parse_response(AuthorizationResponse, info=query,
                            sformat="urlencoded")

    consumer.complete()

    result = consumer.get_user_info()
    print result
    assert result.type() == "OpenIDSchema"
    assert _eq(result.keys(), ['name', 'email', 'verified', 'nickname', 'sub'])

def real_test_discover():
    c = Consumer(None, None)

    principal = "nav@connect-op.heroku.com"

    res = c.discover(principal)
    print res
    assert res.type() == "ProviderConfigurationResponse"
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
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    c.http_request = mfos.http_request

    principal = "foo@example.com"

    res = c.discover(principal)
    assert res == "http://localhost:8088/"

#def test_discover_redirect():
#    c = Consumer(None, None)
#    mfos = MyFakeOICServer(name="http://example.com/")
#    c.http_request = mfos.http_request
#
#    principal = "bar@example.org"
#
#    res = c.discover(principal)
#    assert res == "http://example.net/providerconf"

def test_provider_config():
    c = Consumer(None, None)
    mfos = MyFakeOICServer("http://example.com")
    mfos.keyjar = SRVKEYS
    c.http_request = mfos.http_request

    principal = "foo@example.com"

    res = c.discover(principal)
    info = c.provider_config(res)
    assert info.type() == "ProviderConfigurationResponse"
    print info.keys()
    assert _eq(info.keys(), ['registration_endpoint', 'jwks_uri',
                             'check_session_endpoint',
                             'refresh_session_endpoint', 'register_endpoint',
                             'subject_types_supported',
                             'token_endpoint_auth_methods_supported',
                             'id_token_signing_alg_values_supported',
                             'grant_types_supported', 'user_info_endpoint',
                             'claims_parameter_supported',
                             'request_parameter_supported',
                             'discovery_endpoint', 'issuer',
                             'authorization_endpoint', 'scopes_supported',
                             'require_request_uri_registration',
                             'identifiers_supported', 'token_endpoint',
                             'request_uri_parameter_supported', 'version',
                             'response_types_supported',
                             'end_session_endpoint', 'flows_supported'])

    assert info["end_session_endpoint"] == "http://example.com/end_session"

def test_client_register():
    c = Consumer(None, None)

    c.application_type = "web"
    c.application_name = "My super service"
    c.redirect_uris = ["http://example.com/authz"]
    c.contact = ["foo@example.com"]

    mfos = MyFakeOICServer("http://example.com")
    mfos.keyjar = SRVKEYS
    c.http_request = mfos.http_request
    location = c.discover("foo@example.com")
    info = c.provider_config(location)

    c.register(info["registration_endpoint"])
    assert c.client_id is not None
    assert c.client_secret is not None
    assert c.registration_expires > utc_time_sans_frac()
