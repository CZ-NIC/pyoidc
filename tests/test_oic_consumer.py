import json
import os
import shutil
import tempfile

from jwkest import BadSignature
from jwkest.jwk import SYMKey

from oic.oauth2.message import MissingSigningKey
from oic.oic.message import AccessTokenResponse, AuthorizationResponse, IdToken
from oic.utils.keyio import KeyBundle, keybundle_from_local_file
from oic.utils.keyio import KeyJar


__author__ = 'rohe0002'

from oic.oic import Server, DEF_SIGN_ALG
from oic.oauth2 import rndstr

from oic.oic.consumer import Consumer
from oic.oic.consumer import IGNORE
from oic.oic.consumer import clean_response

from oic.utils.time_util import utc_time_sans_frac
from oic.utils.sdb import SessionDB

from fakeoicsrv import MyFakeOICServer
from mitmsrv import MITMServer

from utils_for_tests import _eq

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_SYM_VS = KeyBundle({"kty": "oct", "key": "abcdefghijklmnop", "use": "ver"})
KC_SYM_S = KeyBundle({"kty": "oct", "key": "abcdefghijklmnop", "use": "sig"})

BASE_PATH = os.path.dirname(os.path.abspath(__file__))

KC_RSA = keybundle_from_local_file("%s/rsa.key" % BASE_PATH,
                                   "rsa", ["ver", "sig"])

SRVKEYS = KeyJar()
SRVKEYS[""] = [KC_RSA]
SRVKEYS["client_1"] = [KC_SYM_VS, KC_RSA]

CLIKEYS = KeyJar()
CLIKEYS["http://localhost:8088"] = [KC_RSA]
CLIKEYS[""] = [KC_SYM_VS]
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

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://localhost:8088",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "userinfo_endpoint": "http://localhost:8088/userinfo",
    "flows_supported": ["code", "token"],
}

CONFIG = {
    "authz_page": "authz",
    "scope": ["openid"],
    "response_type": "code",
    "request_method": "parameter",
    # "temp_dir": "./tmp",
    #"flow_type":
    "password": "hemligt",
    "max_age": 3600,
    #client_secret
    "user_info": {
        "name": None,
    }
}

CLIENT_CONFIG = {"client_id": CLIENT_ID}


def start_response(status=200, headers=None):
    if headers is None:
        return "status=%s, headers={}" % (status, )
    else:
        return "status=%s, headers=%s" % (status, headers)


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


AUTHZ_URL = "http://example.com/authorization"
AUTHZ_ORG_URL = "http://example.org/authorization"


class TestOICConsumer():
    def setup_class(self):
        self.consumer = Consumer(SessionDB(SERVER_INFO["issuer"]),
                                 CONFIG, CLIENT_CONFIG, SERVER_INFO)
        self.consumer.behaviour = {"request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}
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

        self.consumer.authorization_endpoint = AUTHZ_URL

        assert _dict != self.consumer.__dict__.items()

        self.consumer.restore("sid")

        assert _dict == self.consumer.__dict__.items()

    def test_backup_restore_update(self):
        self.consumer.authorization_endpoint = AUTHZ_URL
        self.consumer.token_endpoint = "http://example.com/token"
        self.consumer.userinfo_endpoint = "http://example.com/userinfo"

        self.consumer._backup("sid")

        self.consumer.authorization_endpoint = AUTHZ_ORG_URL
        self.consumer.token_endpoint = "http://example.org/token"
        self.consumer.userinfo_endpoint = ""

        assert self.consumer.authorization_endpoint == AUTHZ_ORG_URL
        assert self.consumer.token_endpoint == "http://example.org/token"
        assert self.consumer.userinfo_endpoint == ""

        self.consumer.update("sid")

        assert self.consumer.authorization_endpoint == AUTHZ_ORG_URL
        assert self.consumer.token_endpoint == "http://example.org/token"
        assert self.consumer.userinfo_endpoint == "http://example.com/userinfo"

    def test_begin(self):
        self.consumer.authorization_endpoint = AUTHZ_URL
        self.consumer.keyjar[""].append(KC_RSA)
        # self.consumer.keyjar.set_sign_key(rsapub, "rsa")
        #self.consumer.keyjar.set_verify_key(rsapub, "rsa")

        srv = Server()
        srv.keyjar = SRVKEYS
        print "redirect_uris", self.consumer.redirect_uris
        print "config", self.consumer.config
        sid, location = self.consumer.begin("openid", "code")
        print location
        authreq = srv.parse_authorization_request(url=location)
        print authreq.keys()
        assert _eq(authreq.keys(), ['request', 'state', 'max_age', 'claims',
                                    'response_type', 'client_id', 'scope',
                                    'redirect_uri'])

        assert authreq["state"] == sid
        assert authreq["scope"] == self.consumer.config["scope"]
        assert authreq["client_id"] == self.consumer.client_id

    def test_begin_file(self):
        tempdir = tempfile.mkdtemp()
        self.consumer.config["request_method"] = "file"
        self.consumer.config["temp_dir"] = tempdir
        self.consumer.config["temp_path"] = tempdir
        self.consumer.config["authz_page"] = "/authz"
        srv = Server()
        srv.keyjar = SRVKEYS

        sid, location = self.consumer.begin("openid", "code",
                                            path="http://localhost:8087")
        print location
        # vkeys = {".":srv.keyjar.get_verify_key()}
        authreq = srv.parse_authorization_request(url=location)
        print authreq.keys()
        assert _eq(authreq.keys(), ['max_age', 'state', 'redirect_uri',
                                    'response_type', 'client_id', 'scope',
                                    'claims', 'request_uri'])

        assert authreq["state"] == sid
        assert authreq["scope"] == self.consumer.config["scope"]
        assert authreq["client_id"] == self.consumer.client_id
        assert authreq["redirect_uri"].startswith("http://localhost:8087/authz")
        # Cleanup the file we have created
        shutil.rmtree(tempdir)

    def test_complete(self):
        mfos = MyFakeOICServer("http://localhost:8088")
        mfos.keyjar = SRVKEYS

        self.consumer.http_request = mfos.http_request
        _state = "state0"
        self.consumer.nonce = rndstr()
        self.consumer.redirect_uris = ["https://example.com/cb"]
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
            state=_state, request_args=args)
        assert result.status_code == 302
        print "redirect_uris", self.consumer.redirect_uris
        print result.headers["location"]

        assert result.headers["location"].startswith(
            self.consumer.redirect_uris[0])
        _, query = result.headers["location"].split("?")

        # vkeys = {".": self.consumer.keyjar.get_verify_key()}

        self.consumer.parse_response(AuthorizationResponse, info=query,
                                     sformat="urlencoded")

        resp = self.consumer.complete(_state)
        print resp
        assert resp.type() == "AccessTokenResponse"
        print resp.keys()
        assert _eq(resp.keys(), ['token_type', 'state', 'access_token',
                                 'scope', 'expires_in', 'refresh_token'])

        assert resp["state"] == _state

    def test_parse_authz(self):
        mfos = MyFakeOICServer("http://localhost:8088")
        mfos.keyjar = SRVKEYS

        self.consumer.http_request = mfos.http_request
        _state = "state0"
        self.consumer.nonce = rndstr()
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
            state=_state, request_args=args)

        print self.consumer.sdb["state0"].keys()
        part = self.consumer.parse_authz(query=result.headers["location"])
        print part
        atr = part[0]
        assert part[1] is None
        assert part[2] is None

        assert atr.type() == "AuthorizationResponse"
        assert atr["state"] == _state
        assert "code" in atr

    def test_parse_authz_implicit(self):
        mfos = MyFakeOICServer("http://localhost:8088")
        mfos.keyjar = SRVKEYS

        self.consumer.http_request = mfos.http_request
        self.consumer.config["response_type"] = ["token"]
        _state = "statxxx"
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "implicit",
            "scope": ["openid"],
            "redirect_uri": "http://localhost:8088/cb"
        }

        result = self.consumer.do_authorization_request(
            state=_state, request_args=args)

        part = self.consumer.parse_authz(query=result.headers["location"])
        print part
        assert part[0] is None
        atr = part[1]
        assert part[2] is None

        assert atr.type() == "AccessTokenResponse"
        assert atr["state"] == _state
        assert "access_token" in atr


def test_complete_secret_auth():
    consumer = Consumer(SessionDB(SERVER_INFO["issuer"]), CONFIG,
                        CLIENT_CONFIG, SERVER_INFO)
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
    _state = "state0"
    consumer.nonce = rndstr()
    consumer.client_secret = "hemlig"
    consumer.secret_type = "basic"
    del consumer.config["password"]

    args = {
        "client_id": consumer.client_id,
        "response_type": "code",
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=_state,
                                               request_args=args)
    assert result.status_code == 302
    assert result.headers["location"].startswith(consumer.redirect_uris[0])
    _, query = result.headers["location"].split("?")

    consumer.parse_response(AuthorizationResponse, info=query,
                            sformat="urlencoded")

    resp = consumer.complete(_state)
    print resp
    assert resp.type() == "AccessTokenResponse"
    print resp.keys()
    assert _eq(resp.keys(), ['token_type', 'state', 'access_token',
                             'scope', 'expires_in', 'refresh_token'])

    assert resp["state"] == _state


def test_complete_auth_token():
    consumer = Consumer(SessionDB(SERVER_INFO["issuer"]), CONFIG,
                        CLIENT_CONFIG, SERVER_INFO)
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
    _state = "state0"
    consumer.nonce = rndstr()
    consumer.client_secret = "hemlig"
    consumer.secret_type = "basic"
    consumer.config["response_type"] = ["code", "token"]

    args = {
        "client_id": consumer.client_id,
        "response_type": consumer.config["response_type"],
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=_state,
                                               request_args=args)
    consumer._backup("state0")

    assert result.status_code == 302
    # assert result.location.startswith(consumer.redirect_uri[0])
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
    assert _eq(auth.keys(), ['code', 'access_token', 'expires_in',
                             'token_type', 'state', 'scope', 'refresh_token'])
    assert _eq(acc.keys(), ['token_type', 'state', 'access_token', 'scope',
                            'expires_in', 'refresh_token'])


def test_complete_auth_token_idtoken():
    consumer = Consumer(SessionDB(SERVER_INFO["issuer"]), CONFIG,
                        CLIENT_CONFIG, SERVER_INFO)
    consumer.keyjar = CLIKEYS
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
    _state = "state0"
    consumer.nonce = rndstr()
    consumer.client_secret = "hemlig"
    consumer.secret_type = "basic"
    consumer.config["response_type"] = ["id_token", "token"]
    consumer.registration_response = {
        "id_token_signed_response_alg": "RS256",
    }
    consumer.provider_info = {"issuer": "http://localhost:8088/"}  # abs min
    consumer.authz_req = {}  # Store AuthzReq with state as key

    args = {
        "client_id": consumer.client_id,
        "response_type": consumer.config["response_type"],
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=_state,
                                               request_args=args)
    # consumer._backup("state0")

    assert result.status_code == 302
    #assert result.location.startswith(consumer.redirect_uri[0])
    _, query = result.headers["location"].split("?")
    print query
    part = consumer.parse_authz(query=query,
                                algs=consumer.sign_enc_algs("id_token"))
    print part
    auth = part[0]
    atr = part[1]
    assert part[2] is None


    #print auth.dictionary()
    #print acc.dictionary()
    assert auth is None
    assert atr.type() == "AccessTokenResponse"
    assert _eq(atr.keys(), ['access_token', 'id_token', 'expires_in',
                            'token_type', 'state', 'scope'])

    consumer.verify_id_token(atr["id_token"], consumer.authz_req[atr["state"]])


def test_userinfo():
    consumer = Consumer(SessionDB(SERVER_INFO["issuer"]), CONFIG,
                        CLIENT_CONFIG, SERVER_INFO)
    consumer.keyjar = CLIKEYS
    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
    _state = "state0"
    consumer.nonce = rndstr()
    consumer.secret_type = "basic"
    consumer.set_client_secret("hemligt")
    consumer.keyjar = CLIKEYS

    args = {
        "client_id": consumer.client_id,
        "response_type": "code",
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=_state,
                                               request_args=args)
    assert result.status_code == 302
    assert result.headers["location"].startswith(consumer.redirect_uris[0])
    _, query = result.headers["location"].split("?")

    consumer.parse_response(AuthorizationResponse, info=query,
                            sformat="urlencoded")

    consumer.complete(_state)

    result = consumer.get_user_info(_state)
    print result
    assert result.type() == "OpenIDSchema"
    assert _eq(result.keys(), ['name', 'email', 'verified', 'nickname', 'sub'])


def test_sign_userinfo():
    consumer = Consumer(SessionDB(SERVER_INFO["issuer"]), CONFIG,
                        CLIENT_CONFIG, SERVER_INFO)
    consumer.keyjar = CLIKEYS

    mfos = MyFakeOICServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    mfos.userinfo_signed_response_alg = "RS256"

    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
    _state = "state0"
    consumer.nonce = rndstr()
    consumer.secret_type = "basic"
    consumer.set_client_secret("hemligt")
    consumer.keyjar = CLIKEYS
    consumer.client_prefs = {"userinfo_signed_response_alg": "RS256"}
    consumer.provider_info = {
        "userinfo_endpoint": "http://localhost:8088/userinfo",
        "issuer": "http://localhost:8088/"}
    del consumer.config["request_method"]

    args = {
        "client_id": consumer.client_id,
        "response_type": "code",
        "scope": ["openid"],
    }

    sid, location = consumer.begin("openid", "code")
    print location

    result = consumer.do_authorization_request(state=_state,
                                               request_args=args)
    assert result.status_code == 302
    assert result.headers["location"].startswith(consumer.redirect_uris[0])
    _, query = result.headers["location"].split("?")

    consumer.parse_response(AuthorizationResponse, info=query,
                            sformat="urlencoded")

    consumer.complete(_state)

    result = consumer.get_user_info(_state)
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


SYMKEY = SYMKey(key="TestPassword")


def _faulty_id_token():
    idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
             'iss': 'https://alpha.cloud.nds.rub.de', 'exp': 1420823073,
             'iat': 1420822473, 'aud': 'TestClient'}
    idts = IdToken(**idval)

    _signed_jwt = idts.to_jwt(key=[SYMKEY], algorithm="HS256")

    # Mess with the signed id_token
    p = _signed_jwt.split(".")
    p[2] = "aaa"

    return ".".join(p)


def test_faulty_id_token():
    _faulty_signed_jwt = _faulty_id_token()
    try:
        _ = IdToken().from_jwt(_faulty_signed_jwt, key=[SYMKEY])
    except BadSignature:
        pass
    else:
        assert False

    # What if no verification key is given ?
    # Should also result in an exception
    try:
        _ = IdToken().from_jwt(_faulty_signed_jwt)
    except MissingSigningKey:
        pass
    else:
        assert False


def test_faulty_id_token_in_access_token_response():
    c = Consumer(None, None)
    c.keyjar.add_symmetric("", "TestPassword", ["sig"])

    _info = {"access_token": "accessTok", "id_token": _faulty_id_token(),
             "token_type": "Bearer", "expires_in": 3600}

    _json = json.dumps(_info)
    try:
        resp = c.parse_response(AccessTokenResponse, _json, sformat="json")
    except BadSignature:
        pass
    else:
        assert False


def test_faulty_idtoken_from_accesstoken_endpoint():
    consumer = Consumer(SessionDB(SERVER_INFO["issuer"]), CONFIG,
                        CLIENT_CONFIG, SERVER_INFO)
    consumer.keyjar = CLIKEYS
    mfos = MITMServer("http://localhost:8088")
    mfos.keyjar = SRVKEYS
    consumer.http_request = mfos.http_request
    consumer.redirect_uris = ["http://example.com/authz"]
    _state = "state0"
    consumer.nonce = rndstr()
    consumer.client_secret = "hemlig"
    consumer.secret_type = "basic"
    consumer.config["response_type"] = ["id_token"]

    args = {
        "client_id": consumer.client_id,
        "response_type": consumer.config["response_type"],
        "scope": ["openid"],
    }

    result = consumer.do_authorization_request(state=_state,
                                               request_args=args)
    consumer._backup("state0")

    assert result.status_code == 302
    # assert result.location.startswith(consumer.redirect_uri[0])
    _, query = result.headers["location"].split("?")
    print query
    try:
        consumer.parse_authz(query=query)
    except BadSignature:
        pass
    else:
        assert False


if __name__ == "__main__":
    # test_sign_userinfo()
    # t = TestOICConsumer()
    # t.setup_class()
    # t.test_begin()
    test_complete_auth_token_idtoken()
