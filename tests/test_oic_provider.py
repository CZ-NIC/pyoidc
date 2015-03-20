from Cookie import SimpleCookie
import json
import locale
import os
from time import sleep, time
import datetime
import urllib

from mako.lookup import TemplateLookup

from oic.oauth2 import rndstr
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import Redirect
from oic.utils.userinfo import UserInfo
from oic.exception import RedirectURIError
from oic.exception import FailedAuthentication
from oic.utils.keyio import KeyBundle, ec_init
from oic.utils.keyio import KeyJar
from oic.utils.keyio import keybundle_from_local_file
from oic.oic.message import AuthorizationRequest
from oic.oic.message import RegistrationResponse
from oic.oic.message import OpenIDSchema
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AccessTokenRequest
from oic.oic.message import TokenErrorResponse
from oic.oic.message import AuthorizationResponse
from oic.oic.message import UserInfoRequest
from oic.oic.message import CheckSessionRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import IdToken
from oic.utils.sdb import SessionDB, AuthnEvent
from oic.oic import DEF_SIGN_ALG
from oic.oic import make_openid_request
from oic.oic.consumer import Consumer
from oic.oic.provider import Provider
from oic.utils.time_util import epoch_in_a_while


__author__ = 'rohe0002'

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    # "password": args.passwd,
    "scope": ["openid"],
    "response_type": ["code"],
    #"expire_in": 600,
    "user_info": {
        "name": None,
        "email": None,
        "nickname": None
    },
    "request_method": "param"
}

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://connect-op.heroku.com",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    # "userinfo_endpoint":"http://localhost:8088/user_info",
    # "check_id_endpoint":"http://localhost:8088/id_token",
    # "registration_endpoint":"https://connect-op.heroku.com/connect/client",
    # "scopes_supported":["openid","profile","email","address","PPID"],
    "flows_supported": ["code", "token", "code token"],
    #"identifiers_supported":["public","ppid"],
    #"x509_url":"https://connect-op.heroku.com/cert.pem"
}

BASE_PATH = os.path.dirname(os.path.abspath(__file__))

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_SYM = KeyBundle([{"kty": "oct", "key": CLIENT_SECRET, "use": "ver"},
                    {"kty": "oct", "key": CLIENT_SECRET, "use": "sig"}])
KC_SYM2 = KeyBundle([{"kty": "oct", "key": "drickyoughurt", "use": "sig"},
                     {"kty": "oct", "key": "drickyoughurt", "use": "ver"}])

KC_RSA = keybundle_from_local_file("%s/rsa.key" % BASE_PATH,
                                   "RSA", ["ver", "sig"])

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_SYM, KC_RSA]
KEYJAR["number5"] = [KC_SYM2, KC_RSA]
KEYJAR[""] = KC_RSA

CDB = {
    "number5": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        # "jwk_key": CONSUMER_CONFIG["key"],
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "post_logout_redirect_uris": [("https://example.com/post_logout", None)]
    },
    "a1b2c3": {
        "redirect_uris": [("http://localhost:8087/authz", None)]
    },
    "client0": {
        "redirect_uris": [("http://www.example.org/authz", None)]
    },
    CLIENT_ID: {
        "client_secret": CLIENT_SECRET,
        "redirect_uris": [("http://localhost:8087/authz", None)]
    }
}

USERDB = {
    "user": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "user"
    },
    "username": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "username"
    }
}

URLMAP = {CLIENT_ID: ["https://example.com/authz"]}

PASSWD = {"user": "password"}

ROOT = '../oc3/'
tl = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                    module_directory=ROOT + 'modules',
                    input_encoding='utf-8', output_encoding='utf-8')


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie == "FAIL":
            return None, 0
        else:
            return {"uid": self.user}, time()


# AUTHN = UsernamePasswordMako(None, "login.mako", tl, PASSWD, "authenticated")
AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = rndstr(16)  # symmetric key used to encrypt cookie info
USERINFO = UserInfo(USERDB)


def _eq(l1, l2):
    return set(l1) == set(l2)


class TestOICProvider(object):
    def setup_class(self):
        self.server = Provider("pyoicserv", SessionDB(SERVER_INFO["issuer"]), CDB,
                               AUTHN_BROKER, USERINFO,
                               AUTHZ, verify_client, SYMKEY, urlmap=URLMAP,
                               keyjar=KEYJAR)

        self.cons = Consumer({}, CONSUMER_CONFIG, CLIENT_CONFIG,
                               server_info=SERVER_INFO, )
        self.cons.behaviour = {"request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}
        self.cons.debug = True
        self.cons.keyjar[""] = KC_RSA

    def test_server_init(self):
        assert self.server
        assert self.server.authn_broker == AUTHN_BROKER
        print self.server.urlmap
        assert self.server.urlmap["client_1"] == ["https://example.com/authz"]

    def test_server_authorization_endpoint(self):
        bib = {"scope": ["openid"],
               "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               "redirect_uri": "http://localhost:8087/authz",
               "response_type": ["code"],
               "client_id": "a1b2c3",
               "nonce": "Nonce"}

        arq = AuthorizationRequest(**bib)

        resp = self.server.authorization_endpoint(request=arq.to_urlencoded())

        print resp.message
        assert resp.message

    def test_server_authorization_endpoint_request(self):
        bib = {"scope": ["openid"],
               "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               "redirect_uri": "http://localhost:8087/authz",
               "response_type": ["code", "id_token"],
               "client_id": "a1b2c3",
               "nonce": "Nonce",
               "prompt": ["none"]}

        req = AuthorizationRequest(**bib)
        # want to be someone else !
        ic = {"sub": {"value": "userX"}}
        _keys = self.server.keyjar.get_signing_key(key_type="RSA")
        req["request"] = make_openid_request(req, _keys, idtoken_claims=ic,
                                             algorithm="RS256")

        try:
            resp = self.server.authorization_endpoint(request=req.to_urlencoded())
        except FailedAuthentication:
            pass
        else:
            assert False


    def test_server_authorization_endpoint_id_token(self):
        bib = {"scope": ["openid"],
               "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               "redirect_uri": "http://localhost:8087/authz",
               "response_type": ["code", "id_token"],
               "client_id": "a1b2c3",
               "nonce": "Nonce",
               "prompt": ["none"]}

        req = AuthorizationRequest(**bib)
        areq = AuthorizationRequest(response_type="code",
                                    client_id="client_1",
                                    redirect_uri="http://example.com/authz",
                                    scope=["openid"], state="state000")

        sdb = self.server.sdb
        ae = AuthnEvent("userX")
        sid = sdb.create_authz_session(ae, areq)
        sdb.do_sub(sid)
        _info = sdb[sid]
        # All this is jut removed when the id_token is constructed
        # The proper information comes from the session information
        _user_info = IdToken(iss="https://foo.example.om", sub="foo",
                             aud=bib["client_id"], exp=epoch_in_a_while(minutes=10),
                             acr="2", nonce=bib["nonce"])

        print self.server.keyjar.issuer_keys
        print _user_info.to_dict()
        idt = self.server.id_token_as_signed_jwt(_info, access_token="access_token",
                                                 user_info=_user_info)

        req["id_token"] = idt
        query_string = req.to_urlencoded()

        # client_id not in id_token["aud"] so login required
        resp = self.server.authorization_endpoint(request=query_string, cookie="FAIL")

        print resp
        assert "error=login_required" in resp.message

        req["client_id"] = "client_1"
        query_string = req.to_urlencoded()

        # client_id is in id_token["aud"] so no login required
        resp = self.server.authorization_endpoint(request=query_string, cookie="FAIL")

        print resp.message
        assert resp.message.startswith("http://localhost:8087/authz")


    def test_server_authenticated(self):
        _state, location = self.cons.begin("openid", "code",
                                           path="http://localhost:8087")

        QUERY_STRING = location.split("?")[1]
        print QUERY_STRING
        resp = self.server.authorization_endpoint(request=QUERY_STRING)

        print resp.message

        assert resp.message.startswith("http://localhost:8087/authz")

        part = self.cons.parse_authz(query=location)

        aresp = part[0]
        assert part[1] is None
        assert part[2] is None

        # aresp = client.parse_response(AuthorizationResponse, location,
        # format="urlencoded",
        # state="id-6da9ca0cc23959f5f33e8becd9b08cae")

        print aresp.keys()
        assert aresp.type() == "AuthorizationResponse"
        assert _eq(aresp.keys(), ['request', 'state', 'redirect_uri',
                                  'response_type', 'client_id', 'claims', 'scope'])

        print self.cons.grant[_state].keys()
        assert _eq(self.cons.grant[_state].keys(),
                   ['code', 'tokens', 'id_token', 'exp_in', 'seed',
                    'grant_expiration_time'])


    def test_server_authenticated_1(self):
        state, location = self.cons.begin("openid", "code", path="http://localhost:8087")

        resp = self.server.authorization_endpoint(request=location.split("?")[1])

        print resp
        aresp = self.cons.parse_response(AuthorizationResponse, resp.message,
                                         sformat="urlencoded")

        print aresp.keys()
        assert aresp.type() == "AuthorizationResponse"
        assert _eq(aresp.keys(), ['request', 'state', 'redirect_uri', 'claims',
                                  'response_type', 'client_id', 'scope'])


    def test_server_authenticated_2(self):
        self.server.baseurl = self.server.name

        _state, location = self.cons.begin(scope="openid email claims_in_id_token",
                                           response_type="code id_token",
                                           path="http://localhost:8087")

        print location
        resp = self.server.authorization_endpoint(request=location.split("?")[1])

        print resp.message

        part = self.cons.parse_authz(resp.message)

        print part
        aresp = part[0]
        assert part[1] is None
        assert part[2] is not None

        # aresp = cons.parse_response(AuthorizationResponse, location,
        # sformat="urlencoded")

        print aresp.keys()
        assert aresp.type() == "AuthorizationResponse"
        assert _eq(aresp.keys(), ['scope', 'state', 'code', 'id_token'])

        print self.cons.grant[_state].keys()
        assert _eq(self.cons.grant[_state].keys(), ['code', 'id_token', 'tokens',
                                                    'exp_in',
                                                    'grant_expiration_time', 'seed'])
        id_token = part[2]
        assert isinstance(id_token, IdToken)
        print id_token.keys()
        assert _eq(id_token.keys(),
                   ['nonce', 'c_hash', 'sub', 'iss', 'acr', 'exp', 'auth_time',
                    'iat', 'aud'])


    def test_server_authenticated_token(self):
        _state, location = self.cons.begin("openid", response_type="token",
                                           path="http://localhost:8087")

        resp = self.server.authorization_endpoint(request=location.split("?")[1])

        txt = resp.message
        assert "access_token=" in txt
        assert "token_type=Bearer" in txt


    def test_server_authenticated_none(self):
        _state, location = self.cons.begin("openid", response_type="none",
                                           path="http://localhost:8087")

        resp = self.server.authorization_endpoint(request=location.split("?")[1])

        assert resp.message.startswith("http://localhost:8087/authz")
        query_part = resp.message.split("?")[1]
        print query_part
        assert "state" in query_part


    def test_token_endpoint(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id=CLIENT_ID,
                                       response_type="code",
                                       scope=["openid"])

        _sdb = self.server.sdb
        sid = _sdb.token.key(user="sub", areq=authreq)
        access_grant = _sdb.token(sid=sid)
        ae = AuthnEvent("user")
        _sdb[sid] = {
            "oauth_state": "authz",
            "authn_event": ae,
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid)

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant, client_id=CLIENT_ID,
                                  redirect_uri="http://example.com/authz",
                                  client_secret=CLIENT_SECRET)

        txt = areq.to_urlencoded()

        resp = self.server.token_endpoint(request=txt)
        print resp
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        print atr.keys()
        assert _eq(atr.keys(), ['token_type', 'id_token', 'access_token', 'scope',
                                'expires_in', 'refresh_token'])


    def test_token_endpoint_unauth(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client_1")

        _sdb = self.server.sdb
        sid = _sdb.token.key(user="sub", areq=authreq)
        access_grant = _sdb.token(sid=sid)
        ae = AuthnEvent("user")
        _sdb[sid] = {
            "authn_event": ae,
            "oauth_state": "authz",
            "authzreq": "",
            "client_id": "client_1",
            "code": access_grant,
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz"
        }
        _sdb.do_sub(sid)

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client_1", client_secret="secret", )

        print areq.to_dict()
        txt = areq.to_urlencoded()

        resp = self.server.token_endpoint(request=txt, remote_user="client2",
                                          request_method="POST")
        print resp
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        print atr.keys()
        assert _eq(atr.keys(), ['error'])


    def test_authz_endpoint(self):
        _state, location = self.cons.begin("openid", response_type=["code", "token"],
                                           path="http://localhost:8087")
        resp = self.server.authorization_endpoint(request=location.split("?")[1])
        print resp.message
        assert "token_type=Bearer" in resp.message
        assert "code=" in resp.message


    def test_idtoken(self):
        AREQ = AuthorizationRequest(response_type="code", client_id=CLIENT_ID,
                                    redirect_uri="http://example.com/authz",
                                    scope=["openid"], state="state000")

        ae = AuthnEvent("sub")
        sid = self.server.sdb.create_authz_session(ae, AREQ)
        self.server.sdb.do_sub(sid)
        session = self.server.sdb[sid]

        id_token = self.server.id_token_as_signed_jwt(session)
        print id_token
        assert len(id_token.split(".")) == 3


    def test_idtoken_with_extra_claims(self):
        areq = AuthorizationRequest(response_type="code", client_id=CLIENT_ID,
                                    redirect_uri="http://example.com/authz",
                                    scope=["openid"], state="state000")
        aevent = AuthnEvent("sub")
        sid = self.server.sdb.create_authz_session(aevent, areq)
        self.server.sdb.do_sub(sid)
        session = self.server.sdb[sid]

        claims = {'k1': 'v1', 'k2': 32}

        id_token = self.server.id_token_as_signed_jwt(session, extra_claims=claims)
        parsed = IdToken().from_jwt(id_token, keyjar=self.server.keyjar)

        print id_token
        for key, value in claims.iteritems():
            assert parsed[key] == value


    def test_userinfo_endpoint(self):
        self.cons.client_secret = "drickyoughurt"
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"

        state, location = self.cons.begin("openid", "token",
                                          path="http://localhost:8087")

        resp = self.server.authorization_endpoint(request=location.split("?")[1])

        line = resp.message
        path, query = line.split("#")

        # redirect
        atr = AuthorizationResponse().deserialize(query, "urlencoded")

        uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")

        resp3 = self.server.userinfo_endpoint(request=uir.to_urlencoded())
        ident = OpenIDSchema().deserialize(resp3.message, "json")
        print ident.keys()
        assert _eq(ident.keys(), ['nickname', 'sub', 'name', 'email'])

        # uid = server.sdb[sid]["authn_event"].uid
        # _sub = "%x" % hash(uid+server.sdb.base_url)
        #
        # assert ident["sub"] == hash(USERDB["username"]["sub"]+server.sdb.base_url)


    def test_check_session_endpoint(self):
        print self.server.name

        session = {"sub": "UserID", "client_id": "number5"}
        idtoken = self.server.id_token_as_signed_jwt(session)
        csr = CheckSessionRequest(id_token=idtoken)

        info = self.server.check_session_endpoint(request=csr.to_urlencoded())
        print info
        idt = IdToken().deserialize(info.message, "json")
        print idt.keys()
        assert _eq(idt.keys(), ['sub', 'aud', 'iss', 'acr', 'exp', 'iat'])
        assert idt["iss"] == self.server.name + "/"


    def test_registration_endpoint(self):
        req = RegistrationRequest()

        req["application_type"] = "web"
        req["client_name"] = "My super service"
        req["redirect_uris"] = ["http://example.com/authz"]
        req["contacts"] = ["foo@example.com"]
        req["response_types"] = ["code"]

        print req.to_dict()

        resp = self.server.registration_endpoint(request=req.to_json())

        print resp.message
        regresp = RegistrationResponse().deserialize(resp.message, "json")
        print regresp.keys()
        assert _eq(regresp.keys(), ['redirect_uris', 'contacts', 'application_type',
                                    'client_name', 'registration_client_uri',
                                    'client_secret_expires_at',
                                    'registration_access_token',
                                    'client_id', 'client_secret',
                                    'client_id_issued_at', 'response_types'])


    def test_provider_key_setup(self):
        provider = Provider("pyoicserv", SessionDB(SERVER_INFO["issuer"]), None,
                            None, None, None, None, "")
        provider.baseurl = "http://www.example.com/"
        provider.key_setup("static", sig={"format": "jwk", "alg": "RSA"})

        keys = provider.keyjar.get_signing_key("RSA")
        assert len(keys) == 1
        assert provider.jwks_uri == "http://www.example.com/static/jwks"

    def _client_id(self, cdb):
        cid = None
        for k, item in cdb.items():
            if item in cdb.keys():
                cid = item
                break

        return cid

    def test_registered_redirect_uri_without_query_component(self):
        provider = Provider("FOO", {}, {}, None, None, None, None, "")
        rr = RegistrationRequest(operation="register",
                                 redirect_uris=["http://example.org/cb"],
                                 response_types=["code"])

        registration_req = rr.to_json()

        provider.registration_endpoint(request=registration_req)

        correct = [
            "http://example.org/cb",
            "http://example.org/cb/foo",
            "http://example.org/cb?got=you",
            "http://example.org/cb/foo?got=you"
        ]
        faulty = [
            "http://example.org/foo",
            "http://example.com/cb",
        ]

        cid = self._client_id(provider.cdb)

        for ruri in faulty:
            areq = AuthorizationRequest(redirect_uri=ruri,
                                        client_id=cid,
                                        response_type="code",
                                        scope="openid")

            print areq
            try:
                provider._verify_redirect_uri(areq)
                assert False
            except RedirectURIError:
                pass

        for ruri in correct:
            areq = AuthorizationRequest(redirect_uri=ruri,
                                        client_id=cid,
                                        response_type="code", scope="openid")

            print areq
            try:
                provider._verify_redirect_uri(areq)
            except RedirectURIError, err:
                print err
                assert False


    def test_registered_redirect_uri_with_query_component(self):
        provider2 = Provider("FOOP", {}, {}, None, None, None, None, "")

        rr = RegistrationRequest(operation="register",
                                 redirect_uris=["http://example.org/cb?foo=bar"],
                                 response_types=["code"])

        registration_req = rr.to_json()
        resp = provider2.registration_endpoint(request=registration_req)

        regresp = RegistrationResponse().from_json(resp.message)

        print regresp.to_dict()

        faulty = [
            "http://example.org/cb",
            "http://example.org/cb/foo",
            "http://example.org/cb?got=you",
            "http://example.org/cb?foo=you"
        ]
        correct = [
            "http://example.org/cb?foo=bar",
            "http://example.org/cb?foo=bar&got=you",
            "http://example.org/cb?foo=bar&foo=you"
        ]

        cid = regresp["client_id"]

        for ruri in faulty:
            areq = AuthorizationRequest(redirect_uri=ruri,
                                        client_id=cid,
                                        scope="openid",
                                        response_type="code")

            print areq
            try:
                provider2._verify_redirect_uri(areq)
            except RedirectURIError:
                pass

        for ruri in correct:
            areq = AuthorizationRequest(redirect_uri=ruri,
                                        client_id=cid, scope="openid",
                                        response_type="code")

            resp = provider2._verify_redirect_uri(areq)
            print resp
            assert resp is None


    def test_key_rollover(self):
        provider2 = Provider("FOOP", {}, {}, None, None, None, None, "")
        provider2.keyjar = KEYJAR
        # Number of KeyBundles
        assert len(provider2.keyjar.issuer_keys[""]) == 1
        kb = ec_init({"type": "EC", "crv": "P-256", "use": ["sig"]})
        provider2.do_key_rollover(json.loads(kb.jwks()), "b%d")
        print provider2.keyjar
        assert len(provider2.keyjar.issuer_keys[""]) == 2
        kb = ec_init({"type": "EC", "crv": "P-256", "use": ["sig"]})
        provider2.do_key_rollover(json.loads(kb.jwks()), "b%d")
        print provider2.keyjar
        assert len(provider2.keyjar.issuer_keys[""]) == 3
        sleep(1)
        provider2.remove_inactive_keys(0)
        assert len(provider2.keyjar.issuer_keys[""]) == 2


    def test_endsession_endpoint(self):
        resp = self.server.endsession_endpoint("")
        self._assert_cookies_expired(resp.headers)

    def test_endsession_endpoint_with_id_token_hint(self):
        id_token = self._auth_with_id_token()
        assert self.server.sdb.get_sids_from_sub(id_token["sub"])  # verify we got valid session

        id_token_hint = id_token.to_jwt(algorithm="none")
        resp = self.server.endsession_endpoint(urllib.urlencode({"id_token_hint": id_token_hint}))
        assert not self.server.sdb.get_sids_from_sub(id_token["sub"])  # verify session has been removed
        self._assert_cookies_expired(resp.headers)

    def test_endsession_endpoint_with_post_logout_redirect_uri(self):
        id_token = self._auth_with_id_token()
        assert self.server.sdb.get_sids_from_sub(id_token["sub"])  # verify we got valid session

        post_logout_redirect_uri = CDB[CLIENT_CONFIG["client_id"]]["post_logout_redirect_uris"][0][0]
        resp = self.server.endsession_endpoint(urllib.urlencode({"post_logout_redirect_uri": post_logout_redirect_uri}))
        assert isinstance(resp, Redirect)
        assert not self.server.sdb.get_sids_from_sub(id_token["sub"])  # verify session has been removed
        self._assert_cookies_expired(resp.headers)

    def _assert_cookies_expired(self, http_headers):
        cookies_string = ";".join([c[1] for c in http_headers if c[0] == "Set-Cookie"])
        all_cookies = SimpleCookie()
        all_cookies.load(cookies_string)

        loc = locale.getlocale()
        locale.setlocale(locale.LC_ALL, 'C')  # strptime depends on locale, use default (C) locale

        now = datetime.datetime.now()
        for c in [self.server.cookie_name, self.server.session_cookie_name]:
            dt = datetime.datetime.strptime(all_cookies[c]["expires"], "%a, %d-%b-%Y %H:%M:%S GMT")
            assert dt < now  # make sure the cookies have expired to be cleared

        locale.setlocale(locale.LC_ALL, loc)  # restore saved locale

    def _auth_with_id_token(self):
        state, location = self.cons.begin("openid", "id_token", path="http://localhost:8087")
        resp = self.server.authorization_endpoint(request=location.split("?")[1])
        aresp = self.cons.parse_response(AuthorizationResponse, resp.message,
                                         sformat="urlencoded")
        return aresp["id_token"]