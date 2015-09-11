# from Cookie import SimpleCookie
import json
import os
from time import time
import datetime

import pytest

from six import iteritems

from six.moves.http_cookies import SimpleCookie
from six.moves.urllib.parse import urlparse, parse_qs, urlencode
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
from oic.oic.provider import Provider, InvalidRedirectURIError
from oic.utils.time_util import epoch_in_a_while
from utils_for_tests import _eq

__author__ = 'rohe0002'

CLIENT_CONFIG = {
    "client_id": "number5",
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "scope": ["openid"],
    "response_type": ["code"],
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
    "flows_supported": ["code", "token", "code token"],
}

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_SYM = KeyBundle([{"kty": "oct", "key": CLIENT_SECRET, "use": "ver"},
                    {"kty": "oct", "key": CLIENT_SECRET, "use": "sig"}])
KC_SYM2 = KeyBundle([{"kty": "oct", "key": "drickyoughurt", "use": "sig"},
                     {"kty": "oct", "key": "drickyoughurt", "use": "ver"}])

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/keys"))
KC_RSA = keybundle_from_local_file(os.path.join(BASE_PATH, "rsa.key"),
                                   "RSA", ["ver", "sig"])

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_SYM, KC_RSA]
KEYJAR["number5"] = [KC_SYM2, KC_RSA]
KEYJAR[""] = KC_RSA

CDB = {
    "number5": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "post_logout_redirect_uris": [("https://example.com/post_logout", None)],
        "client_salt": "salted"
    },
    "a1b2c3": {
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "client_salt": "salted"
    },
    "client0": {
        "redirect_uris": [("http://www.example.org/authz", None)],
        "client_salt": "salted"
    },
    CLIENT_ID: {
        "client_secret": CLIENT_SECRET,
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "client_salt": "salted"
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


class TestProvider(object):
    @pytest.fixture(autouse=True)
    def create_provider(self):
        self.provider = Provider("pyoicserv", SessionDB(SERVER_INFO["issuer"]),
                                 CDB,
                                 AUTHN_BROKER, USERINFO,
                                 AUTHZ, verify_client, SYMKEY, urlmap=URLMAP,
                                 keyjar=KEYJAR)
        self.provider.baseurl = self.provider.name

        self.cons = Consumer({}, CONSUMER_CONFIG, CLIENT_CONFIG,
                             server_info=SERVER_INFO, )
        self.cons.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}
        self.cons.keyjar[""] = KC_RSA

    def test_authorization_endpoint(self):
        bib = {"scope": ["openid"],
               "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               "redirect_uri": "http://localhost:8087/authz",
               "response_type": ["code"],
               "client_id": "a1b2c3",
               "nonce": "Nonce"}

        arq = AuthorizationRequest(**bib)

        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        parsed = parse_qs(urlparse(resp.message).query)
        assert parsed["scope"] == ["openid"]
        assert parsed["state"][0] == "id-6da9ca0cc23959f5f33e8becd9b08cae"
        assert "code" in parsed

    def test_authorization_endpoint_request(self):
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
        _keys = self.provider.keyjar.get_signing_key(key_type="RSA")
        req["request"] = make_openid_request(req, _keys, idtoken_claims=ic,
                                             request_object_signing_alg="RS256")

        with pytest.raises(FailedAuthentication):
            self.provider.authorization_endpoint(request=req.to_urlencoded())

    def test_authorization_endpoint_id_token(self):
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

        sdb = self.provider.sdb
        ae = AuthnEvent("userX", "salt")
        sid = sdb.create_authz_session(ae, areq)
        sdb.do_sub(sid, "client_salt")
        _info = sdb[sid]
        # All this is jut removed when the id_token is constructed
        # The proper information comes from the session information
        _user_info = IdToken(iss="https://foo.example.om", sub="foo",
                             aud=bib["client_id"],
                             exp=epoch_in_a_while(minutes=10),
                             acr="2", nonce=bib["nonce"])

        idt = self.provider.id_token_as_signed_jwt(_info,
                                                   access_token="access_token",
                                                   user_info=_user_info)

        req["id_token"] = idt
        query_string = req.to_urlencoded()

        # client_id not in id_token["aud"] so login required
        resp = self.provider.authorization_endpoint(request=query_string,
                                                    cookie="FAIL")
        parsed_resp = parse_qs(urlparse(resp.message).fragment)
        assert parsed_resp["error"][0] == "login_required"

        req["client_id"] = "client_1"
        query_string = req.to_urlencoded()

        # client_id is in id_token["aud"] so no login required
        resp = self.provider.authorization_endpoint(request=query_string,
                                                    cookie="FAIL")

        assert resp.message.startswith("http://localhost:8087/authz")

    def test_authenticated(self):
        _state, location = self.cons.begin("openid", "code",
                                           path="http://localhost:8087")

        resp = self.provider.authorization_endpoint(
            request=urlparse(location).query)

        parsed = urlparse(resp.message)
        assert "{}://{}{}".format(parsed.scheme, parsed.netloc,
                                  parsed.path) == "http://localhost:8087/authz"

        part = self.cons.parse_authz(query=resp.message)

        aresp = part[0]
        assert part[1] is None
        assert part[2] is None

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ['code', 'state', 'scope'])

        assert _eq(self.cons.grant[_state].keys(),
                   ['code', 'tokens', 'id_token', 'exp_in', 'seed',
                    'grant_expiration_time'])

    def test_authenticated_url(self):
        state, location = self.cons.begin("openid", "code",
                                          path="http://localhost:8087")

        resp = self.provider.authorization_endpoint(
            request=urlparse(location).query)

        aresp = self.cons.parse_response(AuthorizationResponse, resp.message,
                                         sformat="urlencoded")

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ['code', 'state', 'scope'])

    def test_authenticated_hybrid(self):
        _state, location = self.cons.begin(
            scope="openid email claims_in_id_token",
            response_type="code id_token",
            path="http://localhost:8087")

        resp = self.provider.authorization_endpoint(
            request=urlparse(location).query)

        part = self.cons.parse_authz(resp.message)

        aresp = part[0]
        assert part[1] is None
        assert part[2] is not None

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ['scope', 'state', 'code', 'id_token'])

        assert _eq(self.cons.grant[_state].keys(),
                   ['code', 'id_token', 'tokens',
                    'exp_in',
                    'grant_expiration_time', 'seed'])
        id_token = part[2]
        assert isinstance(id_token, IdToken)
        assert _eq(id_token.keys(),
                   ['nonce', 'c_hash', 'sub', 'iss', 'acr', 'exp', 'auth_time',
                    'iat', 'aud'])

    def test_authenticated_token(self):
        _state, location = self.cons.begin("openid", response_type="token",
                                           path="http://localhost:8087")

        resp = self.provider.authorization_endpoint(
            request=urlparse(location).query)
        parsed = parse_qs(urlparse(resp.message).fragment)
        assert parsed["token_type"][0] == "Bearer"
        assert "access_token" in parsed

    def test_authenticated_none(self):
        _state, location = self.cons.begin("openid", response_type="none",
                                           path="http://localhost:8087")

        resp = self.provider.authorization_endpoint(
            request=location.split("?")[1])
        parsed = urlparse(resp.message)
        assert "{}://{}{}".format(parsed.scheme, parsed.netloc,
                                  parsed.path) == "http://localhost:8087/authz"
        assert "state" in parse_qs(parsed.query)

    def test_token_endpoint(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id=CLIENT_ID,
                                       response_type="code",
                                       scope=["openid"])

        _sdb = self.provider.sdb
        sid = _sdb.token.key(user="sub", areq=authreq)
        access_grant = _sdb.token(sid=sid)
        ae = AuthnEvent("user", "salt")
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
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant, client_id=CLIENT_ID,
                                  redirect_uri="http://example.com/authz",
                                  client_secret=CLIENT_SECRET)

        txt = areq.to_urlencoded()

        resp = self.provider.token_endpoint(request=txt)
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        assert _eq(atr.keys(),
                   ['token_type', 'id_token', 'access_token', 'scope',
                    'expires_in', 'refresh_token'])

    def test_token_endpoint_unauth(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client_1")

        _sdb = self.provider.sdb
        sid = _sdb.token.key(user="sub", areq=authreq)
        access_grant = _sdb.token(sid=sid)
        ae = AuthnEvent("user", "salt")
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
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client_1",
                                  client_secret="secret", )

        txt = areq.to_urlencoded()

        resp = self.provider.token_endpoint(request=txt, remote_user="client2",
                                            request_method="POST")
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "unauthorized_client"

    def test_authz_endpoint(self):
        _state, location = self.cons.begin("openid",
                                           response_type=["code", "token"],
                                           path="http://localhost:8087")
        resp = self.provider.authorization_endpoint(
            request=urlparse(location).query)

        parsed = parse_qs(urlparse(resp.message).fragment)
        assert parsed["token_type"][0] == "Bearer"
        assert "code" in parsed

    def test_idtoken(self):
        AREQ = AuthorizationRequest(response_type="code", client_id=CLIENT_ID,
                                    redirect_uri="http://example.com/authz",
                                    scope=["openid"], state="state000")

        ae = AuthnEvent("sub", "salt")
        sid = self.provider.sdb.create_authz_session(ae, AREQ)
        self.provider.sdb.do_sub(sid, "client_salt")
        session = self.provider.sdb[sid]

        id_token = self.provider.id_token_as_signed_jwt(session)
        assert len(id_token.split(".")) == 3

    def test_idtoken_with_extra_claims(self):
        areq = AuthorizationRequest(response_type="code", client_id=CLIENT_ID,
                                    redirect_uri="http://example.com/authz",
                                    scope=["openid"], state="state000")
        aevent = AuthnEvent("sub", "salt")
        sid = self.provider.sdb.create_authz_session(aevent, areq)
        self.provider.sdb.do_sub(sid, "client_salt")
        session = self.provider.sdb[sid]

        claims = {'k1': 'v1', 'k2': 32}

        id_token = self.provider.id_token_as_signed_jwt(session,
                                                        extra_claims=claims)
        parsed = IdToken().from_jwt(id_token, keyjar=self.provider.keyjar)

        for key, value in iteritems(claims):
            assert parsed[key] == value

    def test_userinfo_endpoint(self):
        self.cons.client_secret = "drickyoughurt"
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"
        state, location = self.cons.begin("openid", "token",
                                          path="http://localhost:8087")

        resp = self.provider.authorization_endpoint(
            request=urlparse(location).query)

        # redirect
        atr = AuthorizationResponse().deserialize(
            urlparse(resp.message).fragment, "urlencoded")

        uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")

        resp = self.provider.userinfo_endpoint(request=uir.to_urlencoded())
        ident = OpenIDSchema().deserialize(resp.message, "json")
        assert _eq(ident.keys(), ['nickname', 'sub', 'name', 'email'])

    def test_check_session_endpoint(self):
        session = {"sub": "UserID", "client_id": "number5"}
        idtoken = self.provider.id_token_as_signed_jwt(session)
        csr = CheckSessionRequest(id_token=idtoken)

        info = self.provider.check_session_endpoint(request=csr.to_urlencoded())
        idt = IdToken().deserialize(info.message, "json")
        assert _eq(idt.keys(), ['sub', 'aud', 'iss', 'acr', 'exp', 'iat'])
        assert idt["iss"] == self.provider.name + "/"

    def test_registration_endpoint(self):
        req = RegistrationRequest()

        req["application_type"] = "web"
        req["client_name"] = "My super service"
        req["redirect_uris"] = ["http://example.com/authz"]
        req["contacts"] = ["foo@example.com"]
        req["response_types"] = ["code"]

        resp = self.provider.registration_endpoint(request=req.to_json())

        regresp = RegistrationResponse().deserialize(resp.message, "json")
        assert _eq(regresp.keys(),
                   ['redirect_uris', 'contacts', 'application_type',
                    'client_name', 'registration_client_uri',
                    'client_secret_expires_at',
                    'registration_access_token',
                    'client_id', 'client_secret',
                    'client_id_issued_at', 'response_types'])

    def test_registration_endpoint_with_non_https_redirect_uri_implicit_flow(
            self):
        params = {"application_type": "web",
                  "redirect_uris": ["http://example.com/authz"],
                  "response_types": ["id_token", "token"]}
        req = RegistrationRequest(**params)
        resp = self.provider.registration_endpoint(request=req.to_json())

        assert resp.status == "400 Bad Request"
        error = json.loads(resp.message)
        assert error["error"] == "invalid_redirect_uri"

    def test_verify_redirect_uris_with_https_code_flow(self):
        params = {"application_type": "web",
                  "redirect_uris": ["http://example.com/authz"],
                  "response_types": ["code"]}
        request = RegistrationRequest(**params)
        verified_uris = self.provider._verify_redirect_uris(request)
        assert verified_uris == [("http://example.com/authz", None)]

    def test_verify_redirect_uris_with_non_https_redirect_uri_implicit_flow(self):
        params = {"application_type": "web",
                  "redirect_uris": ["http://example.com/authz"],
                  "response_types": ["id_token", "token"]}
        request = RegistrationRequest(**params)

        with pytest.raises(InvalidRedirectURIError) as exc_info:
            self.provider._verify_redirect_uris(request)

        assert str(exc_info.value) == "None https redirect_uri not allowed"

    @pytest.mark.network
    def test_registration_endpoint_openid4us(self):
        req = RegistrationRequest(
            **{'token_endpoint_auth_method': u'client_secret_post',
               'redirect_uris': [
                   u'https://connect.openid4.us:5443/phpRp/index.php/callback',
                   u'https://connect.openid4.us:5443/phpRp/authcheck.php/authcheckcb'],
               'jwks_uri': u'https://connect.openid4.us:5443/phpRp/rp/rp.jwk',
               'userinfo_encrypted_response_alg': u'RSA1_5',
               'contacts': [u'me@example.com'],
               'userinfo_encrypted_response_enc': u'A128CBC-HS256',
               'application_type': u'web',
               'client_name': u'ABRP-17',
               'grant_types': [u'authorization_code', u'implicit'],
               'post_logout_redirect_uris': [
                   u'https://connect.openid4.us:5443/phpRp/index.php/logoutcb'],
               'subject_type': u'public',
               'response_types': [u'code', u'token', u'id_token', u'code token',
                                  u'code id_token', u'id_token token',
                                  u'code id_token token'],
               'policy_uri': u'https://connect.openid4.us:5443/phpRp/index.php/policy',
               'logo_uri': u'https://connect.openid4.us:5443/phpRp/media/logo.png'})

        resp = self.provider.registration_endpoint(request=req.to_json())

        regresp = RegistrationResponse().deserialize(resp.message, "json")
        assert _eq(regresp.keys(), list(req.keys()) +
                   ['registration_client_uri',
                    'client_secret_expires_at',
                    'registration_access_token',
                    'client_id', 'client_secret',
                    'client_id_issued_at'])

    def test_provider_key_setup(self, tmpdir):
        path = tmpdir.strpath
        provider = Provider("pyoicserv", SessionDB(SERVER_INFO["issuer"]), None,
                            None, None, None, None, "")
        provider.baseurl = "http://www.example.com"
        provider.key_setup(path, path, sig={"format": "jwk", "alg": "RSA"})

        keys = provider.keyjar.get_signing_key("RSA")
        assert len(keys) == 1
        assert provider.jwks_uri == "http://www.example.com/{}/jwks".format(
            path)

    @pytest.mark.parametrize("uri", [
        "http://example.org/foo",
        "http://example.com/cb",
        "http://example.org/cb?got=you",
        "http://example.org/cb/foo?got=you"
    ])
    def test_verify_redirect_uri_faulty_without_query(self, uri):
        rr = RegistrationRequest(operation="register",
                                 redirect_uris=["http://example.org/cb"],
                                 response_types=["code"])
        registration_req = rr.to_json()

        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(redirect_uri=uri,
                                    client_id=cid,
                                    response_type="code",
                                    scope="openid")

        with pytest.raises(RedirectURIError):
            self.provider._verify_redirect_uri(areq)

    @pytest.mark.parametrize("uri", [
        "http://example.org/cb",
        "http://example.org/cb/foo"
    ])
    def test_verify_redirect_uri_correct_without_query(self, uri):
        rr = RegistrationRequest(operation="register",
                                 redirect_uris=["http://example.org/cb"],
                                 response_types=["code"])
        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(redirect_uri=uri,
                                    client_id=cid,
                                    response_type="code",
                                    scope="openid")

        self.provider._verify_redirect_uri(areq)

    @pytest.mark.parametrize("uri", [
        "http://example.org/cb",
        "http://example.org/cb/foo",
        "http://example.org/cb?got=you",
        "http://example.org/cb?foo=you"
        "http://example.org/cb?foo=bar&got=you",
        "http://example.org/cb?foo=you&foo=bar"
    ])
    def test_registered_redirect_uri_faulty_with_query_component(self, uri):
        rr = RegistrationRequest(operation="register",
                                 redirect_uris=[
                                     "http://example.org/cb?foo=bar"],
                                 response_types=["code"])

        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(redirect_uri=uri,
                                    client_id=cid,
                                    scope="openid",
                                    response_type="code")

        with pytest.raises(RedirectURIError):
            self.provider._verify_redirect_uri(areq)

    def test_registered_redirect_uri_correct_with_query_component(self):
        rr = RegistrationRequest(operation="register",
                                 redirect_uris=[
                                     "http://example.org/cb?foo=bar"],
                                 response_types=["code"])

        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(
            redirect_uri="http://example.org/cb?foo=bar",
            client_id=cid, scope="openid",
            response_type="code")

        self.provider._verify_redirect_uri(areq)

    def test_key_rollover(self):
        provider2 = Provider("FOOP", {}, {}, None, None, None, None, "")
        provider2.keyjar = KEYJAR
        # Number of KeyBundles
        assert len(provider2.keyjar.issuer_keys[""]) == 1
        kb = ec_init({"type": "EC", "crv": "P-256", "use": ["sig"]})
        provider2.do_key_rollover(json.loads(kb.jwks()), "b%d")
        assert len(provider2.keyjar.issuer_keys[""]) == 2
        kb = ec_init({"type": "EC", "crv": "P-256", "use": ["sig"]})
        provider2.do_key_rollover(json.loads(kb.jwks()), "b%d")
        assert len(provider2.keyjar.issuer_keys[""]) == 3
        provider2.remove_inactive_keys(-1)
        assert len(provider2.keyjar.issuer_keys[""]) == 2

    def test_endsession_endpoint(self):
        resp = self.provider.endsession_endpoint("")
        self._assert_cookies_expired(resp.headers)

        # End session not allowed if no cookie is sent (can't determine session)
        resp = self.provider.endsession_endpoint("", cookie="FAIL")
        assert resp.status == "400 Bad Request"

    def test_endsession_endpoint_with_id_token_hint(self):
        id_token = self._auth_with_id_token()
        assert self.provider.sdb.get_sids_by_sub(
            id_token["sub"])  # verify we got valid session

        id_token_hint = id_token.to_jwt(algorithm="none")
        resp = self.provider.endsession_endpoint(
            urlencode({"id_token_hint": id_token_hint}))
        assert not self.provider.sdb.get_sids_by_sub(
            id_token["sub"])  # verify session has been removed
        self._assert_cookies_expired(resp.headers)

    def test_endsession_endpoint_with_post_logout_redirect_uri(self):
        id_token = self._auth_with_id_token()
        assert self.provider.sdb.get_sids_by_sub(
            id_token["sub"])  # verify we got valid session

        post_logout_redirect_uri = \
            CDB[CLIENT_CONFIG["client_id"]]["post_logout_redirect_uris"][0][0]
        resp = self.provider.endsession_endpoint(urlencode(
            {"post_logout_redirect_uri": post_logout_redirect_uri}))
        assert isinstance(resp, Redirect)
        assert not self.provider.sdb.get_sids_by_sub(
            id_token["sub"])  # verify session has been removed
        self._assert_cookies_expired(resp.headers)

    def test_session_state_in_auth_req_for_session_support(self):
        provider = Provider("foo", SessionDB(SERVER_INFO["issuer"]), CDB,
                            AUTHN_BROKER, USERINFO,
                            AUTHZ, verify_client, SYMKEY, urlmap=URLMAP,
                            keyjar=KEYJAR, capabilities={
                "check_session_iframe": "https://op.example.com/check_session"})

        req_args = {"scope": ["openid"],
                    "redirect_uri": "http://localhost:8087/authz",
                    "response_type": ["code"],
                    "client_id": "a1b2c3"
                    }
        areq = AuthorizationRequest(**req_args)
        resp = provider.authorization_endpoint(
            request=areq.to_urlencoded())
        aresp = self.cons.parse_response(AuthorizationResponse, resp.message,
                                         sformat="urlencoded")
        assert "session_state" in aresp

    def _assert_cookies_expired(self, http_headers):
        cookies_string = ";".join(
            [c[1] for c in http_headers if c[0] == "Set-Cookie"])
        all_cookies = SimpleCookie()
        all_cookies.load(cookies_string)

        now = datetime.datetime.now()
        for c in [self.provider.cookie_name, self.provider.session_cookie_name]:
            dt = datetime.datetime.strptime(all_cookies[c]["expires"],
                                            "%a, %d-%b-%Y %H:%M:%S GMT")
            assert dt < now  # make sure the cookies have expired to be cleared

    def _auth_with_id_token(self):
        state, location = self.cons.begin("openid", "id_token",
                                          path="http://localhost:8087")
        resp = self.provider.authorization_endpoint(
            request=location.split("?")[1])
        aresp = self.cons.parse_response(AuthorizationResponse, resp.message,
                                         sformat="urlencoded")
        return aresp["id_token"]

if __name__ == "__main__":
    t = TestProvider()
    t.create_provider()
    t.test_token_endpoint()