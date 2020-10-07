import copy
import os
import re
from http.cookies import SimpleCookie
from time import time
from typing import Any
from typing import Dict
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest
import requests
import responses

from oic import rndstr
from oic.exception import ParameterError
from oic.oauth2.message import ErrorResponse
from oic.oic import DEF_SIGN_ALG
from oic.oic.consumer import Consumer
from oic.oic.message import AuthorizationResponse
from oic.oic.message import EndSessionRequest
from oic.oic.provider import Provider
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import Response
from oic.utils.http_util import SeeOther
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.sdb import DictSessionBackend
from oic.utils.sdb import session_get
from oic.utils.userinfo import UserInfo

__author__ = "roland hedberg"

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "scope": ["openid"],
    "response_type": ["code"],
    "user_info": {"name": None, "email": None, "nickname": None},
    "request_method": "param",
}

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://connect-op.heroku.com",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

CLIENT_CONFIG = {"client_id": "number5", "config": {"issuer": SERVER_INFO["issuer"]}}

CLIENT_CONFIG_2 = {"client_id": "client0", "config": {"issuer": SERVER_INFO["issuer"]}}

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_SYM = KeyBundle(
    [
        {"kty": "oct", "key": CLIENT_SECRET, "use": "ver"},
        {"kty": "oct", "key": CLIENT_SECRET, "use": "sig"},
    ]
)
KC_SYM2 = KeyBundle(
    [
        {"kty": "oct", "key": "drickyoughurt", "use": "sig"},
        {"kty": "oct", "key": "drickyoughurt", "use": "ver"},
    ]
)

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/keys"))
KC_RSA = keybundle_from_local_file(
    os.path.join(BASE_PATH, "rsa.key"), "RSA", ["ver", "sig"]
)

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_SYM, KC_RSA]
KEYJAR["number5"] = [KC_SYM2, KC_RSA]
KEYJAR[""] = KC_RSA
KEYJAR["https://connect-op.heroku.com"] = KC_RSA

USERDB = {
    "user": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "user",
    },
    "username": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "username",
        "extra_claim": "extra_claim_value",
    },
}

URLMAP = {CLIENT_ID: ["https://example.com/authz"]}


class DummyEventStore(object):
    def __init__(self):
        self.db: Dict[str, str] = {}

    def store(self, typ, val):
        self.db[typ] = val


def _eq(l1, l2):
    return set(l1) == set(l2)


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie == "FAIL":
            return None, 0
        else:
            return {"uid": self.user}, time()


AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = rndstr(16)  # symmetric key used to encrypt cookie info
USERINFO = UserInfo(USERDB)


class TestProvider(object):
    CDB: Dict[str, Dict[str, Any]] = {
        "number5": {
            "password": "hemligt",
            "client_secret": "drickyoughurt",
            "redirect_uris": [("http://localhost:8087/authz", None)],
            "post_logout_redirect_uris": [("https://example.com/post_logout", None)],
            "client_salt": "salted",
            "response_types": [
                "code",
                "token",
                "code id_token",
                "none",
                "code token",
                "id_token",
            ],
        },
        "a1b2c3": {
            "redirect_uris": [("http://localhost:8088/authz", None)],
            "client_salt": "salted",
            "client_secret": "very_secret",
            "response_types": ["code", "token", "code id_token"],
        },
        "client0": {
            "redirect_uris": [("http://www.example.org/authz", None)],
            "client_secret": "very_secret",
            "post_logout_redirect_uris": [
                ("https://www.example.org/post_logout", None)
            ],
            "client_salt": "salted",
            "response_types": ["code", "token", "code id_token"],
        },
        CLIENT_ID: {
            "client_secret": CLIENT_SECRET,
            "redirect_uris": [("http://localhost:8087/authz", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token"],
        },
    }

    @pytest.fixture(autouse=True)
    def create_provider(self, session_db_factory):
        self.provider = Provider(
            SERVER_INFO["issuer"],
            session_db_factory(SERVER_INFO["issuer"]),
            self.CDB,
            AUTHN_BROKER,
            USERINFO,
            AUTHZ,
            verify_client,
            SYMKEY,
            urlmap=URLMAP,
            keyjar=KEYJAR,
        )
        self.provider.baseurl = self.provider.name
        self.provider.logout_verify_url = "https://127.0.0.1/logout_verify.html"

        self.cons = Consumer(
            DictSessionBackend(),
            CONSUMER_CONFIG.copy(),
            CLIENT_CONFIG,
            server_info=SERVER_INFO,
        )
        self.cons.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]
        }
        self.cons.keyjar[""] = KC_RSA
        self.cons.keyjar.import_jwks(
            self.provider.keyjar.export_jwks(), self.cons.issuer
        )

        self.cons2 = Consumer(
            {}, CONSUMER_CONFIG.copy(), CLIENT_CONFIG_2, server_info=SERVER_INFO
        )
        self.cons2.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]
        }
        self.cons2.keyjar[""] = KC_RSA

    def _code_auth(self):
        state, location = self.cons.begin(
            "openid", "code", path="http://localhost:8087"
        )
        return self.provider.authorization_endpoint(request=location.split("?")[1])

    def _code_auth2(self):
        state, location = self.cons2.begin(
            "openid", "code", path="http://www.example.org"
        )
        return self.provider.authorization_endpoint(request=location.split("?")[1])

    def _auth_with_id_token(self):
        state, location = self.cons.begin(
            "openid", "id_token", path="http://localhost:8087"
        )
        resp = self.provider.authorization_endpoint(request=location.split("?")[1])
        aresp = self.cons.parse_response(
            AuthorizationResponse, resp.message, sformat="urlencoded"
        )
        return aresp["id_token"]

    def _create_cookie(self, user, client_id, c_type="sso"):
        cd = CookieDealer(self.provider)
        set_cookie = cd.create_cookie(
            "{}][{}".format(user, client_id), c_type, self.provider.sso_cookie_name
        )
        cookies_string = set_cookie[1]
        all_cookies: SimpleCookie = SimpleCookie()

        try:
            cookies_string = cookies_string.decode()
        except (AttributeError, UnicodeDecodeError):
            pass

        all_cookies.load(cookies_string)

        return all_cookies

    def test_missing_post_logout_redirect_uri(self):
        esr = EndSessionRequest(state="foo")
        assert self.provider.verify_post_logout_redirect_uri(esr, CLIENT_ID) is None

    def test_wrong_post_logout_redirect_uri(self):
        self.provider.cdb[CLIENT_ID]["post_logout_redirect_uris"] = [
            "https://example.com/plru"
        ]
        esr = EndSessionRequest(
            state="foo", post_logout_redirect_uri="https://localhost:8087/plru"
        )
        assert self.provider.verify_post_logout_redirect_uri(esr, CLIENT_ID) is None

    def test_no_post_logout_redirect_uri(self):
        self.provider.cdb[CLIENT_ID]["post_logout_redirect_uris"] = [
            "https://example.com/plru",
            "https://example.com/plru2",
        ]
        esr = EndSessionRequest(state="foo")

        assert self.provider.verify_post_logout_redirect_uri(esr, CLIENT_ID) is None

    def test_let_user_verify_logout(self):
        self.provider.cdb[CLIENT_ID]["post_logout_redirect_uris"] = [
            "https://localhost:8087/plru"
        ]
        esr = EndSessionRequest(
            state="foo", post_logout_redirect_uri="https://localhost:8087/plru"
        )
        res = self.provider.let_user_verify_logout("user", esr, None, None)
        assert isinstance(res, Response)
        assert res.headers == [("Content-type", "text/html")]
        assert res.status_code == 200

    def test_let_user_verify_logout_with_cookie(self):
        self.provider.cdb[CLIENT_ID]["post_logout_redirect_uris"] = [
            "https://localhost:8087/plru"
        ]
        esr = EndSessionRequest(
            state="foo", post_logout_redirect_uri="https://localhost:8087/plru"
        )
        res = self.provider.let_user_verify_logout(
            "user", esr, [("Set-Cookie", "kaka")], None
        )
        assert isinstance(res, Response)
        assert set(res.headers) == {
            ("Content-type", "text/html"),
            ("Set-Cookie", "kaka"),
        }
        assert res.status_code == 200

    def test_let_user_verify_logout_with_redirect(self):
        self.provider.cdb[CLIENT_ID]["post_logout_redirect_uris"] = [
            "https://localhost:8087/plru"
        ]
        esr = EndSessionRequest(
            state="foo", post_logout_redirect_uri="https://localhost:8087/plru"
        )
        res = self.provider.let_user_verify_logout(
            "user", esr, None, "https://example.com/redirect"
        )
        assert isinstance(res, Response)
        assert set(res.headers) == {("Content-type", "text/html")}
        assert res.status_code == 200
        # make sure the redirect was propagated
        txt = '<input type="hidden" name="{}" value="{}"/>'.format(
            "post_logout_redirect_uri", "https://localhost:8087/plru"
        )
        assert txt in res.message

    def test_let_user_verify_logout_with_id_token_hint(self):
        self.provider.cdb[CLIENT_ID]["post_logout_redirect_uris"] = [
            "https://localhost:8087/plru"
        ]

        esr = EndSessionRequest(
            state="foo",
            post_logout_redirect_uri="https://localhost:8087/plru",
            id_token_hint="J.W.S",
        )
        res = self.provider.let_user_verify_logout("user", esr, None, None)
        assert isinstance(res, Response)
        assert set(res.headers) == {("Content-type", "text/html")}
        assert res.status_code == 200
        # make sure the id_token_hint was propagated
        txt = '<input type="hidden" name="{}" value="{}"/>'.format(
            "id_token_hint", "J.W.S"
        )
        assert txt in res.message

    def test_end_session_endpoint_with_cookie(self):
        self.provider.events = DummyEventStore()  # type: ignore

        self._code_auth()
        cookie = self._create_cookie("username", "number5")

        resp = self.provider.end_session_endpoint(
            urlencode({"state": "abcde"}), cookie=cookie
        )

        # returns a SeeOther instance
        p = urlparse(resp.message)
        qs = parse_qs(p.query)

        jwt_info = self.provider.unpack_signed_jwt(qs["sjwt"][0])

        assert jwt_info["state"] == "abcde"
        assert jwt_info["uid"] == "username"
        assert jwt_info["client_id"] == "number5"
        assert jwt_info["redirect_uri"] == "https://example.com/post_logout"

    def test_end_session_endpoint_with_wrong_cookie(self):
        # Need cookie and ID Token to figure this out
        id_token = self._auth_with_id_token()
        assert session_get(
            self.provider.sdb, "sub", id_token["sub"]
        )  # verify we got valid session

        id_token_hint = id_token.to_jwt(algorithm="none")
        cookie = self._create_cookie("diggins", "number5")

        resp = self.provider.end_session_endpoint(
            urlencode({"id_token_hint": id_token_hint}), cookie=cookie
        )

        assert isinstance(resp, Response)
        _err = ErrorResponse().from_json(resp.message)
        assert _err["error"] == "invalid_request"
        assert _err["error_description"] == "Wrong user"

    def test_end_session_endpoint_with_cookie_wrong_user(self):
        # Need cookie and ID Token to figure this out
        id_token = self._auth_with_id_token()
        assert session_get(self.provider.sdb, "sub", id_token["sub"])

        id_token_hint = id_token.to_jwt(algorithm="none")
        cookie = self._create_cookie("diggins", "number5")

        resp = self.provider.end_session_endpoint(
            urlencode({"id_token_hint": id_token_hint}), cookie=cookie
        )

        assert isinstance(resp, Response)
        _err = ErrorResponse().from_json(resp.message)
        assert _err["error"] == "invalid_request"
        assert _err["error_description"] == "Wrong user"

    def test_end_session_endpoint_with_cookie_wrong_client(self):
        # Need cookie and ID Token to figure this out
        id_token = self._auth_with_id_token()
        assert session_get(self.provider.sdb, "sub", id_token["sub"])

        id_token_hint = id_token.to_jwt(algorithm="none")
        # Wrong client_id
        cookie = self._create_cookie("username", "a1b2c3")

        resp = self.provider.end_session_endpoint(
            urlencode({"id_token_hint": id_token_hint}), cookie=cookie
        )

        assert isinstance(resp, Response)
        _err = ErrorResponse().from_json(resp.message)
        assert _err["error"] == "invalid_request"

    def test_end_session_endpoint_with_cookie_dual_login(self):
        self._code_auth()
        self._code_auth2()
        cookie = self._create_cookie("username", "client0")

        resp = self.provider.end_session_endpoint(
            urlencode({"state": "abcde"}), cookie=cookie
        )

        # returns a SeeOther instance
        p = urlparse(resp.message)
        qs = parse_qs(p.query)

        jwt_info = self.provider.unpack_signed_jwt(qs["sjwt"][0])

        assert jwt_info["state"] == "abcde"
        assert jwt_info["uid"] == "username"
        assert jwt_info["client_id"] == "client0"
        assert jwt_info["redirect_uri"] == "https://www.example.org/post_logout"

    def test_end_session_endpoint_with_cookie_dual_login_wrong_client(self):
        self._code_auth()
        self._code_auth2()
        # The cookie states that a user has a session at a client and this
        # statement is false.
        cookie = self._create_cookie("username", "a1b2c3")

        resp = self.provider.end_session_endpoint(
            urlencode({"state": "abcde"}), cookie=cookie
        )

        assert isinstance(resp, Response)
        _err = ErrorResponse().from_json(resp.message)
        assert _err["error"] == "invalid_request"

    def test_end_session_endpoint_with_id_token_hint_only(self):
        id_token = self._auth_with_id_token()
        assert session_get(self.provider.sdb, "sub", id_token["sub"])

        id_token_hint = id_token.to_jwt(algorithm="none")

        resp = self.provider.end_session_endpoint(
            urlencode({"id_token_hint": id_token_hint})
        )

        # returns a SeeOther instance
        p = urlparse(resp.message)
        qs = parse_qs(p.query)

        jwt_info = self.provider.unpack_signed_jwt(qs["sjwt"][0])

        assert jwt_info["uid"] == "username"
        assert jwt_info["client_id"] == "number5"
        assert jwt_info["redirect_uri"] == "https://example.com/post_logout"

    def test_end_session_endpoint_with_id_token_hint_and_cookie(self):
        id_token = self._auth_with_id_token()
        assert session_get(self.provider.sdb, "sub", id_token["sub"])

        id_token_hint = id_token.to_jwt(algorithm="none")
        cookie = self._create_cookie("username", "number5")

        resp = self.provider.end_session_endpoint(
            urlencode({"id_token_hint": id_token_hint}), cookie=cookie
        )

        # returns a SeeOther instance
        p = urlparse(resp.message)
        qs = parse_qs(p.query)

        jwt_info = self.provider.unpack_signed_jwt(qs["sjwt"][0])

        assert jwt_info["uid"] == "username"
        assert jwt_info["client_id"] == "number5"
        assert jwt_info["redirect_uri"] == "https://example.com/post_logout"

    def test_end_session_endpoint_with_post_logout_redirect_uri(self):
        self._code_auth()
        cookie = self._create_cookie("username", "number5")

        post_logout_redirect_uri = self.CDB[str(CLIENT_CONFIG["client_id"])][
            "post_logout_redirect_uris"
        ][0][0]
        resp = self.provider.end_session_endpoint(
            urlencode(
                {"post_logout_redirect_uri": post_logout_redirect_uri, "state": "abcde"}
            ),
            cookie=cookie,
        )

        # returns a SeeOther instance
        p = urlparse(resp.message)
        qs = parse_qs(p.query)

        jwt_info = self.provider.unpack_signed_jwt(qs["sjwt"][0])

        assert jwt_info["state"] == "abcde"
        assert jwt_info["uid"] == "username"
        assert jwt_info["client_id"] == "number5"
        assert jwt_info["redirect_uri"] == "https://example.com/post_logout"

    def test_end_session_endpoint_without_post_logout_redirect_uri(self):
        # default post logout page registered
        self.provider.post_logout_page = "https://foo.example.com/def_post"
        # No post_logout_redirect_uris registered
        _plru = self.provider.cdb["number5"]["post_logout_redirect_uris"]
        del self.provider.cdb["number5"]["post_logout_redirect_uris"]
        self._code_auth()
        cookie = self._create_cookie("username", "number5")

        resp = self.provider.end_session_endpoint(
            urlencode({"state": "abcde"}), cookie=cookie
        )

        # returns a SeeOther instance
        p = urlparse(resp.message)
        qs = parse_qs(p.query)

        jwt_info = self.provider.unpack_signed_jwt(qs["sjwt"][0])
        assert jwt_info["state"] == "abcde"
        assert jwt_info["uid"] == "username"
        assert jwt_info["client_id"] == "number5"
        assert jwt_info["redirect_uri"] == "https://foo.example.com/def_post"

        # restore
        self.provider.cdb["number5"]["post_logout_redirect_uris"] = _plru

    def test_end_session_endpoint_without_post_logout_redirect_uri_no_default(self):
        # No post_logout_redirect_uris registered
        _plru = self.provider.cdb["number5"]["post_logout_redirect_uris"]
        del self.provider.cdb["number5"]["post_logout_redirect_uris"]
        self._code_auth()
        cookie = self._create_cookie("username", "number5")

        resp = self.provider.end_session_endpoint(
            urlencode({"state": "abcde"}), cookie=cookie
        )

        assert isinstance(resp, Response)
        _err = ErrorResponse().from_json(resp.message)
        assert _err["error"] == "server_error"
        # restore
        self.provider.cdb["number5"]["post_logout_redirect_uris"] = _plru

    def test_end_session_endpoint_bogus_sjwt(self):
        self._code_auth()
        cookie = self._create_cookie("username", "number5")

        post_logout_redirect_uri = self.CDB[str(CLIENT_CONFIG["client_id"])][
            "post_logout_redirect_uris"
        ][0][0]
        resp = self.provider.end_session_endpoint(
            urlencode(
                {"post_logout_redirect_uri": post_logout_redirect_uri, "state": "abcde"}
            ),
            cookie=cookie,
        )

        # returns a SeeOther instance
        p = urlparse(resp.message)
        qs = parse_qs(p.query)

        _sjwt = qs["sjwt"][0]
        _sjwt = ".".join(_sjwt.split(".")[:2]) + "."  # Not signed
        with pytest.raises(ValueError):
            self.provider.unpack_signed_jwt(_sjwt)

    def test_end_session_endpoint_with_wrong_post_logout_redirect_uri(self):
        self._code_auth()
        cookie = self._create_cookie("username", "number5")

        post_logout_redirect_uri = "https://www.example.com/logout"
        resp = self.provider.end_session_endpoint(
            urlencode(
                {"post_logout_redirect_uri": post_logout_redirect_uri, "state": "abcde"}
            ),
            cookie=cookie,
        )

        assert isinstance(resp, Response)
        _err = ErrorResponse().from_json(resp.message)
        assert _err["error"] == "invalid_request"

    def test_end_session_endpoint_with_registered_post_logout_redirect_uri_with_query_part(
        self,
    ):
        self._code_auth()
        cookie = self._create_cookie("username", "number5")

        self.provider.cdb["number5"]["post_logout_redirect_uris"] = [
            ("https://www.example.com/logout", {"foo": ["bar"]})
        ]

        # No post_logout_redirect_uri in request
        resp = self.provider.end_session_endpoint(
            urlencode({"state": "abcde"}), cookie=cookie
        )

        assert isinstance(resp, Response)
        _qp = parse_qs(resp.message.split("?")[1])
        _jwt = self.provider.unpack_signed_jwt(_qp["sjwt"][0])
        assert _jwt["redirect_uri"] == "https://www.example.com/logout?foo=bar"

    def test_back_channel_logout_no_uri(self):
        self._code_auth()

        res = self.provider.do_back_channel_logout(
            self.provider.cdb[CLIENT_ID], "username", "sid"
        )
        assert res is None

    def test_back_channel_logout(self):
        self._code_auth()

        _cdb = copy.copy(self.provider.cdb[CLIENT_ID])
        _cdb["backchannel_logout_uri"] = "https://example.com/bc_logout"
        _cdb["client_id"] = CLIENT_ID
        res = self.provider.do_back_channel_logout(_cdb, "username", "_sid_")
        assert isinstance(res, tuple)
        assert res[0] == "https://example.com/bc_logout"
        _jwt = self.provider.unpack_signed_jwt(res[1])
        assert _jwt
        assert _jwt["iss"] == SERVER_INFO["issuer"]
        assert _jwt["aud"] == [CLIENT_ID]
        assert _jwt["sub"] == "username"
        assert _jwt["sid"] == "_sid_"

    def test_front_channel_logout(self):
        self._code_auth()

        _cdb = copy.copy(self.provider.cdb[CLIENT_ID])
        _cdb["frontchannel_logout_uri"] = "https://example.com/fc_logout"
        _cdb["client_id"] = CLIENT_ID
        res = self.provider.do_front_channel_logout_iframe(
            _cdb, str(SERVER_INFO["issuer"]), "_sid_"
        )
        assert res == '<iframe src="https://example.com/fc_logout">'

    def test_front_channel_logout_session_required(self):
        self._code_auth()

        _cdb = copy.copy(self.provider.cdb[CLIENT_ID])
        _cdb["frontchannel_logout_uri"] = "https://example.com/fc_logout"
        _cdb["frontchannel_logout_session_required"] = True
        _cdb["client_id"] = CLIENT_ID
        res = self.provider.do_front_channel_logout_iframe(
            _cdb, str(SERVER_INFO["issuer"]), "_sid_"
        )
        m = re.match(r'<iframe src="([^"]+)">', str(res))
        assert m
        _q = parse_qs(str(m.group(1)).split("?")[1])
        assert set(_q.keys()) == {"iss", "sid"}

    def test_front_channel_logout_session_required_uri_query(self):
        self._code_auth()

        _cdb = copy.copy(self.provider.cdb[CLIENT_ID])
        _cdb["frontchannel_logout_uri"] = "https://example.com/fc_logout?foo=bar"
        _cdb["frontchannel_logout_session_required"] = True
        _cdb["client_id"] = CLIENT_ID
        res = self.provider.do_front_channel_logout_iframe(
            _cdb, str(SERVER_INFO["issuer"]), "_sid_"
        )
        m = re.match(r'<iframe src="([^"]+)">', str(res))
        assert m
        _q = parse_qs(str(m.group(1)).split("?")[1])
        assert set(_q.keys()) == {"foo", "iss", "sid"}

    def test_front_channel_logout_missing_url(self):
        self._code_auth()

        _cdb = copy.copy(self.provider.cdb[CLIENT_ID])
        _cdb["client_id"] = CLIENT_ID
        res = self.provider.do_front_channel_logout_iframe(
            _cdb, str(SERVER_INFO["issuer"]), "_sid_"
        )
        assert res is None

    def test_logout_from_client_bc(self):
        self._code_auth()
        self.provider.cdb[CLIENT_ID][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb[CLIENT_ID]["client_id"] = CLIENT_ID
        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]
        res = self.provider.logout_info_for_one_client(_sid, CLIENT_ID)
        assert set(res.keys()) == {"back_channel", "front_channel"}
        assert res["back_channel"] != {}
        assert res["front_channel"] == {}
        assert set(res["back_channel"].keys()) == {CLIENT_ID}
        _spec = res["back_channel"][CLIENT_ID]
        assert _spec[0] == "https://example.com/bc_logout"
        _jwt = self.provider.unpack_signed_jwt(_spec[1])
        assert _jwt
        assert _jwt["iss"] == SERVER_INFO["issuer"]
        assert _jwt["aud"] == [CLIENT_ID]
        assert _jwt["sid"] == _sid

    def test_logout_from_client_fc(self):
        self._code_auth()
        del self.provider.cdb[CLIENT_ID]["backchannel_logout_uri"]
        self.provider.cdb[CLIENT_ID][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb[CLIENT_ID]["client_id"] = CLIENT_ID
        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]
        res = self.provider.logout_info_for_one_client(_sid, CLIENT_ID)
        assert set(res.keys()) == {"front_channel", "back_channel"}
        assert res["back_channel"] == {}
        assert set(res["front_channel"].keys()) == {CLIENT_ID}
        _spec = res["front_channel"][CLIENT_ID]
        assert _spec == '<iframe src="https://example.com/fc_logout">'

    def test_logout_from_client(self):
        self._code_auth()
        self._code_auth2()

        # client0
        self.provider.cdb["client0"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb["client0"]["client_id"] = "client0"
        self.provider.cdb["number5"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb["number5"]["client_id"] = CLIENT_ID

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]
        res = self.provider.logout_info_for_all_clients(sid=_sid)
        assert res
        assert set(res.keys()) == {"back_channel", "front_channel"}
        assert set(res["front_channel"].keys()) == {"number5"}
        _spec = res["front_channel"]["number5"]
        assert _spec == '<iframe src="https://example.com/fc_logout">'
        assert set(res["back_channel"].keys()) == {"client0"}
        _spec = res["back_channel"]["client0"]
        assert _spec[0] == "https://example.com/bc_logout"
        _jwt = self.provider.unpack_signed_jwt(_spec[1])
        assert _jwt
        assert _jwt["iss"] == SERVER_INFO["issuer"]
        assert _jwt["aud"] == ["client0"]

    def test_logout_spec_all(self):
        self._code_auth()
        self._code_auth2()

        # client0
        self.provider.cdb["client0"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb["client0"]["client_id"] = "client0"
        self.provider.cdb["number5"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb["number5"]["client_id"] = CLIENT_ID

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]

        logout_spec_all = self.provider.logout_info_for_all_clients(sid=_sid)

        assert set(logout_spec_all.keys()) == {"back_channel", "front_channel"}
        assert set(logout_spec_all["back_channel"].keys()) == {"client0"}
        assert set(logout_spec_all["front_channel"].keys()) == {"number5"}

    def test_do_verified_logout_all(self):
        self._code_auth()
        self._code_auth2()

        # client0
        self.provider.cdb["client0"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb["client0"]["client_id"] = "client0"
        self.provider.cdb["number5"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb["number5"]["client_id"] = CLIENT_ID

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]

        with responses.RequestsMock() as rsps:
            rsps.add(rsps.POST, "https://example.com/bc_logout", status=200)
            res = self.provider.do_verified_logout(_sid, CLIENT_ID, alla=True)

        assert set(res.keys()) == {"iframe", "cookie"}

    def test_do_verified_logout_just_the_one(self):
        self.provider.events = DummyEventStore()  # type: ignore

        self._code_auth()
        self._code_auth2()

        # client0
        self.provider.cdb["client0"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb["client0"]["client_id"] = "client0"
        self.provider.cdb["number5"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb["number5"]["client_id"] = CLIENT_ID

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]

        # There is no back channel logout, hence there should be no HTTP POST
        exception = requests.ConnectionError()
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            rsps.add(responses.POST, "https://example.com/bc_logout", body=exception)
        res = self.provider.do_verified_logout(_sid, CLIENT_ID, alla=False)

        assert set(res.keys()) == {"iframe", "cookie"}

    def test_do_verified_logout_the_other(self):
        self._code_auth()
        self._code_auth2()

        # client0
        self.provider.cdb["client0"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb["client0"]["client_id"] = "client0"
        self.provider.cdb["number5"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb["number5"]["client_id"] = CLIENT_ID

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]

        # This only does back channel logout
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.POST, "https://example.com/bc_logout", status=200)
            res = self.provider.do_verified_logout(_sid, "client0", alla=False)

        assert set(res.keys()) == {"cookie"}

    def test_do_verified_logout_the_other_back_channel_failed(self):
        self._code_auth()
        self._code_auth2()

        # client0
        self.provider.cdb["client0"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb["client0"]["client_id"] = "client0"
        self.provider.cdb["number5"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb["number5"]["client_id"] = CLIENT_ID

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]

        # Does back channel logout and it will fail
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.POST, "https://example.com/bc_logout", status=400)
            res = self.provider.do_verified_logout(_sid, "client0", alla=False)

        assert list(res.keys()) == []

    def test_end_session_endpoint_no_post_logout_redirect_uri(self):
        self._code_auth()
        cookie = self._create_cookie("username", "number5")

        self.provider.cdb["number5"]["post_logout_redirect_uris"] = [
            ("https://example.com/plru", ""),
            ("https://example.com/plru2", ""),
        ]

        res = self.provider.end_session_endpoint(
            urlencode({"state": "abcde"}), cookie=cookie
        )
        assert isinstance(res, Response)
        assert res.status_code == 400

    def test_logout_info_for_all_clients_no_params(self):
        with pytest.raises(ParameterError):
            self.provider.logout_info_for_all_clients()

    def test_do_back_channel_logout_no_backchannel(self):
        self._code_auth()

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]
        _sub = self.provider.sdb[_sid]["sub"]
        #
        if "backchannel_logout_uri" in self.provider.cdb["number5"]:
            del self.provider.cdb["number5"]["backchannel_logout_uri"]

        res = self.provider.do_back_channel_logout(
            self.provider.cdb["number5"], _sub, _sid
        )
        assert res is None

    def test_id_token_hint_multiple_aud(self):
        id_token = self._auth_with_id_token()
        assert session_get(
            self.provider.sdb, "sub", id_token["sub"]
        )  # verify we got valid session

        self.provider.cdb["number5"]["post_logout_redirect_uris"] = [
            ("https://example.com/plru", "")
        ]

        # add another aud and an azp.
        id_token["azp"] = id_token["aud"][0]
        id_token["aud"].append("foobar")
        id_token_hint = id_token.to_jwt(algorithm="none")

        resp = self.provider.end_session_endpoint(
            urlencode({"id_token_hint": id_token_hint})
        )

        assert isinstance(resp, SeeOther)

    def test_id_token_hint_aud_does_not_match_client_id(self):
        id_token = self._auth_with_id_token()
        assert session_get(
            self.provider.sdb, "sub", id_token["sub"]
        )  # verify we got valid session

        # add another aud and an azp.
        id_token_hint = id_token.to_jwt(algorithm="none")

        # Mess with the session DB
        _sid = list(self.provider.sdb._db.storage.keys())[0]
        self.provider.sdb[_sid]["client_id"] = "something else"
        resp = self.provider.end_session_endpoint(
            urlencode({"id_token_hint": id_token_hint})
        )

        assert isinstance(resp, Response)
        assert resp.status_code == 400

    def test_no_back_or_front_channel_logout(self):
        self._code_auth()

        # Mess with client DB
        for c in ["backchannel_logout_uri", "frontchannel_logout_uri"]:
            if c in self.provider.cdb["number5"]:
                del self.provider.cdb["number5"][c]

        resp = self.provider.do_verified_logout(
            sid=list(self.provider.sdb._db.storage.keys())[0], client_id="number5"
        )

        # only cookies
        assert set(resp.keys()) == {"cookie"}

    def test_back_channel_logout_fails(self):
        self._code_auth()

        # client0
        self.provider.cdb["client0"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb["client0"]["client_id"] = "client0"

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]

        # There is no back channel logout, hence there should be no HTTP POST
        with responses.RequestsMock():
            res = self.provider.do_verified_logout(_sid, "client0", alla=False)

        assert res == {}

    def test_logout_info_for_one_client_no_logout_info(self):
        self._code_auth()

        # Mess with client DB
        for c in ["backchannel_logout_uri", "frontchannel_logout_uri"]:
            if c in self.provider.cdb["number5"]:
                del self.provider.cdb["number5"][c]

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]
        resp = self.provider.logout_info_for_one_client(_sid, "number5")

        assert resp == {"back_channel": {}, "front_channel": {}}

    def test_unknown_client(self):
        self._code_auth()
        cookie = self._create_cookie("username", "unknown")

        resp = self.provider.end_session_endpoint(
            urlencode({"state": "abcde"}), cookie=cookie
        )

        assert isinstance(resp, Response)
        assert resp.status_code == 400

    def test_no_cookie_no_id_token_hint(self):
        self._code_auth()

        resp = self.provider.end_session_endpoint(urlencode({"state": "abcde"}))

        assert isinstance(resp, Response)
        assert resp.status_code == 400

    def test_back_channel_logout_failed_front_channel_logout_exists(self):
        self._code_auth()

        # client0
        self.provider.cdb["number5"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.provider.cdb["number5"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb["number5"]["client_id"] = "number5"

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]

        # Does back channel logout and it will fail
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.POST, "https://example.com/bc_logout", status=400)
            res = self.provider.do_verified_logout(_sid, "client0", alla=True)

        assert set(res.keys()) == {"cookie", "iframe"}

    def test_logout_from_clients_one_without_logout_info(self):
        self._code_auth()
        self._code_auth2()

        # Mess with client DB
        # neither back channel nor front channel
        for c in ["backchannel_logout_uri", "frontchannel_logout_uri"]:
            if c in self.provider.cdb["client0"]:
                del self.provider.cdb["client0"][c]

        self.provider.cdb["client0"]["client_id"] = "client0"

        # both back channel and front channel
        self.provider.cdb["number5"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.provider.cdb["number5"]["client_id"] = "number5"

        # Get a session ID, anyone will do.
        # I know the session backend DB is a DictSessionBackend so I can use that
        _sid = list(self.provider.sdb._db.storage.keys())[0]
        res = self.provider.logout_info_for_all_clients(sid=_sid)
        assert set(res.keys()) == {"back_channel", "front_channel"}
        assert set(res["back_channel"].keys()) == {"number5"}
        assert set(res["front_channel"].keys()) == {"number5"}
