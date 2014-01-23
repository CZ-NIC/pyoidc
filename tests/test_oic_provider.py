from mako.lookup import TemplateLookup
from oic.oauth2 import rndstr
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.userinfo import UserInfo

from oic.exception import RedirectURIError

from oic.utils.keyio import KeyBundle
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

from oic.utils.sdb import SessionDB
from oic.oic import Client
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
    #"password": args.passwd,
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
    #"userinfo_endpoint":"http://localhost:8088/user_info",
    #"check_id_endpoint":"http://localhost:8088/id_token",
    #"registration_endpoint":"https://connect-op.heroku.com/connect/client",
    #"scopes_supported":["openid","profile","email","address","PPID"],
    "flows_supported": ["code", "token", "code token"],
    #"identifiers_supported":["public","ppid"],
    #"x509_url":"https://connect-op.heroku.com/cert.pem"
}

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_SYM = KeyBundle([{"kty": "oct", "key": CLIENT_SECRET, "use": "ver"},
                     {"kty": "oct", "key": CLIENT_SECRET, "use": "sig"}])
KC_SYM2 = KeyBundle([{"kty": "oct", "key": "drickyoughurt", "use": "sig"},
                      {"kty": "oct", "key": "drickyoughurt", "use": "ver"}])

KC_RSA = keybundle_from_local_file("../oc3/certs/mycert.key", "RSA",
                                   ["ver", "sig"])

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_SYM, KC_RSA]
KEYJAR["number5"] = [KC_SYM2, KC_RSA]
KEYJAR[""] = KC_RSA

CDB = {
    "number5": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        #"jwk_key": CONSUMER_CONFIG["key"],
        "redirect_uris": [("http://localhost:8087/authz", None)],
    },
    "a1b2c3": {
        "redirect_uris": [("http://localhost:8087/authz", None)]
    },
    "client0": {
        "redirect_uris": [("http://www.example.org/authz", None)]
    },
    CLIENT_ID: {
        "client_secret": CLIENT_SECRET,
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

    def authenticated_as(self, cookie=None,  **kwargs):
        return {"uid": self.user}

#AUTHN = UsernamePasswordMako(None, "login.mako", tl, PASSWD, "authenticated")
AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = rndstr(16)  # symmetric key used to encrypt cookie info
USERINFO = UserInfo(USERDB)

provider_init = Provider("pyoicserv", SessionDB(), CDB, AUTHN_BROKER, USERINFO,
                         AUTHZ, verify_client, SYMKEY, urlmap=URLMAP,
                         keyjar=KEYJAR)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_server_init():
    server = provider_init

    assert server
    assert server.authn_broker == AUTHN_BROKER
    print server.urlmap
    assert server.urlmap["client_1"] == ["https://example.com/authz"]


def test_server_authorization_endpoint():
    server = provider_init

    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087/authz",
           "response_type": ["code"],
           "client_id": "a1b2c3",
           "nonce": "Nonce"}

    arq = AuthorizationRequest(**bib)

    resp = server.authorization_endpoint(request=arq.to_urlencoded())

    print resp.message
    assert resp.message


def test_server_authorization_endpoint_request():
    server = provider_init

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
    _keys = server.keyjar.get_signing_key(key_type="RSA")
    req["request"] = make_openid_request(req, _keys, idtoken_claims=ic,
                                         algorithm="RS256")

    resp = server.authorization_endpoint(request=req.to_urlencoded())

    print resp
    assert "error=login_required" in resp.message


def test_server_authorization_endpoint_id_token():
    provider = provider_init

    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087/authz",
           "response_type": ["code", "id_token"],
           "client_id": "a1b2c3",
           "nonce": "Nonce",
           "prompt": ["none"]}

    req = AuthorizationRequest(**bib)
    AREQ = AuthorizationRequest(response_type="code",
                                client_id="client_1",
                                redirect_uri="http://example.com/authz",
                                scope=["openid"], state="state000")

    sdb = SessionDB()
    sid = sdb.create_authz_session("userX", AREQ)

    _info = sdb[sid]
    _user_info = IdToken(iss="https://foo.example.om", sub="foo",
                         aud=bib["client_id"], exp=epoch_in_a_while(minutes=10),
                         acr="2", nonce=bib["nonce"])

    print provider.keyjar.issuer_keys
    print _user_info.to_dict()
    idt = provider.id_token_as_signed_jwt(_info, access_token="access_token",
                                          user_info=_user_info)

    req["id_token"] = idt

    QUERY_STRING = req.to_urlencoded()

    resp = provider.authorization_endpoint(request=QUERY_STRING)

    print resp
    assert "error=login_required" in resp.message


def test_server_authenticated():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    location = cons.begin("openid", "code", path="http://localhost:8087")

    QUERY_STRING = location.split("?")[1]
    print QUERY_STRING
    resp = server.authorization_endpoint(request=QUERY_STRING)

    print resp.message

    assert resp.message.startswith("http://localhost:8087/authz")

    part = cons.parse_authz(query=location)
    
    aresp = part[0]
    assert part[1] is None
    assert part[2] is None

    #aresp = client.parse_response(AuthorizationResponse, location,
    #                              format="urlencoded",
    #                              state="id-6da9ca0cc23959f5f33e8becd9b08cae")

    print aresp.keys()
    assert aresp.type() == "AuthorizationResponse"
    assert _eq(aresp.keys(), ['request', 'state', 'redirect_uri',
                              'response_type', 'client_id', 'claims', 'scope'])

    print cons.grant[cons.state].keys()
    assert _eq(cons.grant[cons.state].keys(), ['tokens', 'id_token', 'exp_in',
                                               'seed', 'grant_expiration_time'])


def test_server_authenticated_1():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    location = cons.begin("openid", "code", path="http://localhost:8087")

    resp = server.authorization_endpoint(request=location.split("?")[1])

    print resp
    aresp = cons.parse_response(AuthorizationResponse, location,
                                sformat="urlencoded")

    print aresp.keys()
    assert aresp.type() == "AuthorizationResponse"
    assert _eq(aresp.keys(), ['request', 'state', 'redirect_uri', 'claims',
                              'response_type', 'client_id', 'scope'])


def test_server_authenticated_2():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    location = cons.begin(scope="openid email claims_in_id_token",
                          response_type="code id_token",
                          path="http://localhost:8087")

    print location
    resp = server.authorization_endpoint(request=location.split("?")[1])

    print resp.message

    part = cons.parse_authz(resp.message)

    print part
    aresp = part[0]
    assert part[1] is None
    assert part[2] is not None

    #aresp = cons.parse_response(AuthorizationResponse, location,
    #                            sformat="urlencoded")

    print aresp.keys()
    assert aresp.type() == "AuthorizationResponse"
    assert _eq(aresp.keys(), ['scope', 'state', 'code', 'id_token'])

    print cons.grant[cons.state].keys()
    assert _eq(cons.grant[cons.state].keys(), ['code', 'id_token', 'tokens',
                                               'exp_in',
                                               'grant_expiration_time', 'seed'])
    id_token = part[2]
    assert isinstance(id_token, IdToken)
    print id_token.keys()
    assert _eq(id_token.keys(), ['c_hash', 'sub', 'iss', 'acr', 'exp', 'iat',
                                 'aud'])


def test_server_authenticated_token():
    server = provider_init

    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    location = cons.begin("openid", response_type="token",
                          path="http://localhost:8087")

    resp = server.authorization_endpoint(request=location.split("?")[1])

    txt = resp.message
    assert "access_token=" in txt
    assert "token_type=Bearer" in txt


def test_server_authenticated_none():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    location = cons.begin("openid", response_type="none",
                          path="http://localhost:8087")

    resp = server.authorization_endpoint(request=location.split("?")[1])

    assert resp.message.startswith("http://localhost:8087/authz")
    query_part = resp.message.split("?")[1]
    print query_part
    assert "state" in query_part
    

def test_token_endpoint():
    server = provider_init

    authreq = AuthorizationRequest(state="state",
                                   redirect_uri="http://example.com/authz",
                                   client_id=CLIENT_ID)

    _sdb = server.sdb
    sid = _sdb.token.key(user="user_id", areq=authreq)
    access_grant = _sdb.token(sid=sid)
    _sdb[sid] = {
        "oauth_state": "authz",
        "sub": "user_id",
        "authzreq": "",
        "client_id": CLIENT_ID,
        "code": access_grant,
        "code_used": False,
        "scope": ["openid"],
        "redirect_uri": "http://example.com/authz"
    }

    # Construct Access token request
    areq = AccessTokenRequest(code=access_grant, client_id=CLIENT_ID,
                              redirect_uri="http://example.com/authz",
                              client_secret=CLIENT_SECRET)

    txt = areq.to_urlencoded()

    resp = server.token_endpoint(request=txt)
    print resp
    atr = AccessTokenResponse().deserialize(resp.message, "json")
    print atr.keys()
    assert _eq(atr.keys(), ['token_type', 'id_token', 'access_token', 'scope',
                            'expires_in', 'refresh_token'])


def test_token_endpoint_unauth():
    server = provider_init

    authreq = AuthorizationRequest(state="state",
                                   redirect_uri="http://example.com/authz",
                                   client_id="client_1")

    _sdb = server.sdb
    sid = _sdb.token.key(user="user_id", areq=authreq)
    access_grant = _sdb.token(sid=sid)
    _sdb[sid] = {
        "oauth_state": "authz",
        "sub": "user_id",
        "authzreq": "",
        "client_id": "client_1",
        "code": access_grant,
        "code_used": False,
        "scope": ["openid"],
        "redirect_uri": "http://example.com/authz"
    }

    # Construct Access token request
    areq = AccessTokenRequest(code=access_grant,
                              redirect_uri="http://example.com/authz",
                              client_id="client_1", client_secret="secret",)

    print areq.to_dict()
    txt = areq.to_urlencoded()

    resp = server.token_endpoint(request=txt, remote_user="client2",
                                 request_method="POST")
    print resp
    atr = TokenErrorResponse().deserialize(resp.message, "json")
    print atr.keys()
    assert _eq(atr.keys(), ['error'])


def test_authz_endpoint():
    server = provider_init

    cli = Client()
    cli.redirect_uris = ["http://www.example.org/authz"]
    cli.client_id = "client0"
    cli.state = "_state_"
    args = {"response_type": ["code", "token"], "scope": ["openid"]}
    req = cli.construct_AuthorizationRequest(request_args=args)

    resp = server.authorization_endpoint(request=req.to_urlencoded())
    print resp.message
    assert "token_type=Bearer" in resp.message
    assert "code=" in resp.message


def test_idtoken():
    server = provider_init
    AREQ = AuthorizationRequest(response_type="code", client_id=CLIENT_ID,
                                redirect_uri="http://example.com/authz",
                                scope=["openid"], state="state000")

    sid = server.sdb.create_authz_session("user_id", AREQ)
    session = server.sdb[sid]

    id_token = server.id_token_as_signed_jwt(session)
    print id_token
    assert len(id_token.split(".")) == 3


def test_userinfo_endpoint():
    server = provider_init

    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO)
    cons.debug = True
    cons.client_secret = "drickyoughurt"
    cons.config["response_type"] = ["token"]
    cons.config["request_method"] = "parameter"
    cons.keyjar[""] = KC_RSA

    location = cons.begin("openid", "token", path="http://localhost:8087")

    resp = server.authorization_endpoint(request=location.split("?")[1])

    line = resp.message
    path, query = line.split("?")

    # redirect
    atr = AuthorizationResponse().deserialize(query, "urlencoded")

    uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")

    resp3 = server.userinfo_endpoint(request=uir.to_urlencoded())
    ident = OpenIDSchema().deserialize(resp3.message, "json")
    print ident.keys()
    assert _eq(ident.keys(), ['nickname', 'sub', 'name', 'email'])
    assert ident["sub"] == USERDB["username"]["sub"]


def test_check_session_endpoint():
    server = provider_init
    print server.name

    session = {"sub": "UserID", "client_id": "number5"}
    idtoken = server.id_token_as_signed_jwt(session)
    csr = CheckSessionRequest(id_token=idtoken)

    info = server.check_session_endpoint(request=csr.to_urlencoded())
    print info
    idt = IdToken().deserialize(info.message, "json")
    print idt.keys()
    assert _eq(idt.keys(), ['sub', 'aud', 'iss', 'acr', 'exp', 'iat'])
    assert idt["iss"] == server.name


def test_registration_endpoint():
    server = provider_init

    req = RegistrationRequest()

    req["application_type"] = "web"
    req["client_name"] = "My super service"
    req["redirect_uris"] = ["http://example.com/authz"]
    req["contacts"] = ["foo@example.com"]

    print req.to_dict()

    resp = server.registration_endpoint(request=req.to_json())

    print resp.message
    regresp = RegistrationResponse().deserialize(resp.message, "json")
    print regresp.keys()
    assert _eq(regresp.keys(), ['redirect_uris', 'contacts', 'application_type',
                                'client_name', 'registration_client_uri',
                                'client_secret_expires_at',
                                'registration_access_token',
                                'client_id', 'client_secret',
                                'client_id_issued_at'])


def test_provider_key_setup():
    provider = Provider("pyoicserv", SessionDB(), None, None, None, None, None,
                        "")
    provider.baseurl = "http://www.example.com/"
    provider.key_setup("static", sig={"format": "jwk", "alg": "RSA"})

    keys = provider.keyjar.get_signing_key("RSA")
    assert len(keys) == 1
    assert provider.jwks_uri == "http://www.example.com/static/jwks"


def _client_id(cdb):
    cid = None
    for k, item in cdb.items():
        if item in cdb.keys():
            cid = item
            break

    return cid


def test_registered_redirect_uri_without_query_component():
    provider = Provider("FOO", {}, {}, None, None, None, None, "")
    rr = RegistrationRequest(operation="register",
                             redirect_uris=["http://example.org/cb"])

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

    cid = _client_id(provider.cdb)

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


def test_registered_redirect_uri_with_query_component():
    provider2 = Provider("FOOP", {}, {}, None, None, None, None, "")

    rr = RegistrationRequest(operation="register",
                             redirect_uris=["http://example.org/cb?foo=bar"])

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

if __name__ == "__main__":
    test_token_endpoint()