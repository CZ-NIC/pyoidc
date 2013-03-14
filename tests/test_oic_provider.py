__author__ = 'rohe0002'

import StringIO
import urllib

from oic.oauth2.exception import FailedAuthentication

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

from oic.utils import http_util
from oic.utils.time_util import epoch_in_a_while

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "client_timeout": 0
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    #"password": args.passwd,
    "scope": ["openid"],
    "response_type": ["code"],
    #"expire_in": 600,
    "user_info": {
        "claims": {
            "name": None,
            "email": None,
            "nickname": None
        }
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

BASE_ENVIRON = {'SERVER_PROTOCOL': 'HTTP/1.1',
                'REQUEST_METHOD': 'GET',
                'QUERY_STRING': '',
                'HTTP_CONNECTION': 'keep-alive',
                'REMOTE_ADDR': '127.0.0.1',
                'wsgi.url_scheme': 'http',
                'SERVER_PORT': '8087',
                'PATH_INFO': '/register',
                'HTTP_HOST': 'localhost:8087',
                'HTTP_ACCEPT':
                    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'HTTP_ACCEPT_LANGUAGE': 'sv-se',
                'CONTENT_TYPE': 'text/plain',
                'REMOTE_HOST': '1.0.0.127.in-addr.arpa',
                'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
                'COMMAND_MODE': 'unix2003'}

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_HMAC = KeyBundle([{"kty": "hmac", "key": CLIENT_SECRET, "use": "ver"},
                     {"kty": "hmac", "key": CLIENT_SECRET, "use": "sig"}])
KC_HMAC2 = KeyBundle([{"kty": "hmac", "key": "drickyoughurt", "use": "sig"},
                      {"kty": "hmac", "key": "drickyoughurt", "use": "ver"}])

KC_RSA = keybundle_from_local_file("../oc3/certs/mycert.key", "rsa",
                                   ["ver", "sig"])

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_HMAC, KC_RSA]
KEYJAR["number5"] = [KC_HMAC2, KC_RSA]
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


#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return


#noinspection PyUnusedLocal
def do_authentication(environ, start_response, bsid, cookie):
    resp = http_util.Response("<form>%s</form>" % bsid)
    return resp(environ, start_response)


#noinspection PyUnusedLocal
def do_authorization(user, session=None):
    if user == "user":
        return "ALL"
    else:
        raise Exception("No Authorization defined")


def verify_username_and_password(dic):
    try:
        user = dic["login"][0]
    except KeyError:
        raise FailedAuthentication("Authentication failed")

    if user == "user":
        return True, user
    elif user == "hannibal":
        raise FailedAuthentication(
            "Not allowed to use this service (%s)" % user)
    else:
        if user:
            return False, user
        else:
            raise FailedAuthentication("Missing user name")


#noinspection PyUnusedLocal
def verify_client(environ, client, cdb):
    if client:
        if client == CLIENT_ID:
            return True
        else:
            return False

    return False


def create_return_form_env(user, password, sid):
    _dict = {
        "login": user,
        "password": password,
        "sid": sid
    }

    environ = BASE_ENVIRON.copy()
    environ["REQUEST_METHOD"] = "POST"

    text = urllib.urlencode(_dict)
    environ["CONTENT_LENGTH"] = len(text)

    fil = StringIO.StringIO(buf=text)
    environ["wsgi.input"] = fil

    return environ


#noinspection PyUnusedLocal
def user_info(oicsrv, userdb, user_id, client_id, user_info):
    identity = userdb[user_id]
    result = {}
    for key, restr in user_info["claims"].items():
        try:
            result[key] = identity[key]
        except KeyError:
            if restr == {"essential": True}:
                raise Exception("Missing property '%s'" % key)

    return OpenIDSchema(**result)

FUNCTIONS = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify_user": verify_username_and_password,
    "verify_client": verify_client,
    "userinfo": user_info,
}

USERDB = {
    "user": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "user"
    }
}

URLMAP = {"client_1": ["https://example.com/authz"]}

provider_init = Provider("pyoicserv", SessionDB(), CDB, FUNCTIONS,
                         userdb=USERDB, urlmap=URLMAP, keyjar=KEYJAR)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_server_init():
    server = provider_init

    assert server
    assert server.function["authenticate"] == do_authentication
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

    resp = server.authorization_endpoint(query=arq.to_urlencoded())

    print resp
    line = resp[0]
    assert line.startswith("<form>")
    assert line.endswith("</form>")


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
    ic = {"claims": {"sub": {"value": "username"}}}
    _keys = server.keyjar.get_signing_key(key_type="rsa")
    req["request"] = make_openid_request(req, _keys, idtoken_claims=ic,
                                         algorithm="RS256")

    resp = server.authorization_endpoint(query=req.to_urlencoded())

    print resp
    line = resp[0]
    assert "error=login_required" in line


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
    sid = sdb.create_authz_session("username", AREQ)

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

    resp = provider.authorization_endpoint(query=QUERY_STRING)

    print resp
    line = resp[0]
    assert "error=login_required" in line


def test_failed_authenticated():
    server = provider_init
    post = create_return_form_env("haden", "secret", "sid1")
    resp1 = server.authenticated(post)
    assert resp1.message == "Wrong password"

    post = create_return_form_env("", "secret", "sid2")
    resp2 = server.authenticated(post)
    assert resp2.message == "Authentication failed"

    form = create_return_form_env("hannibal", "hemligt", "sid3")
    resp = server.authenticated(form)
    assert resp.message == "Authentication failed"


def test_server_authenticated():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization")

    QUERY_STRING = location.split("?")[1]

    resp = server.authorization_endpoint(query=QUERY_STRING)

    print resp.message
    sid = resp[0][len("<form>"):-len("</form>")]
    form = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(form)

    print resp2[0]
    assert len(resp2) == 1
    txt = resp2[0]
    pos0 = txt.index("<title>") + len("<title>Redirecting to ")
    pos1 = txt.index("</title>")
    location = txt[pos0:pos1]
    print location

    assert location.startswith("http://localhost:8087/authz")

    part = cons.parse_authz(query=location)
    
    aresp = part[0]
    assert part[1] is None
    assert part[2] is None

    #aresp = client.parse_response(AuthorizationResponse, location,
    #                              format="urlencoded",
    #                              state="id-6da9ca0cc23959f5f33e8becd9b08cae")

    print aresp.keys()
    assert aresp.type() == "AuthorizationResponse"
    assert _eq(aresp.keys(), ['code', 'state', 'scope'])

    print cons.grant[cons.state].keys()
    assert _eq(cons.grant[cons.state].keys(), ['code', 'id_token', 'tokens',
                                               'exp_in',
                                               'grant_expiration_time', 'seed'])


def test_server_authenticated_1():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization")

    _ = server.authorization_endpoint(query=location.split("?")[1])

    #sid = resp[0][len("FORM with "):]
    environ2 = create_return_form_env("user", "password", "abcd")

    resp2 = server.authenticated(environ2, start_response)
    print resp2
    assert resp2 == ['<html>Could not find session</html>']


def test_server_authenticated_2():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    location = cons.begin(scope="openid email claims_in_id_token",
                          response_type="code id_token")

    resp = server.authorization_endpoint(query=location.split("?")[1])

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    print server.keyjar.issuer_keys

    resp2 = server.authenticated(environ2, start_response)

    print resp2[0]
    assert len(resp2) == 1
    txt = resp2[0]
    pos0 = txt.index("<title>") + len("<title>Redirecting to ")
    pos1 = txt.index("</title>")
    location = txt[pos0:pos1]
    print location

    assert location.startswith("http://localhost:8087/authz")

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location

    part = cons.parse_authz(environ, start_response)

    aresp = part[0]
    assert part[1] is None
    assert part[2] is not None

    #aresp = client.parse_response(AuthorizationResponse, location,
    #                              format="urlencoded",
    #                              state="id-6da9ca0cc23959f5f33e8becd9b08cae")

    print aresp.keys()
    assert aresp.type() == "AuthorizationResponse"
    assert _eq(aresp.keys(), ['code', 'state', 'scope', "id_token"])

    print cons.grant[cons.state].keys()
    assert _eq(cons.grant[cons.state].keys(), ['code', 'id_token', 'tokens',
                                               'exp_in',
                                               'grant_expiration_time', 'seed'])

    assert isinstance(part[2], IdToken)
    assert (part[2].keys(), ['acr', 'aud', 'c_hash', 'email', 'exp', 'iss',
                             'name', 'nickname', 'sub'])


def test_server_authenticated_token():
    server = provider_init

    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA

    cons.config["response_type"] = ["token"]
    environ = BASE_ENVIRON

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization")

    resp = server.authorization_endpoint(query=location.split("?")[1])

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response)

    assert len(resp2) == 1
    txt = resp2[0]
    assert "access_token=" in txt
    assert "token_type=Bearer" in txt


def test_server_authenticated_none():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.keyjar[""] = KC_RSA
    cons.response_type = "none"

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization")

    resp = server.authorization_endpoint(query=location.split("?")[1])

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response)

    assert len(resp2) == 1
    txt = resp2[0]
    pos0 = txt.index("<title>") + len("<title>Redirecting to ")
    pos1 = txt.index("</title>")
    location = txt[pos0:pos1]
    print location

    assert location.startswith("http://localhost:8087/authz")
    query = location.split("?")[1]
    print query
    assert "token_type=Bearer" in query
    

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

    resp = server.token_endpoint(post=txt, remote_user=CLIENT_ID)
    print resp
    atr = AccessTokenResponse().deserialize(resp[0], "json")
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

    resp = server.token_endpoint(post=txt, remote_user="client2",
                                 request_method="POST")
    print resp
    atr = TokenErrorResponse().deserialize(resp[0], "json")
    print atr.keys()
    assert _eq(atr.keys(), ['error'])


def test_authz_endpoint():
    server = provider_init

    cli = Client()
    cli.redirect_uri = "http://www.example.org/authz"
    cli.client_id = "client0"
    cli.state = "_state_"
    args = {"response_type": ["code", "token"], "scope": ["openid"]}
    req = cli.construct_AuthorizationRequest(request_args=args)

    resp = server.authorization_endpoint(query=req.to_urlencoded())
    print resp
    assert resp[0].startswith('<form>')
    assert resp[0].endswith('</form>')


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

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization")

    resp = server.authorization_endpoint(query=location.split("?")[1])

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response)
    line = resp2[0]
    start = line.index("<title>")
    start += len("<title>Redirecting to ")
    stop = line.index("</title>")
    path, query = line[start:stop].split("?")

    # redirect
    atr = AuthorizationResponse().deserialize(query, "urlencoded")

    uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")

    resp3 = server.userinfo_endpoint(query=uir.to_urlencoded())
    ident = OpenIDSchema().deserialize(resp3[0], "json")
    print ident.keys()
    assert _eq(ident.keys(), ['nickname', 'sub', 'name', 'email'])
    assert ident["sub"] == USERDB["user"]["sub"]


def test_check_session_endpoint():
    server = provider_init
    print server.name

    session = {"sub": "UserID", "client_id": "number5"}
    idtoken = server.id_token_as_signed_jwt(session)
    csr = CheckSessionRequest(id_token=idtoken)

    info = server.check_session_endpoint(query=csr.to_urlencoded())
    print info
    idt = IdToken().deserialize(info[0], "json")
    print idt.keys()
    assert _eq(idt.keys(), ['sub', 'aud', 'iss', 'acr', 'exp', 'iat'])
    assert idt["iss"] == server.name


def test_registration_endpoint():
    server = provider_init

    req = RegistrationRequest(operation="register")

    req["application_type"] = "web"
    req["client_name"] = "My super service"
    req["redirect_uris"] = ["http://example.com/authz"]
    req["contacts"] = ["foo@example.com"]

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = req.to_urlencoded()

    resp = server.registration_endpoint(environ, start_response)

    print resp
    regresp = RegistrationResponse().deserialize(resp[0], "json")
    print regresp.keys()
    assert _eq(regresp.keys(), ['redirect_uris', 'application_type',
                                'expires_at', 'registration_access_token',
                                'client_id', 'client_secret', 'client_name',
                                "contacts"])

    # --- UPDATE ----

    req = RegistrationRequest(operation="client_update")
    req["application_type"] = "web"
    req["client_name"] = "My super duper service"
    req["redirect_uris"] = ["http://example.com/authz"]
    req["contacts"] = ["foo@example.com"]

    resp = server.registration_endpoint(query=req.to_urlencoded(),
                                        authn="Bearer %s" % regresp[
                                            "registration_access_token"])

    print resp
    update = RegistrationResponse().deserialize(resp[0], "json")
    print update.keys()
    assert _eq(update.keys(), ['redirect_uris', 'application_type',
                               'expires_at', 'registration_access_token',
                               'client_id', 'client_secret', 'client_name',
                               'contacts'])


def test_provider_key_setup():
    provider = Provider("pyoicserv", SessionDB(), None, None, None)
    provider.baseurl = "http://www.example.com/"
    provider.key_setup("static", sig={"format": "jwk", "alg": "rsa"})

    keys = provider.keyjar.get_signing_key("rsa")
    assert len(keys) == 1
    assert provider.jwks_uri[0] == "http://www.example.com/static/jwk.json"


def test_registered_redirect_uri_without_query_component():
    provider = Provider("FOO", {}, {}, None, None)
    rr = RegistrationRequest(operation="register",
                             redirect_uris=["http://example.org/cb"])

    registration_req = rr.to_urlencoded()

    provider.registration_endpoint({}, start_response,
                                   query=registration_req)

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

    for ruri in faulty:
        areq = AuthorizationRequest(redirect_uri=ruri,
                                    client_id=provider.cdb.keys()[0],
                                    response_type="code",
                                    scope="openid")

        print areq
        assert provider._verify_redirect_uri(areq) is not None

    for ruri in correct:
        areq = AuthorizationRequest(redirect_uri=ruri,
                                    client_id=provider.cdb.keys()[0])

        resp = provider._verify_redirect_uri(areq)
        if resp:
            print resp.message
        assert resp is None


def test_registered_redirect_uri_with_query_component():
    provider2 = Provider("FOOP", {}, {}, None, None)
    environ = {}

    rr = RegistrationRequest(operation="register",
                             redirect_uris=["http://example.org/cb?foo=bar"])

    registration_req = rr.to_urlencoded()
    resp = provider2.registration_endpoint(environ, start_response,
                                           query=registration_req)

    regresp = RegistrationResponse().from_json(resp[0])

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

    for ruri in faulty:
        areq = AuthorizationRequest(redirect_uri=ruri,
                                    client_id=regresp["client_id"],
                                    scope="openid",
                                    response_type="code")

        print areq
        assert provider2._verify_redirect_uri(areq) is not None

    for ruri in correct:
        areq = AuthorizationRequest(redirect_uri=ruri,
                                    client_id=regresp["client_id"])

        resp = provider2._verify_redirect_uri(areq)
        print resp
        assert resp is None
