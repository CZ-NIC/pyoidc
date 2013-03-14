from oic.utils.http_util import Response, ServiceError

__author__ = 'rohe0002'

import StringIO
import urllib

from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import TokenErrorResponse
from oic.oauth2.exception import FailedAuthentication

from oic.utils import sdb, http_util
from oic.oauth2 import rndstr
from oic.oauth2.consumer import Consumer
from oic.oauth2.provider import Provider, get_post

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "grant_expire_in": 600,
    "client_timeout": 0
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "flow_type": "code",
    #"password": args.passwd,
    "scope": [],
    "response_type": "code",
    #"expire_in": 600,
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

CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt"
    },
}


#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return


def do_authentication(bsid):
    return http_util.Response("FORM with %s" % bsid)


#noinspection PyUnusedLocal
def do_authorization(user, session):
    if user == "user":
        return "ALL"
    else:
        raise Exception("No Authorization defined")


def verify_username_and_password(dic):
    _user = dic["login"][0]
    if _user == "user":
        return True, _user
    elif _user == "hannibal":
        raise FailedAuthentication(
            "Not allowed to use this service (%s)" % _user)
    else:
        if _user:
            return False, _user
        else:
            raise FailedAuthentication("Missing user name")


#noinspection PyUnusedLocal
def verify_client(identity, cdb):
    if identity:
        if identity == "client1":
            return True
        else:
            raise KeyError


def create_return_form_env(user, password, sid):
    _dict = {
        "login": user,
        "password": password,
        "sid": sid
    }

    return urllib.urlencode(_dict)

FUNCTIONS = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify_user": verify_username_and_password,
    "verify_client": verify_client,
}


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_get_post():
    environ = BASE_ENVIRON.copy()
    environ["CONTENT_LENGTH"] = 16

    txt = rndstr()
    fil = StringIO.StringIO(buf=txt)
    environ["wsgi.input"] = fil

    post = get_post(environ)
    assert post == txt

    del environ["CONTENT_LENGTH"]
    fil = StringIO.StringIO(buf=txt)
    environ["wsgi.input"] = fil

    post = get_post(environ)
    assert post == ""

    environ["CONTENT_LENGTH"] = "A"
    fil = StringIO.StringIO(buf=txt)
    environ["wsgi.input"] = fil

    post = get_post(environ)
    assert post == ""
    

def test_provider_init():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)

    assert provider
    assert provider.function["authenticate"] == do_authentication

    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS,
                        {"client1": ["https://example.com/authz"]})

    assert provider.urlmap["client1"] == ["https://example.com/authz"]


def test_provider_authorization_endpoint():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)

    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087authz",
           "response_type": ["code"],
           "client_id": "a1b2c3"}

    arq = AuthorizationRequest(**bib)

    QUERY_STRING = arq.to_urlencoded()

    resp = provider.authorization_endpoint(query=QUERY_STRING)

    assert isinstance(resp, Response)
    assert resp.message.startswith("FORM with")


def test_failed_authenticated():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    post = create_return_form_env("haden", "secret", "sid1")
    resp1 = provider.authenticated(post)
    print resp1
    assert resp1.message == "Authentication failed"

    post1 = create_return_form_env("", "secret", "sid2")
    resp2 = provider.authenticated(post1)
    print resp2
    assert resp2.message == "Authentication failed"

    post2 = create_return_form_env("hannibal", "hemligt", "sid3")
    print post2
    resp = provider.authenticated(post2)
    print resp
    assert resp.message == 'Authentication failed'


def test_provider_authenticated():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization")

    QUERY_STRING = location.split("?")[1]

    resp = provider.authorization_endpoint(query=QUERY_STRING)

    sid = resp.message[len("FORM with "):]
    post = create_return_form_env("user", "password", sid)

    resp = provider.authenticated(post)

    print resp.message

    assert resp.message.startswith("http://localhost:8087/authz")

    QUERY_STRING = resp.message.split("?")[1]

    aresp = cons.handle_authorization_response(query=QUERY_STRING)

    #aresp = client.parse_response(AuthorizationResponse, location,
    #                              format="urlencoded",
    #                              state="id-6da9ca0cc23959f5f33e8becd9b08cae")

    print aresp.keys()
    assert aresp.type() == "AuthorizationResponse"
    assert _eq(aresp.keys(), ['state', 'code'])

    print cons.grant[cons.state].keys()
    assert _eq(cons.grant[cons.state].keys(), ['tokens', 'code', 'exp_in',
                                               'seed', 'id_token',
                                               'grant_expiration_time'])


def test_provider_authenticated_1():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization")

    QUERY_STRING = location.split("?")[1]

    _ = provider.authorization_endpoint(query=QUERY_STRING)

    #sid = resp[0][len("FORM with "):]
    post = create_return_form_env("user", "password", "abcd")

    resp2 = provider.authenticated(post)
    assert isinstance(resp2, ServiceError)
    assert resp2.message == "Unknown session identifier"


def test_provider_authenticated_token():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization",
                          "token")

    QUERY_STRING = location.split("?")[1]

    resp = provider.authorization_endpoint(query=QUERY_STRING)

    sid = resp.message[len("FORM with "):]
    post = create_return_form_env("user", "password", sid)

    resp2 = provider.authenticated(post)

    txt = resp2.message
    assert "access_token=" in txt
    assert "token_type=Bearer" in txt


def test_provider_authenticated_none():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization",
                          "none")

    QUERY_STRING = location.split("?")[1]

    resp = provider.authorization_endpoint(query=QUERY_STRING)

    sid = resp.message[len("FORM with "):]
    post = create_return_form_env("user", "password", sid)

    resp2 = provider.authenticated(post)

    location = resp2.message
    print location

    assert location.startswith("http://localhost:8087/authz")
    query = location.split("?")[1]
    assert query.startswith("state=")
    assert "&" not in query


def test_token_endpoint():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)

    authreq = AuthorizationRequest(state="state",
                                   redirect_uri="http://example.com/authz",
                                   client_id="client1")

    _sdb = provider.sdb
    sid = _sdb.token.key(user="user_id", areq=authreq)
    access_grant = _sdb.token(sid=sid)
    _sdb[sid] = {
        "oauth_state": "authz",
        "user_id": "user_id",
        "authzreq": "",
        "client_id": "client1",
        "code": access_grant,
        "code_used": False,
        "redirect_uri": "http://example.com/authz"
    }

    # Construct Access token request
    areq = AccessTokenRequest(code=access_grant,
                              redirect_uri="http://example.com/authz",
                              client_id="client1", client_secret="hemlighet",)

    print areq.to_dict()
    resp = provider.token_endpoint(post=areq.to_urlencoded())
    print resp.message
    atr = AccessTokenResponse().deserialize(resp.message, "json")

    print atr.keys()
    assert _eq(atr.keys(), ['access_token', 'expires_in', 'token_type',
                            'refresh_token'])


def test_token_endpoint_unauth():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)

    authreq = AuthorizationRequest(state="state",
                                   redirect_uri="http://example.com/authz",
                                   client_id="client1")

    _sdb = provider.sdb
    sid = _sdb.token.key(user="user_id", areq=authreq)
    access_grant = _sdb.token(sid=sid)
    _sdb[sid] = {
        "oauth_state": "authz",
        "user_id": "user_id",
        "authzreq": "",
        "client_id": "client1",
        "code": access_grant,
        "code_used": False,
        "redirect_uri": "http://example.com/authz"
    }

    # Construct Access token request
    areq = AccessTokenRequest(code=access_grant,
                              redirect_uri="http://example.com/authz",
                              client_id="client2", client_secret="hemlighet",)


    print areq.to_dict()
    resp = provider.token_endpoint(post=areq.to_urlencoded())
    print resp.message
    atr = TokenErrorResponse().deserialize(resp.message, "json")
    print atr.keys()
    assert _eq(atr.keys(), ['error_description', 'error'])
