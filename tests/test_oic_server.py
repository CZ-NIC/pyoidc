__author__ = 'rohe0002'

import sys
import StringIO
import urllib

from oic.oauth2 import rndstr

from oic.utils.sdb import SessionDB
from oic.oic import Client

from oic.oic.consumer import Consumer
from oic.oic.server import Server
from oic.oic.server import get_post
from oic.oic.server import add_token_info
from oic.oauth2.server import AuthnFailure

from oic.oic.message import AuthorizationResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AccessTokenRequest
from oic.oic.message import AccessTokenResponse
from oic.oic.message import TokenErrorResponse
from oic.oic.message import UserInfoRequest
from oic.oic.message import OpenIDSchema
from oic.oic.message import CheckSessionRequest
from oic.oic.message import IdToken
from oic.oic.message import RegistrationRequest
from oic.oic.message import RegistrationResponse

from oic.utils import http_util

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "disable_ssl_certificate_validation":False,
    #"key":None,
    #"algorithm":"HS256",
    "expire_in":600,
    "client_secret":"",
    "client_timeout":0
}

CONSUMER_CONFIG = {
    #"debug": 1,
    "authz_page": "/authz",
    #"password": args.passwd,
    "scope": ["openid"],
    "response_type": ["code"],
    #"expire_in": 600,
    "key": "jwt_key_001"
}

SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://connect-op.heroku.com",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
    #"userinfo_endpoint":"http://localhost:8088/user_info",
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

CDB = {
    "number5": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        "jwk_key": CONSUMER_CONFIG["key"],
    },
}

#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return

def do_authentication(environ, start_response, bsid):
    resp = http_util.Response("<form>%s</form>" % bsid)
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def do_authorization(user, session):
    if user == "user":
        return "ALL"
    else:
        raise Exception("No Authorization defined")

def verify_username_and_password(dic):
    user = dic["login"][0]

    if user == "user":
        return True, user
    elif user == "hannibal":
        raise AuthnFailure("Not allowed to use this service (%s)" % user)
    else:
        if user:
            return False, user
        else:
            raise AuthnFailure("Missing user name")


#noinspection PyUnusedLocal
def verify_client(environ, areq, cdb):
    identity = areq.client_id
    secret = areq.client_secret
    if identity:
        if identity == "client1" and secret == "hemligt":
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

    str = urllib.urlencode(_dict)
    environ["CONTENT_LENGTH"] = len(str)

    fil = StringIO.StringIO(buf=str)
    environ["wsgi.input"] = fil

    return environ

#noinspection PyUnusedLocal
def user_info(userdb, user_id, client_id, user_info):
    identity = userdb[user_id]
    result = {}
    for claim in user_info.claims:
        for key, restr in claim.items():
            try:
                result[key] = identity[key]
            except KeyError:
                if restr == {"optional": True}:
                    pass
                else:
                    raise Exception("Missing property '%s'" % key)

    return OpenIDSchema(**result)

class LOG():
    def info(self, txt):
        print >> sys.stdout, "INFO: %s" % txt

    def error(self, txt):
        print >> sys.stdout, "ERROR: %s" % txt

    def debug(self, txt):
        print >> sys.stdout, "DEBUG: %s" % txt

FUNCTIONS = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify user": verify_username_and_password,
    "verify client": verify_client,
    "user info": user_info,
}

USERDB = {
    "user":{
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
    }
}

URLMAP = {"client1": ["https://example.com/authz"]}

srv_init = Server("pyoicserv", SessionDB(), CDB, FUNCTIONS, "jwt_key",
                  USERDB, URLMAP)

def _eq(l1, l2):
    return set(l1) == set(l2)

def test_get_post():
    environ = BASE_ENVIRON.copy()
    environ["CONTENT_LENGTH"] = 16

    str = rndstr()
    fil = StringIO.StringIO(buf=str)
    environ["wsgi.input"] = fil

    post = get_post(environ)
    assert post == str

    del environ["CONTENT_LENGTH"]
    fil = StringIO.StringIO(buf=str)
    environ["wsgi.input"] = fil

    post = get_post(environ)
    assert post == ""

    environ["CONTENT_LENGTH"] = "A"
    fil = StringIO.StringIO(buf=str)
    environ["wsgi.input"] = fil

    post = get_post(environ)
    assert post == ""

def test_server_init():
    server = srv_init

    assert server
    assert server.function["authenticate"] == do_authentication
    assert server.urlmap["client1"] == ["https://example.com/authz"]

def test_server_authorization_endpoint():
    server = srv_init

    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087authz",
           "response_type": ["code"],
           "client_id": "a1b2c3",
           "nonce": "Nonce"}

    arq = AuthorizationRequest(**bib)

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = arq.get_urlencoded()

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    print resp
    line = resp[0]
    assert line.startswith("<form>")
    assert line.endswith("</form>")

def test_failed_authenticated():
    server = srv_init
    environ0 = create_return_form_env("haden", "secret", "sid1")
    resp1 = server.authenticated(environ0, start_response, LOG(), None)
    print resp1
    assert resp1 == ['<html>Wrong password</html>']

    environ1 = create_return_form_env("", "secret", "sid2")
    resp2 = server.authenticated(environ1, start_response, LOG(), None)
    print resp2
    assert resp2 == ["<html>Authentication failed</html>"]

    environ2 = create_return_form_env("hannibal", "hemligt", "sid3")
    print environ2
    resp = server.authenticated(environ2, start_response, LOG(), None)
    print resp
    assert resp == ['<html>Authentication failure: Not allowed to use this service (hannibal)</html>']

def test_server_authenticated():
    server = srv_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG(), None)

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

    part = cons.parse_authz(environ, start_response, LOG())
    
    aresp = part[0]
    assert part[1] is None
    assert part[2] is None

    #aresp = client.parse_response(AuthorizationResponse, location,
    #                              format="urlencoded",
    #                              state="id-6da9ca0cc23959f5f33e8becd9b08cae")

    print aresp.keys()
    assert isinstance(aresp, AuthorizationResponse)
    assert _eq(aresp.keys(), ['state', 'code', 'nonce'])

    print cons.grant[cons.state].keys()
    assert _eq(cons.grant[cons.state].keys(), ['tokens', 'exp_in', 'seed',
                                               'grant_expiration_time',
                                               'id_token'])

def test_server_authenticated_1():
    server = srv_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    _ = server.authorization_endpoint(environ, start_response, LOG(), None)

    #sid = resp[0][len("FORM with "):]
    environ2 = create_return_form_env("user", "password", "abcd")

    resp2 = server.authenticated(environ2, start_response, LOG(), None)
    print resp2
    assert resp2 == ['<html>Unknown session identifier</html>']

def test_server_authenticated_token():
    server = srv_init

    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.config["response_type"] = ["token"]
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG(), None)

    assert len(resp2) == 1
    txt = resp2[0]
    assert "access_token=" in txt
    assert "token_type=bearer" in txt

def test_server_authenticated_none():
    server = srv_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.response_type = "none"
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG(), None)

    assert len(resp2) == 1
    txt = resp2[0]
    pos0 = txt.index("<title>") + len("<title>Redirecting to ")
    pos1 = txt.index("</title>")
    location = txt[pos0:pos1]
    print location

    assert location.startswith("http://localhost:8087/authz")
    query = location.split("?")[1]
    print query
    assert "token_type=bearer" in query
    
def test_token_endpoint():
    server = srv_init

    authreq = AuthorizationRequest(state="state",
                                   redirect_uri="http://example.com/authz",
                                   client_id="client1")

    _sdb = server.sdb
    sid, access_grant = _sdb.session(user="user_id", areq=authreq)
    _sdb[sid] = {
        "oauth_state": "authz",
        "user_id": "user_id",
        "authzreq": "",
        "client_id": "client1",
        "code": access_grant,
        "redirect_uri":"http://example.com/authz"
    }

    # Construct Access token request
    areq = AccessTokenRequest(code=access_grant, client_id="client1",
                              redirect_uri="http://example.com/authz",
                              client_secret="hemligt")


    str = areq.get_urlencoded()
    fil = StringIO.StringIO(buf=str)
    environ = BASE_ENVIRON.copy()
    environ["CONTENT_LENGTH"] = len(str)
    environ["wsgi.input"] = fil
    environ["REMOTE_USER"] = "client1"

    resp = server.token_endpoint(environ, start_response, LOG(), None)
    print resp
    atr = AccessTokenResponse.set_json(resp[0])
    print atr.keys()
    assert _eq(atr.keys(), ['access_token', 'expires_in', 'token_type',
                            'refresh_token'])

def test_token_endpoint_unauth():
    server = srv_init

    authreq = AuthorizationRequest(state="state",
                                   redirect_uri="http://example.com/authz",
                                   client_id="client1")

    _sdb = server.sdb
    sid, access_grant = _sdb.session(user="user_id", areq=authreq)
    _sdb[sid] = {
        "oauth_state": "authz",
        "user_id": "user_id",
        "authzreq": "",
        "client_id": "client1",
        "code": access_grant,
        "redirect_uri":"http://example.com/authz"
    }

    # Construct Access token request
    areq = AccessTokenRequest(code=access_grant,
                              redirect_uri="http://example.com/authz",
                              client_id="client1", client_secret="secret",)


    str = areq.get_urlencoded()
    fil = StringIO.StringIO(buf=str)
    environ = BASE_ENVIRON.copy()
    environ["CONTENT_LENGTH"] = len(str)
    environ["wsgi.input"] = fil
    environ["REMOTE_USER"] = "client2"

    resp = server.token_endpoint(environ, start_response, LOG(), None)
    print resp
    atr = TokenErrorResponse.set_json(resp[0])
    print atr.keys()
    assert _eq(atr.keys(), ['error'])


def test_authz_endpoint():
    server = srv_init

    cli = Client()
    cli.redirect_uri = "http://www.example.org/authz"
    cli.client_id = "client0"
    cli.state = "_state_"
    args = {"response_type": ["code", "token"]}
    req = cli.construct_AuthorizationRequest(request_args=args)

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = req.get_urlencoded()

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)
    print resp
    assert resp[0].startswith('<form>')
    assert resp[0].endswith('</form>')

def test_idtoken():
    server = srv_init
    AREQ = AuthorizationRequest(response_type="code", client_id="client1",
                                redirect_uri="http://example.com/authz",
                                scope=["openid"], state="state000")

    sid = server.sdb.create_authz_session("user_id", AREQ)
    session = server.sdb[sid]

    id_token = server._id_token(session)
    print id_token
    assert len(id_token.split(".")) == 3

def test_add_token_info():
    server = srv_init
    AREQ = AuthorizationRequest(response_type="code", client_id="client1",
                                redirect_uri="http://example.com/authz",
                                scope=["openid"], state="state000")

    sid = server.sdb.create_authz_session("user_id", AREQ)
    session = server.sdb[sid]
    scode = session["code"]

    aresp = AuthorizationResponse()
    if AREQ.state:
        aresp.state = AREQ.state
    if AREQ.scope:
        aresp.scope = AREQ.scope
    if AREQ.nonce:
        AREQ.nonce = AREQ.nonce

    _dic = server.sdb.update_to_token(scode, issue_refresh=False)
    add_token_info(aresp, _dic)

    print aresp.keys()
    assert _eq(aresp.keys(), ['access_token', 'expires_in', 'token_type',
                              'state', 'scope'])

def test_userinfo_endpoint():
    server = srv_init

    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.config["response_type"] = ["token"]
    cons.config["request_method"] = "parameter"
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG(), None)
    line = resp2[0]
    start = line.index("<title>")
    start += len("<title>Redirecting to ")
    stop = line.index("</title>")
    path, query = line[start:stop].split("?")

    # redirect
    atr = AuthorizationResponse.from_urlencoded(query)

    uir = UserInfoRequest(access_token=atr.access_token, schema="openid")

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = uir.get_urlencoded()

    resp3 = server.userinfo_endpoint(environ, start_response, LOG())
    ident = OpenIDSchema.set_json(resp3[0])
    print ident.keys()
    assert _eq(ident.keys(), ['name', 'email', 'nickname'])
    assert ident.name == USERDB["user"]["name"]

def test_check_session_endpoint():
    server = srv_init
    print server.name
    server.srvmethod.jwt_keys = {server.name: server.jwt_key}

    session = {"user_id": "UserID", "client_id": "number5"}
    idtoken = server._id_token(session)
    csr = CheckSessionRequest(id_token=idtoken)
    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = csr.get_urlencoded()

    info = server.check_session_endpoint(environ, start_response, LOG())
    print info
    idt = IdToken.set_json(info[0])
    print idt.keys()
    assert _eq(idt.keys(), ['user_id', 'aud', 'iss', 'exp'])
    assert idt.iss == server.name

def test_registration_endpoint():
    server = srv_init

    req = RegistrationRequest(type="client_associate")

    req.application_type = "web"
    req.application_name = "My super service"
    req.redirect_uri = "http://example.com/authz"
    req.contact = ["foo@example.com"]

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = req.get_urlencoded()

    resp = server.registration_endpoint(environ, start_response, LOG())

    print resp
    regresp = RegistrationResponse.from_json(resp[0])
    print regresp.keys()
    assert _eq(regresp.keys(), ['client_secret', 'expires_in', 'client_id'])

    # --- UPDATE ----

    req = RegistrationRequest(type="client_update")
    req.client_id = regresp.client_id
    req.client_secret = regresp.client_secret

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = req.get_urlencoded()

    resp = server.registration_endpoint(environ, start_response, LOG())

    print resp
    update = RegistrationResponse.from_json(resp[0])
    print update.keys()
    assert _eq(update.keys(), ['client_secret', 'expires_in', 'client_id'])
    assert update.client_secret != regresp.client_secret