__author__ = 'rohe0002'

import sys
import StringIO
import urllib

from oic.utils import sdb
from oic import oauth2
from oic.oauth2 import server
from oic.oauth2.consumer import Consumer
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import TokenErrorResponse

from oic.oauth2.server import Server
from oic.utils import http_util

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "disable_ssl_certificate_validation":False,
#    "key":None,
#    "algorithm":"HS256",
    "grant_expire_in":600,
    "client_secret":"",
    "client_timeout":0
}

CONSUMER_CONFIG = {
    "debug": 1,
    "authz_page": "/authz",
    "flow_type": "code",
    #"password": args.passwd,
    "scope": ["openid"],
    "response_type": "code",
    #"expire_in": 600,
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
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt"
    },
}

#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return

def do_authentication(environ, start_response, bsid):
    resp = http_util.Response("FORM with %s" % bsid)
    return resp(environ, start_response)

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
        raise server.AuthnFailure(
                                "Not allowed to use this service (%s)" % _user)
    else:
        if _user:
            return False, _user
        else:
            raise server.AuthnFailure("Missing user name")


#noinspection PyUnusedLocal
def verify_client(environ, identity, cdb):
    if identity:
        if identity == "client1":
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
}

def _eq(l1, l2):
    return set(l1) == set(l2)

def test_get_post():
    environ = BASE_ENVIRON.copy()
    environ["CONTENT_LENGTH"] = 16

    str = server.rndstr()
    fil = StringIO.StringIO(buf=str)
    environ["wsgi.input"] = fil

    post = server.get_post(environ)
    assert post == str

    del environ["CONTENT_LENGTH"]
    fil = StringIO.StringIO(buf=str)
    environ["wsgi.input"] = fil

    post = server.get_post(environ)
    assert post == ""

    environ["CONTENT_LENGTH"] = "A"
    fil = StringIO.StringIO(buf=str)
    environ["wsgi.input"] = fil

    post = server.get_post(environ)
    assert post == ""
    
def test_server_init():
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)

    assert server
    assert server.function["authenticate"] == do_authentication

    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS,
                    {"client1": ["https://example.com/authz"]})

    assert server.urlmap["client1"] == ["https://example.com/authz"]

def test_server_authorization_endpoint():
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)

    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087authz",
           "response_type": ["code"],
           "client_id": "a1b2c3"}

    arq = oauth2.AuthorizationRequest(**bib)

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = arq.get_urlencoded()

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    print resp
    assert resp[0].startswith("FORM with")

def test_failed_authenticated():
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
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
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    sid = resp[0][len("FORM with "):]
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

    aresp = cons.handle_authorization_response(environ, start_response, LOG())

    #aresp = client.parse_response(AuthorizationResponse, location,
    #                              format="urlencoded",
    #                              state="id-6da9ca0cc23959f5f33e8becd9b08cae")

    print aresp.keys()
    assert isinstance(aresp, AuthorizationResponse)
    assert _eq(aresp.keys(), ['state', 'code'])

    print cons.grant[cons.state].keys()
    assert _eq(cons.grant[cons.state].keys(), ['tokens', 'code', 'exp_in',
                                               'seed', 
                                               'grant_expiration_time'])

def test_server_authenticated_1():
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location

    _ = server.authorization_endpoint(environ, start_response, LOG(), None)

    #sid = resp[0][len("FORM with "):]
    environ2 = create_return_form_env("user", "password", "abcd")

    resp2 = server.authenticated(environ2, start_response, LOG(), None)
    print resp2
    assert resp2 == ['<html>Unknown session identifier</html>']

def test_server_authenticated_token():
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    cons.response_type = "token"
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    sid = resp[0][len("FORM with "):]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG(), None)

    assert len(resp2) == 1
    txt = resp2[0]
    assert "access_token=" in txt
    assert "token_type=bearer" in txt

def test_server_authenticated_none():
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)
    _session_db = {}
    cons = Consumer(_session_db, client_config = CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True
    cons.response_type = "none"
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location

    resp = server.authorization_endpoint(environ, start_response, LOG(), None)

    sid = resp[0][len("FORM with "):]
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
    assert query.startswith("state=")
    assert "&" not in query

def test_token_endpoint():
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)

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
    areq = AccessTokenRequest(grant_type="authorization_code", code=access_grant,
                              redirect_uri="http://example.com/authz")


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
    server = Server("pyoicserv", sdb.SessionDB(), CDB, FUNCTIONS)

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
    areq = AccessTokenRequest(grant_type="authorization_code", code=access_grant,
                              redirect_uri="http://example.com/authz",
                              client_id="client1", client_secret="hemlighet",)


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
