from oic.oic import message

__author__ = 'rohe0002'

import sys
import StringIO
import urllib

from oic.oauth2 import rndstr

from oic.utils.sdb import SessionDB
from oic.oic import Client

from oic.oic.consumer import Consumer
from oic.oic.provider import Provider
from oic.oic.provider import get_post
from oic.oic.message import  msg_deser, SCHEMA

#from oic.oic.provider import update_info
from oic.oauth2.provider import AuthnFailure


from oic.utils import http_util

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "disable_ssl_certificate_validation":False,
    "expire_in":600,
    "client_timeout":0
}

CONSUMER_CONFIG = {
    #"debug": 1,
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
    }
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

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KEYS = [
    [CLIENT_SECRET, "hmac", "verify", CLIENT_ID],
    [CLIENT_SECRET, "hmac", "sign", CLIENT_ID],
    ["drickyoughurt", "hmac", "verify", "number5"],
    ["drickyoughurt", "hmac", "sign", "number5"],
]

#SIGN_KEY = {"hmac": ["abcdefghijklmnop"]}

CDB = {
    "number5": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        #"jwk_key": CONSUMER_CONFIG["key"],
        "redirect_uris": ["http://localhost:8087/authz"]
    },
    "a1b2c3":{
        "redirect_uris": ["http://localhost:8087/authz"]
    },
    "client0":{
        "redirect_uris": ["http://www.example.org/authz"]
    },
    CLIENT_ID: {
        "client_secret": CLIENT_SECRET,
    }

}

#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return

def do_authentication(environ, start_response, bsid):
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
        raise AuthnFailure("Authentication failed")

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
        if identity == CLIENT_ID and secret == CLIENT_SECRET:
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
def user_info(oicsrv, userdb, user_id, client_id, user_info):
    identity = userdb[user_id]
    result = {}
    for key, restr in user_info["claims"].items():
        try:
            result[key] = identity[key]
        except KeyError:
            if restr == {"optional": True}:
                pass
            else:
                raise Exception("Missing property '%s'" % key)

    return message("OpenIDSchema", **result)

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
    "verify_user": verify_username_and_password,
    "verify_client": verify_client,
    "userinfo": user_info,
}

USERDB = {
    "user":{
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "user_id": "user"
    }
}

URLMAP = {"client1": ["https://example.com/authz"]}

provider_init = Provider("pyoicserv", SessionDB(), CDB, FUNCTIONS,
                  userdb=USERDB, urlmap=URLMAP, jwt_keys=KEYS)

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
    server = provider_init

    assert server
    assert server.function["authenticate"] == do_authentication
    assert server.urlmap["client1"] == ["https://example.com/authz"]

def test_server_authorization_endpoint():
    server = provider_init

    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087/authz",
           "response_type": ["code"],
           "client_id": "a1b2c3",
           "nonce": "Nonce"}

    arq = message("AuthorizationRequest", **bib)

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = arq.to_urlencoded()

    resp = server.authorization_endpoint(environ, start_response, LOG())

    print resp
    line = resp[0]
    assert line.startswith("<form>")
    assert line.endswith("</form>")

def test_failed_authenticated():
    server = provider_init
    environ0 = create_return_form_env("haden", "secret", "sid1")
    resp1 = server.authenticated(environ0, start_response, LOG())
    print resp1
    assert resp1 == ['<html>Wrong password</html>']

    environ1 = create_return_form_env("", "secret", "sid2")
    resp2 = server.authenticated(environ1, start_response, LOG())
    print resp2
    assert resp2 == ["<html>Authentication failed</html>"]

    environ2 = create_return_form_env("hannibal", "hemligt", "sid3")
    print environ2
    resp = server.authenticated(environ2, start_response, LOG())
    print resp
    assert resp == ['<html>Not allowed to use this service (hannibal)</html>']

def test_server_authenticated():
    server = provider_init
    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    resp = server.authorization_endpoint(environ, start_response, LOG())

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG())

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
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    _ = server.authorization_endpoint(environ, start_response, LOG())

    #sid = resp[0][len("FORM with "):]
    environ2 = create_return_form_env("user", "password", "abcd")

    resp2 = server.authenticated(environ2, start_response, LOG())
    print resp2
    assert resp2 == ['<html>Could not find session</html>']

def test_server_authenticated_token():
    server = provider_init

    _session_db = {}
    cons = Consumer(_session_db, CONSUMER_CONFIG, CLIENT_CONFIG,
                    server_info=SERVER_INFO, )
    cons.debug = True
    cons.config["response_type"] = ["token"]
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    resp = server.authorization_endpoint(environ, start_response, LOG())

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG())

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
    cons.response_type = "none"
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    resp = server.authorization_endpoint(environ, start_response, LOG())

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG())

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

    authreq = message("AuthorizationRequest", state="state",
                      redirect_uri="http://example.com/authz",
                      client_id=CLIENT_ID)

    _sdb = server.sdb
    sid = _sdb.token.key(user="user_id", areq=authreq)
    access_grant = _sdb.token(sid=sid)
    _sdb[sid] = {
        "oauth_state": "authz",
        "user_id": "user_id",
        "authzreq": "",
        "client_id": CLIENT_ID,
        "code": access_grant,
        "code_used": False,
        "scope": ["openid"],
        "redirect_uri":"http://example.com/authz"
    }

    # Construct Access token request
    areq = message("AccessTokenRequest", code=access_grant,
                   client_id=CLIENT_ID,
                   redirect_uri="http://example.com/authz",
                   client_secret=CLIENT_SECRET)


    str = areq.to_urlencoded()
    fil = StringIO.StringIO(buf=str)
    environ = BASE_ENVIRON.copy()
    environ["CONTENT_LENGTH"] = len(str)
    environ["wsgi.input"] = fil
    environ["REMOTE_USER"] = CLIENT_ID

    resp = server.token_endpoint(environ, start_response, LOG(), None)
    print resp
    atr = msg_deser(resp[0], "json", schema=SCHEMA["AccessTokenResponse"])
    print atr.keys()
    assert _eq(atr.keys(), ['token_type', 'id_token', 'access_token', 'scope',
                            'expires_in', 'refresh_token'])

def test_token_endpoint_unauth():
    server = provider_init

    authreq = message("AuthorizationRequest", state="state",
                      redirect_uri="http://example.com/authz",
                      client_id="client1")

    _sdb = server.sdb
    sid = _sdb.token.key(user="user_id", areq=authreq)
    access_grant = _sdb.token(sid=sid)
    _sdb[sid] = {
        "oauth_state": "authz",
        "user_id": "user_id",
        "authzreq": "",
        "client_id": "client1",
        "code": access_grant,
        "code_used": False,
        "scope": ["openid"],
        "redirect_uri":"http://example.com/authz"
    }

    # Construct Access token request
    areq = message("AccessTokenRequest", code=access_grant,
                   redirect_uri="http://example.com/authz",
                   client_id="client1", client_secret="secret",)


    str = areq.to_urlencoded()
    fil = StringIO.StringIO(buf=str)
    environ = BASE_ENVIRON.copy()
    environ["CONTENT_LENGTH"] = len(str)
    environ["wsgi.input"] = fil
    environ["REMOTE_USER"] = "client2"

    resp = server.token_endpoint(environ, start_response, LOG(), None)
    print resp
    atr = msg_deser(resp[0] ,"json", schema=SCHEMA["TokenErrorResponse"])
    print atr.keys()
    assert _eq(atr.keys(), ['error'])


def test_authz_endpoint():
    server = provider_init

    cli = Client()
    cli.redirect_uri = "http://www.example.org/authz"
    cli.client_id = "client0"
    cli.state = "_state_"
    args = {"response_type": ["code", "token"]}
    req = cli.construct_AuthorizationRequest(request_args=args)

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = req.to_urlencoded()

    resp = server.authorization_endpoint(environ, start_response, LOG())
    print resp
    assert resp[0].startswith('<form>')
    assert resp[0].endswith('</form>')

def test_idtoken():
    server = provider_init
    AREQ = message("AuthorizationRequest", response_type="code",
                   client_id=CLIENT_ID,
                   redirect_uri="http://example.com/authz", scope=["openid"],
                   state="state000")

    sid = server.sdb.create_authz_session("user_id", AREQ)
    session = server.sdb[sid]

    id_token = server._id_token(session)
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
    environ = BASE_ENVIRON

    location = cons.begin(environ, start_response, LOG())

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = location.split("?")[1]

    resp = server.authorization_endpoint(environ, start_response, LOG())

    sid = resp[0][len("<form>"):-len("</form>")]
    environ2 = create_return_form_env("user", "password", sid)

    resp2 = server.authenticated(environ2, start_response, LOG())
    line = resp2[0]
    start = line.index("<title>")
    start += len("<title>Redirecting to ")
    stop = line.index("</title>")
    path, query = line[start:stop].split("?")

    # redirect
    atr = msg_deser(query, "urlencoded",
                    schema=SCHEMA["AuthorizationResponse"])

    uir = message("UserInfoRequest", access_token=atr["access_token"],
                  schema="openid")

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = uir.to_urlencoded()

    resp3 = server.userinfo_endpoint(environ, start_response, LOG())
    ident = msg_deser(resp3[0], "json", schema=SCHEMA["OpenIDSchema"])
    print ident.keys()
    assert _eq(ident.keys(), ['nickname', 'user_id', 'name', 'email'])
    assert ident["user_id"] == USERDB["user"]["user_id"]

def test_check_session_endpoint():
    server = provider_init
    print server.name
    server.keystore.add_key(CDB["number5"]["client_secret"], "hmac", "verify",
                            "number5")

    session = {"user_id": "UserID", "client_id": "number5"}
    idtoken = server._id_token(session)
    csr = message("CheckSessionRequest", id_token=idtoken)
    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = csr.to_urlencoded()

    info = server.check_session_endpoint(environ, start_response, LOG())
    print info
    idt = msg_deser(info[0], "json", schema=SCHEMA["IdToken"])
    print idt.keys()
    assert _eq(idt.keys(), ['user_id', 'aud', 'iss', 'acr', 'exp'])
    assert idt["iss"] == server.name

def test_registration_endpoint():
    server = provider_init

    req = message("RegistrationRequest", type="client_associate")

    req["application_type"] = "web"
    req["application_name"] = "My super service"
    req["redirect_uri"] = "http://example.com/authz"
    req["contact"] = ["foo@example.com"]

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = req.to_urlencoded()

    resp = server.registration_endpoint(environ, start_response, LOG())

    print resp
    regresp = msg_deser(resp[0], "json", schema=SCHEMA["RegistrationResponse"])
    print regresp.keys()
    assert _eq(regresp.keys(), ['client_secret', 'expires_at', 'client_id'])

    # --- UPDATE ----

    req = message("RegistrationRequest", type="client_update")
    req["client_id"] = regresp["client_id"]
    req["client_secret"] = regresp["client_secret"]

    environ = BASE_ENVIRON.copy()
    environ["QUERY_STRING"] = req.to_urlencoded()

    resp = server.registration_endpoint(environ, start_response, LOG())

    print resp
    update = msg_deser(resp[0], "json", schema=SCHEMA["RegistrationResponse"])
    print update.keys()
    assert _eq(update.keys(), ['client_secret', 'expires_at', 'client_id'])
    assert update["client_secret"] != regresp["client_secret"]