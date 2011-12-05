#!/usr/bin/env python

__author__ = 'rohe0002'

from mako.lookup import TemplateLookup

from webtest import TestApp
from web_server import application
from web_server import do_authentication
from web_server import do_authorization
from web_server import verify_username_and_password
from web_server import verify_client

from oic.utils import sdb
from oic.oauth2.server import Server
from oic.oauth2.message import AuthorizationResponse

ROOT = '../'

LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        "jwt_key": "",
    },
}

FUNCTION = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify user": verify_username_and_password,
    "verify client": verify_client,
}


SERVER = Server("http://localhost:8088/",
                sdb.SessionDB(),
                CDB,
                FUNCTION,
                "1234567890",
                debug=1)


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

# -----------------------------------------------------------------------------

from oic.oauth2.consumer import Consumer
from oic.utils import http_util

SESSION_DB = {}

CLIENT_CONFIG = {
    "client_id": "a1b2c3",
    "grant_expire_in": 600,
    "key": "args.jwt_key",
    "client_secret": None,
}

SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://localhost:8088",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
#    "user_info_endpoint":"http://localhost:8088/user_info",
    "flows_supported":["code","token"],
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "password": "hemligt",
    "scope": "",
    "response_type": ["code"],
    "debug": 0,
}

#noinspection PyUnusedLocal
class DEVNULL():
    def info(self, txt):
        return

#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return ""

def register(environ, start_response):
    _oac = Consumer(SESSION_DB, CLIENT_CONFIG, SERVER_INFO, **CONSUMER_CONFIG)
    location = _oac.begin(environ, start_response, DEVNULL())
    resp = http_util.Redirect(location)
    return resp(environ, start_response)


app = TestApp(register)
cres = app.get('/register')
#print cres.headers
#print "====================="

# -----------------------------------------------------------------------------

app = TestApp(application)

res = app.get(cres.headers["location"],
              extra_environ={"oic.server":SERVER, "mako.lookup":LOOKUP})

# Authentication form
assert res.status == "200 OK"
form = res.form
fields = list(form.fields.items())
#print fields
form["login"] = "foo"
form['password'] = 'bar'
#form.set('name', 'Bob', index=0)

res = form.submit(extra_environ={"oic.server":SERVER, "mako.lookup":LOOKUP})
assert res.status == "302 Found"
url = res.headers["location"]

# Parse by the client

environ = BASE_ENVIRON.copy()
environ["QUERY_STRING"] = url
_cli = Consumer(SESSION_DB, CLIENT_CONFIG, SERVER_INFO, **CONSUMER_CONFIG)
aresp = _cli.handle_authorization_response(environ, start_response, DEVNULL())

print "ARESP: %s" % aresp

assert isinstance(aresp, AuthorizationResponse)

# Create the AccessTokenRequest
url, body, http_args = _cli.get_access_token_request(environ, start_response,
                                                     DEVNULL())

assert url == "http://localhost:8088/token"
assert len(body) != 0
assert http_args == {"client_password": "hemligt"}

# complete with access token request


app = TestApp(application)
cres = app.post('/token', body,
                extra_environ={"oic.server":SERVER,
                               "mako.lookup":LOOKUP,
                               "REMOTE_USER":_cli.client_id})

print cres.status
print cres.headers
#def handle_access_token_reponse(environ, start_response):
#
#    resp = http_util.Response()
#    return resp(environ, start_response)