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
url = url.replace("#","?")
# implicit flow with multiple return types

def handle_authz_response(environ, start_response):
    _cli = Consumer(SESSION_DB, CLIENT_CONFIG, SERVER_INFO, **CONSUMER_CONFIG)
    aresp = _cli.parse_authz(environ, start_response, DEVNULL())
    print "ARESP: %s" % aresp

    kaka = http_util.cookie(CLIENT_CONFIG["client_id"], _cli.state, _cli.seed,
                            expire=360, path="/")

    resp = http_util.Response("Your will is registered", headers=[kaka])
    return resp(environ, start_response)

capp = TestApp(handle_authz_response)
cres = capp.get(url)
assert cres.status == "200 OK"
print cres.headers
assert "Set-Cookie" in cres.headers.keys()