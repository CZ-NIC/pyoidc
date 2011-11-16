#!/usr/bin/env python

__author__ = 'rohe0002'

from mako.lookup import TemplateLookup

from webtest import TestApp
from oic_server import application
from oic_server import do_authentication
from oic_server import do_authorization
from oic_server import verify_username_and_password
from oic_server import verify_client
from oic_server import userinfo

from oic.utils import sdb
from oic.oic.server import Server
from oic.oic.server import UserInfo

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
    "user info": userinfo,
}

import claim_rules as rules
import userinfo as uinfo

SERVER = Server("http://localhost:8088/",
                sdb.SessionDB(),
                CDB,
                FUNCTION,
                "1234567890",
                UserInfo(rules.RULES, uinfo.DB),
                debug=1)


# -----------------------------------------------------------------------------

from oic.oic.consumer import Consumer
from oic.utils import http_util

SESSION_DB = {}

CLIENT_CONFIG = {
    "client_id": "a1b2c3",
}

SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://localhost:8088",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
    "user_info_endpoint":"http://localhost:8088/user_info",
    #"check_id_endpoint":"http://localhost:8088/id_token",
    #"registration_endpoint":"https://connect-op.heroku.com/connect/client",
    #"scopes_supported":["openid","profile","email","address","PPID"],
    "flows_supported":["code","token","code token"],
    #"identifiers_supported":["public","ppid"],
    #"x509_url":"https://connect-op.heroku.com/cert.pem"
}

from oic_consumer import construct_openid_request

CLIENT_FUNCTION = {
    "openid_request": construct_openid_request,
}

CONSUMER_CONFIG = {
    "debug": 0,
    "server_info": SERVER_INFO,
    "authz_page": "/jqauthz",
    "name": "pyoic",
    "password": "hemligt",
    "scope": ["openid"],
    "expire_in": 600,
    "client_secret": None,
    "function": CLIENT_FUNCTION,
    "response_type": ["code", "token"],
    "request_method": "parameter",
    "temp_dir": "/tmp",
    "key": "args.jwt_key",
}

#noinspection PyUnusedLocal
class DEVNULL():
    def info(self, txt):
        return

def register(environ, start_response):
    _oac = Consumer(SESSION_DB, CONSUMER_CONFIG, CLIENT_CONFIG, SERVER_INFO)
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
    _cli = Consumer(SESSION_DB, CONSUMER_CONFIG, CLIENT_CONFIG, SERVER_INFO)
    aresp, atr, idt = _cli.parse_authz(environ, start_response, DEVNULL())
    print "ARESP: %s" % aresp
    print "ATR: %s" % atr
    print "IDT: %s" % idt
    kaka = http_util.cookie(CONSUMER_CONFIG["name"], _cli.state, _cli.seed,
                            expire=360, path="/")

    resp = http_util.Response("Your will is registered", headers=[kaka])
    return resp(environ, start_response)

capp = TestApp(handle_authz_response)
cres = capp.get(url)
assert cres.status == "200 OK"
print cres.headers
assert "Set-Cookie" in cres.headers.keys()