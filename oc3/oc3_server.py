#!/usr/bin/env python
# -*- coding: utf-8 -*-
#import sys
from oic.utils import http_util

__author__ = 'rohe0002'

import logging
import re

from oic.utils.http_util import *
from oic.oic.message import OpenIDSchema
from oic.oic.server import AuthnFailure
from oic.oic.claims_provider import ClaimsClient

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("oicServer")
hdlr = logging.FileHandler('oc3.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

URLMAP={}

NAME = "pyoic"

OAS = None

PASSWD = [("diana", "krall")]


#noinspection PyUnusedLocal
def devnull(txt):
    pass

def do_authentication(environ, start_response, sid):
    """
    Put up the login form
    """
    resp = Response(mako_template="login.mako",
                    template_lookup=environ["mako.lookup"])

    argv = { "sid": sid,
             "login": "",
             "password": "",
             "action": "authenticated"
    }
    return resp(environ, start_response, **argv)

def verify_username_and_password(dic):
    # verify username and password
    for user, pwd in PASSWD:
        if user == dic["login"][0]:
            if pwd == dic["password"][0]:
                return True, user
            else:
                raise AuthnFailure("Wrong password")

    return False, ""

#noinspection PyUnusedLocal
def do_authorization(user, session=None):
    if user in [u for u,p in PASSWD]:
        return "ALL"
    else:
        raise Exception("No Authorization defined")

#noinspection PyUnusedLocal
def verify_client(environ, areq, cdb):
    identity = areq.client_id
    secret = areq.client_secret
    if identity:
        if identity in cdb:
            if cdb[identity]["client_secret"] == secret:
                return True

    return False

#import sys
def dynamic_init_claims_client(issuer, req_args):
    cc = ClaimsClient()
    # dynamic provider info discovery
    cc.provider_config(issuer)
    resp = cc.do_registration_request(request_args=req_args)
    cc.client_id = resp.client_id
    cc.client_secret = resp.client_secret
    return cc

def init_claims_clients(client_info):
    res = {}
    for cid, specs in client_info.items():
        if "dynamic" in specs:
            cc = dynamic_init_claims_client(cid, args)
        else:
            cc = ClaimsClient(client_id=specs["client_id"])
            cc.client_secret=specs["client_secret"]
            cc.load_x509_cert(specs["x509_url"], "verify", cid)
            cc.userclaims_endpoint = specs["userclaims_endpoint"]
        res[cid] = cc
    return res

def _collect_distributed(srv, cc, user_id, what, alias=""):

    try:
        resp = cc.do_claims_request(request_args={"user_id": user_id,
                                                  "claims_names": what})
    except Exception:
        raise

    result = {"_claims_names":{}, "_claims_sources": {}}

    if not alias:
        alias = srv

    for key in resp.claims_names:
        result["_claims_names"][key] = alias

    if resp.jwt:
        result["_claims_sources"][alias] = {"JWT": resp.jwt}
    else:
        result["_claims_sources"][alias] = {"endpoint": resp.endpoint}
        if "access_token" in resp:
            result["_claims_sources"][alias]["access_token"] = resp.access_token

    return result

#noinspection PyUnusedLocal
def user_info(oicsrv, userdb, user_id, client_id="", user_info_claims=None):
    #print >> sys.stderr, "claims: %s" % user_info_claims

    identity = userdb[user_id]

    if user_info_claims:
        result = {}
        missing = []
        optional = []
        for key, restr in user_info_claims.claims.items():
            try:
                result[key] = identity[key]
            except KeyError:
                if restr == {"optional": True}:
                    optional.append(key)
                else:
                    missing.append(key)

        # Check if anything asked for is somewhere else
        if (missing or optional) and "_external_" in identity:
            cpoints = {}
            remaining = missing[:]
            missing.extend(optional)
            for key in missing:
                for _srv, what in identity["_external_"].items():
                    if key in what:
                        try:
                            cpoints[_srv].append(key)
                        except KeyError:
                            cpoints[_srv] = [key]
                        try:
                            remaining.remove(key)
                        except ValueError:
                            pass

            if remaining:
                raise Exception("Missing properties '%s'" % remaining)

            for srv, what in cpoints.items():
                cc = oicsrv.claims_clients[srv]
                _res = _collect_distributed(srv, cc, user_id, what)
                for key, val in _res.items():
                    if key in result:
                        result[key].update(val)
                    else:
                        result[key] = val

    else:
        # default is what "openid" demands which is user_id
        #result = identity
        result = {"user_id": user_id}

    return OpenIDSchema(**result)

FUNCTIONS = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify_user": verify_username_and_password,
    "verify_client": verify_client,
    "userinfo": user_info,
    }

# ----------------------------------------------------------------------------

def safe(environ, start_response, handle):
    _oas = environ["oic.oas"]
    _srv = _oas.server
    _log_info = _oas.logger.info

    _log_info("- safe -")
    _log_info("env: %s" % environ)
    _log_info("handle: %s" % (handle,))

    try:
        authz = environ["HTTP_AUTHORIZATION"]
        (typ, code) = authz.split(" ")
        assert typ == "Bearer"
    except KeyError:
        resp = BadRequest("Missing authorization information")
        return resp(environ, start_response)

    try:
        _sinfo = _srv.sdb[code]
    except KeyError:
        resp = Unauthorized("Not authorized")
        return resp(environ, start_response)

    info = "'%s' secrets" % _sinfo["user_id"]
    resp = Response(info)
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def css(environ, start_response, handle, logger):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except Exception:
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------

def token(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.token_endpoint(environ, start_response, LOGGER, handle)

#noinspection PyUnusedLocal
def authorization(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.authorization_endpoint(environ, start_response, LOGGER,
                                       handle=handle)

#noinspection PyUnusedLocal
def authenticated(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.authenticated(environ, start_response, LOGGER)

#noinspection PyUnusedLocal
def userinfo(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.userinfo_endpoint(environ, start_response, LOGGER)

#noinspection PyUnusedLocal
def op_info(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.providerinfo_endpoint(environ, start_response, LOGGER)

#noinspection PyUnusedLocal
def registration(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.registration_endpoint(environ, start_response, LOGGER)

#noinspection PyUnusedLocal
def check_id(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.check_id_endpoint(environ, start_response, LOGGER)

# ----------------------------------------------------------------------------
from oic.oic.server import AuthorizationEndpoint
from oic.oic.server import TokenEndpoint
from oic.oic.server import UserinfoEndpoint
from oic.oic.server import CheckIDEndpoint
from oic.oic.server import RegistrationEndpoint


ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
    UserinfoEndpoint(userinfo),
    CheckIDEndpoint(check_id),
    RegistrationEndpoint(registration)
    ]

URLS = [
    (r'^authenticated', authenticated),
    (r'^.well-known/openid-configuration', op_info),
    (r'.+\.css$', css),
    (r'safe', safe)
]

for endp in ENDPOINTS:
    URLS.append(("^%s" % endp.type, endp))

# ----------------------------------------------------------------------------

ROOT = '../'

LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

# ----------------------------------------------------------------------------

def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above and store the regular expression
    captures in the WSGI environment as  `oic.url_args` so that
    the functions from above can access the url placeholders.

    If nothing matches call the `not_found` function.

    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the
        request is done
    :return: The response as a list of lines
    """
    global LOOKUP
    global OAS

    #user = environ.get("REMOTE_USER", "")
    path = environ.get('PATH_INFO', '').lstrip('/')
    kaka = environ.get("HTTP_COOKIE", '')


    if kaka:
        if OAS.debug:
            OAS.logger.debug("Cookie: %s" % (kaka,))
        try:
            handle = parse_cookie(OAS.cookie_name, OAS.seed, kaka)
        except ValueError:
            handle = ""
    else:
        handle = ""

    environ["oic.oas"] = OAS
    environ["mako.lookup"] = LOOKUP

    LOGGER.info("path: %s" % path)
    LOGGER.info("client address: %s" % environ.get("REMOTE_ADDR"))

    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = path

            try:
                return callback(environ, start_response, handle)
            except Exception,err:
                LOGGER.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------


USERDB = {
    "diana":{
        "user_id": "dikr0001",
        "name": "Diana Krall",
        "given_name": "Diana",
        "family_name": "Krall",
        "nickname": "Dina",
        "email": "diana@example.org",
        "verified": False,
        "phone_number": "+46 90 7865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },

#        "_external_": {
#            "https://localhost:8089/": ["birthdate", "gender", "address"]
#        }
    }
}

CLIENT_INFO = {
#    "https://localhost:8089/": {
#        "userclaims_endpoint":"https://localhost:8089/userclaims",
#        "client_id": "client_1",
#        "client_secret": "hemlig",
#        "x509_url": "https://localhost:8089/certs/mycert.pem",
#        }
}

if __name__ == '__main__':
    import argparse
    import shelve
    import importlib

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_builtin

    from oic.oic.server import Server
    from oic.utils.sdb import SessionDB


    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument(dest="config")
    args = parser.parse_args()

    cdb = shelve.open("client_db", writeback=True)
    # in memory session storage

    config = importlib.import_module(args.config)
    OAS = Server(config.issuer, SessionDB(), cdb, FUNCTIONS,  USERDB)

    try:
        OAS.cookie_ttl = config.COOKIETTL
    except AttributeError:
        pass

    try:
        OAS.cookie_name = config.COOKIENAME
    except AttributeError:
        pass

    OAS.cookie_func = http_util.cookie

    #print URLS
    if args.debug:
        OAS.debug = True

    OAS.endpoints = ENDPOINTS
    if args.port == 80:
        OAS.baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        OAS.baseurl = "%s:%d" % (config.baseurl, args.port)

    if not OAS.baseurl.endswith("/"):
        OAS.baseurl += "/"

    OAS.claims_clients = init_claims_clients(CLIENT_INFO)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)
    SRV.ssl_adapter = ssl_builtin.BuiltinSSLAdapter("certs/server.crt",
                                                    "certs/server.key")
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
