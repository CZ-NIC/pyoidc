#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import traceback
from oic.oauth2 import rndstr
import sys
from oic.utils.keystore import rsa_load

__author__ = 'rohe0002'

import logging
import re

from logging.handlers import BufferingHandler

from oic.utils import http_util
from oic.oic.provider import Provider
from oic.oic.provider import STR

from oic.utils.http_util import *
from oic.oic.message import OpenIDSchema
from oic.oic.message import AuthnToken
from oic.oic.provider import AuthnFailure
from oic.oic.claims_provider import ClaimsClient
from oic.oic import JWT_BEARER

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oc3.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = '%(asctime)s %(name)s:%(levelname)s [%(client)s,%(path)s,%(cid)s] %(message)s'
cpc_formatter = logging.Formatter(CPC)

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

_formatter = logging.Formatter(CPC)
fil_handl = logging.FileHandler(LOGFILE_NAME)
fil_handl.setFormatter(_formatter)

buf_handl = BufferingHandler(10000)
buf_handl.setFormatter(_formatter)

HANDLER = {"CPC-file": fil_handl, "CPC-buffer": buf_handl}

URLMAP={}

NAME = "pyoic"

OAS = None

PASSWD = [("diana", "krall"),
            ("babs", "howes"),
            ("upper", "crust")]


#noinspection PyUnusedLocal
def devnull(txt):
    pass


def create_session_logger(format="CPC"):
    logger = logging.getLogger("")
    try:
        logger.addHandler(HANDLER["%s-buffer" % format])
    except KeyError:
        _formatter = logging.Formatter(format)
        handl = BufferingHandler(10000)
        handl.setFormatter(_formatter)
        logger.addHandler(handl)

    logger.setLevel(logging.INFO)

    return logger

def replace_format_handler(logger, format="CPC"):
    _handler = HANDLER["%s-file" % format]
    if _handler in logger.handlers:
        return logger

    # remove all present handler
    logger.handlers = []

    try:
        logger.addHandler(HANDLER["%s-file" % format])
    except KeyError:
        _formatter = logging.Formatter(format)
        handl = logging.FileHandler(LOGFILE_NAME)
        handl.setFormatter(_formatter)
        logger.addHandler(handl)

    return logger

def do_authentication(environ, start_response, sid, cookie=None):
    """
    Put up the login form
    """
    if cookie:
        headers = [cookie]
    else:
        headers = []
    resp = Response(mako_template="login.mako",
                    template_lookup=environ["mako.lookup"], headers=headers)

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
    if "client_secret" in areq: # client_secret_post
        identity = areq["client_id"]
        if identity in cdb:
            if cdb[identity]["client_secret"] == areq["client_secret"]:
                return True
    elif "client_assertion" in areq: # client_secret_jwt or public_key_jwt
        assert areq["client_assertion_type"] == JWT_BEARER
        secret = cdb[areq["client_id"]]["client_secret"]
        key_col = {"hmac": secret}
        bjwt = AuthnToken.deserialize(areq["client_assertion"], "jwt",
                                      key=key_col)
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
            try:
                cc.keystore.load_x509_cert(specs["x509_url"], "ver", cid)
            except KeyError:
                pass
            try:
                cc.keystore.load_jwk(specs["jwk_url"], "ver", cid)
            except KeyError:
                pass
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

    for key in resp["claims_names"]:
        result["_claims_names"][key] = alias

    if "jwt" in resp:
        result["_claims_sources"][alias] = {"JWT": resp["jwt"]}
    else:
        result["_claims_sources"][alias] = {"endpoint": resp["endpoint"]}
        if "access_token" in resp:
            result["_claims_sources"][alias]["access_token"] = resp["access_token"]

    return result

#noinspection PyUnusedLocal
def user_info(oicsrv, userdb, user_id, client_id="", user_info_claims=None):
    #print >> sys.stderr, "claims: %s" % user_info_claims

    identity = userdb[user_id]

    if user_info_claims:
        result = {}
        missing = []
        optional = []
        for key, restr in user_info_claims["claims"].items():
            try:
                result[key] = identity[key]
            except KeyError:
                if restr == {"essential": True}:
                    missing.append(key)
                else:
                    optional.append(key)

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
                print >> sys.stderr, srv, what
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
    #_log_info("env: %s" % environ)
    #_log_info("handle: %s" % (handle,))

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
def css(environ, start_response, handle):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except Exception:
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------

def token(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.token_endpoint(environ, start_response, handle=handle)

#noinspection PyUnusedLocal
def authorization(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.authorization_endpoint(environ, start_response,
                                       handle=handle)

#noinspection PyUnusedLocal
def authenticated(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.authenticated(environ, start_response, handle=handle)

#noinspection PyUnusedLocal
def userinfo(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.userinfo_endpoint(environ, start_response, handle=handle)

#noinspection PyUnusedLocal
def op_info(environ, start_response, handle):
    _oas = environ["oic.oas"]
    LOGGER.info("op_info")
    return _oas.providerinfo_endpoint(environ, start_response, handle=handle)

#noinspection PyUnusedLocal
def registration(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.registration_endpoint(environ, start_response, handle=handle)

#noinspection PyUnusedLocal
def check_id(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.check_id_endpoint(environ, start_response, handle=handle)

#noinspection PyUnusedLocal
def swd_info(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.discovery_endpoint(environ, start_response, handle=handle)

def trace_log(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.tracelog_endpoint(environ, start_response, handle=handle)

def meta_info(environ, start_response, handle):
    """
    Returns something like this
     {"links":[
        {
            "rel":"http://openid.net/specs/connect/1.0/issuer",
            "href":"https://openidconnect.info/"
        }
     ]}
    """
    pass

def static_file(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False

def static(environ, start_response, logger, path):
    logger.info("[static]sending: %s" % (path,))

    try:
        text = open(path).read()
        if path.endswith(".ico"):
            start_response('200 OK', [('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            start_response('200 OK', [('Content-Type', 'text/html')])
        elif path.endswith(".json"):
            start_response('200 OK', [('Content-Type', 'application/json')])
        elif path.endswith(".txt"):
            start_response('200 OK', [('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            start_response('200 OK', [('Content-Type', 'text/css')])
        else:
            start_response('200 OK', [('Content-Type', "text/xml")])
        return [text]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)

# ----------------------------------------------------------------------------
from oic.oic.provider import AuthorizationEndpoint
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import UserinfoEndpoint
#from oic.oic.provider import CheckIDEndpoint
from oic.oic.provider import RegistrationEndpoint


ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
    UserinfoEndpoint(userinfo),
    #CheckIDEndpoint(check_id),
    RegistrationEndpoint(registration)
    ]

URLS = [
    (r'^authenticated', authenticated),
    (r'^.well-known/openid-configuration', op_info),
    (r'^.well-known/simple-web-discovery', swd_info),
    (r'^.well-known/host-meta.json', meta_info),
    (r'.+\.css$', css),
    (r'safe', safe),
#    (r'tracelog', trace_log),
]

for endp in ENDPOINTS:
    URLS.append(("^%s" % endp.type, endp))

# ----------------------------------------------------------------------------

ROOT = './'

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

    environ["oic.oas"] = OAS
    environ["mako.lookup"] = LOOKUP

    remote = environ.get("REMOTE_ADDR")
    logger = logging.getLogger('oicServer')

    kaka = environ.get("HTTP_COOKIE", '')
    a1 = None
    handle = ""
    key = ""
    if kaka:
        try:
            handle = parse_cookie(OAS.cookie_name, OAS.seed, kaka)
            key = handle[0]

            if hasattr(OAS, "trace_log"):
                try:
                    _log = OAS.trace_log[key]
                except KeyError:
                    _log = create_session_logger(key)
                    OAS.trace_log[key] = _log
            else:
                _log = replace_format_handler(logger)

            a1 = logging.LoggerAdapter(_log,
                                {'path' : path, 'client' : remote, "cid": key})

        except ValueError:
            pass

    if not a1:
        key = STR+rndstr()+STR
        handle = (key, 0)

        if hasattr(OAS, "trace_log"):
            try:
                _log = OAS.trace_log[key]
            except KeyError:
                _log = create_session_logger(key)
                OAS.trace_log[key] = _log
        else:
            _log = replace_format_handler(logger)

        a1 = logging.LoggerAdapter(_log, {'path' : path, 'client' : remote,
                                          "cid": key})

    #logger.info("handle:%s [%s]" % (handle, a1))
    #a1.info(40*"-")
    if path.startswith("static/"):
        return static(environ, start_response, a1, path)
#    elif path.startswith("oc3_keys/"):
#        return static(environ, start_response, a1, path)

    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = path

            a1.info("callback: %s" % callback)
            try:
                return callback(environ, start_response, handle)
            except Exception,err:
                print >> sys.stderr, "%s" % err
                message = traceback.format_exception(*sys.exc_info())
                print >> sys.stderr, message
                a1.exception("%s" % err)
                if key and hasattr(OAS, "trace_log"):
                    _txt = OAS.dump_tracelog(key)
                    _txt += "\n" + "%s" % err
                    resp = ServiceError(_txt)
                else:
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
        "email_verified": False,
        "phone_number": "+46 90 7865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
    },
    "babs": {
        "user_id": "babs0001",
        "name": "Barbara J Jensen",
        "given_name": "Barbara",
        "family_name": "Jensen",
        "nickname": "babs",
        "email": "babs@example.com",
        "email_verified": True,
        "address": {
            "street_address": "100 Universal City Plaza",
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "91608",
            "country": "USA",
        },
        "_external_": {
            "https://localhost:8089/": ["geolocation"]
        }
    },
    "upper": {
        "user_id": "uppe0001",
        "name": "Upper Crust",
        "given_name": "Upper",
        "family_name": "Crust",
        "email": "uc@example.com",
        "email_verified": True,
        "_external_": {
            "https://localhost:8089/": ["geolocation"]
        }
    }
}

CLIENT_INFO = {
    "https://localhost:8089/": {
        "userclaims_endpoint":"https://localhost:8089/userclaims",
        "client_id": "client_1",
        "client_secret": "hemlig",
        "x509_url": "https://localhost:8089/cp_keys/cert.pem",
        "jwk_url": "https://localhost:8089/cp_keys/pub.jwk",
        }
}

class TestProvider(Provider):
    def __init__(self, name, sdb, cdb, function, userdb, urlmap=None,
             debug=0, ca_certs="", jwt_keys=None):
        Provider.__init__(self, name, sdb, cdb, function, userdb, urlmap,
                          ca_certs, jwt_keys)
        self.test_mode = True
        self.trace_log = {}

    def dump_tracelog(self, key):
        tlog = self.trace_log[key]
        for handler in tlog.handlers:
            if isinstance(handler, BufferingHandler):
                arr = []
                for record in handler.buffer:
                    arr.append(handler.format(record))

                return "\n".join(arr)
        return ""

    #noinspection PyUnusedLocal
    def tracelog_endpoint(self, environ, start_response, logger, **kwargs):
        handle = kwargs["handle"]
        tlog = self.trace_log[handle[0]]
        for handler in tlog.handlers:
            if isinstance(handler, BufferingHandler):
                arr = []
                for record in handler.buffer:
                    arr.append(handler.format(record))

                resp = Response("\n".join(arr), content="text/plain")
                return resp(environ, start_response)

        resp = Response("no info", content="text/plain")
        return resp(environ, start_response)

    def re_link_log(self, old, new):
        self.trace_log[new] = self.trace_log[old]

def mv_content(fro, to):
    txt = open(fro).read()
    (head, tail) = os.path.split(fro)
    f = open("%s/%s" % (to, tail))
    f.write(txt)
    f.close

if __name__ == '__main__':
    import argparse
    import shelve
    import importlib

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_builtin

    from oic.utils.sdb import SessionDB

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-t', dest='test', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument(dest="config")
    args = parser.parse_args()

    cdb = shelve.open("client_db", writeback=True)
    # in memory session storage

    config = importlib.import_module(args.config)
    if args.test:
        URLS.append((r'tracelog', trace_log))
        OAS = TestProvider(config.issuer, SessionDB(), cdb, FUNCTIONS,  USERDB)
    else:
        OAS = Provider(config.issuer, SessionDB(), cdb, FUNCTIONS,  USERDB)

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
    if args.test:
        OAS.test_mode = True
    else:
        OAS.test_mode = False

    OAS.endpoints = ENDPOINTS
    if args.port == 80:
        OAS.baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        OAS.baseurl = "%s:%d" % (config.baseurl, args.port)

    if not OAS.baseurl.endswith("/"):
        OAS.baseurl += "/"

        try:
            for type, info in config.keys.items():
                _rsa = rsa_load(info["key"])
                OAS.keystore.add_key(_rsa, type, "sig")
                OAS.keystore.add_key(_rsa, type, "ver")
                try:
                    OAS.cert.append(info["cert"])
                    mv_content(info["cert"], "static")
                except KeyError:
                    pass
                try:
                    OAS.jwk.append(info["jwk"])
                    mv_content(info["jwk"], "static")
                except KeyError:
                    pass

        except Exception:
            OAS.key_setup("static", sig={"format":"jwk", "alg":"rsa"})

    OAS.claims_clients = init_claims_clients(CLIENT_INFO)

    for key, cc in OAS.claims_clients.items():
        OAS.keystore.update(cc.keystore)

    LOGGER.debug("%s" % OAS.keystore._store)

    # Add the claims providers keys
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)
    SRV.ssl_adapter = ssl_builtin.BuiltinSSLAdapter("certs/server.crt",
                                                    "certs/server.key")

    LOGGER.info("OC3 server starting")
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
