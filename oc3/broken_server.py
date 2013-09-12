#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __builtin__ import int, open, hasattr
import copy
from exceptions import KeyError
from exceptions import Exception
from exceptions import ValueError
from exceptions import OSError
from exceptions import IndexError
from exceptions import AttributeError
from exceptions import KeyboardInterrupt

import sys
import os
import traceback

from jwkest.jwk import load_x509_cert
from jwkest.jwk import load_jwk
from jwkest.jws import alg2keytype

from oic.oauth2 import rndstr
from oic.utils.keystore import rsa_load
from oic.utils.keystore import get_signing_key

__author__ = 'rohe0002'

import logging
import re

from logging.handlers import BufferingHandler

from oic.utils import http_util
from oic.oic.provider import Provider
from oic.oic.provider import STR

from oic.utils.http_util import *
from oic.oic.message import OpenIDSchema, RegistrationRequest
from oic.oic.message import AuthnToken
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.provider import AuthnFailure
from oic.oic.claims_provider import ClaimsClient

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oc4broke.log'
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
ACTIVE_HANDLER = "BASE"
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
    global HANDLER

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
    global ACTIVE_HANDLER
    global HANDLER
    global LOGFILE_NAME

    if ACTIVE_HANDLER == format:
        return logger

    _handler = HANDLER["%s-file" % format]
    print "handlers", logger.handlers
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

    print "**handlers", logger.handlers
    ACTIVE_HANDLER = format
    return logger

def do_authentication(environ, start_response, sid, cookie=None,
                      policy_url=None, logo_url=None):
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
             "action": "authenticated",
             "policy_url": policy_url,
             "logo_url": logo_url
    }
    LOGGER.info("do_authentication argv: %s" % argv)
    return resp(environ, start_response, **argv)

def verify_username_and_password(dic):
    global PASSWD
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
    global PASSWD
    if user in [u for u,p in PASSWD]:
        return "ALL"
    else:
        raise Exception("No Authorization defined")

#noinspection PyUnusedLocal
def verify_client(environ, areq, cdb):
    global JWT_BEARER
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
            _req = cc.keystore.crypt.http_request
            _s2k = cc.keystore.spec2key
            try:
                for typ, key in load_x509_cert(_req, specs["x509_url"], _s2k):
                    cc.keystore.set_verify_key(key, typ, cid)
            except KeyError:
                pass
            try:
                for typ, key in load_jwk(_req, specs["jwk_url"], _s2k):
                    cc.keystore.set_verify_key(key, typ, cid)
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
    """
    :param oicsrv: The OpenID Connect server instance
    :param userdb: A user DB
    :param user_id: The local user id
    :param client_id: Identifier of the RP
    :param user_info_claims: Possible userinfo claims (a dictionary)
    :return: A schema dependent userinfo instance
    """
    #print >> sys.stderr, "claims: %s" % user_info_claims
    global LOGGER

    LOGGER.info("User_info about '%s'" % user_id)
    identity = copy.copy(userdb[user_id])

    if user_info_claims:
        result = {}
        missing = []
        optional = []
        if "claims" in user_info_claims:
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

#noinspection PyUnusedLocal
def simple_user_info(oicsrv, userdb, user_id, client_id="",
                     user_info_claims=None):
    result = {"user_id": "diana"}
    return OpenIDSchema(**result)

FUNCTIONS = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify_user": verify_username_and_password,
    "verify_client": verify_client,
    "userinfo": user_info,
    }

# ----------------------------------------------------------------------------

def safe(environ, start_response, logger, handle):
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
def css(environ, start_response, logger, handle):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except Exception:
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------

def token(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.token_endpoint(environ, start_response, logger=logger,
                               handle=handle)

#noinspection PyUnusedLocal
def authorization(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.authorization_endpoint(environ, start_response, logger=logger,
                                       handle=handle)

#noinspection PyUnusedLocal
def authenticated(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.authenticated(environ, start_response, logger=logger,
                              handle=handle)

#noinspection PyUnusedLocal
def userinfo(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.userinfo_endpoint(environ, start_response, logger=logger,
                                  handle=handle)

#noinspection PyUnusedLocal
def op_info(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]
    LOGGER.info("op_info")
    return _oas.providerinfo_endpoint(environ, start_response, logger=logger,
                                      handle=handle)

#noinspection PyUnusedLocal
def registration(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.registration_endpoint(environ, start_response, logger=logger,
                                      handle=handle)

#noinspection PyUnusedLocal
def check_id(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.check_id_endpoint(environ, start_response, logger=logger,
                                  handle=handle)

#noinspection PyUnusedLocal
def swd_info(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.discovery_endpoint(environ, start_response, logger=logger,
                                   handle=handle)

def trace_log(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.tracelog_endpoint(environ, start_response, logger=logger,
                                  handle=handle)

def meta_info(environ, start_response, logger, handle):
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

#noinspection PyUnresolvedReferences
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

def add_endpoints(extra):
    global URLS

    for endp in extra:
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

    logger = logging.getLogger('oicServer')

    if path == "robots.txt":
        return static(environ, start_response, logger, "static/robots.txt")

    environ["oic.oas"] = OAS
    environ["mako.lookup"] = LOOKUP

    remote = environ.get("REMOTE_ADDR")

    kaka = environ.get("HTTP_COOKIE", '')
    a1 = None
    handle = ""
    key = ""
    if kaka:
        try:
            handle = parse_cookie(OAS.cookie_name, OAS.seed, kaka)
            key = handle[0]

            _log = replace_format_handler(logger)
            if OAS.debug:
                _log.setLevel(logging.DEBUG)
            a1 = logging.LoggerAdapter(_log,
                                {'path' : path, 'client' : remote, "cid": key})
        except ValueError:
            pass

    if not a1:
        key = STR+rndstr()+STR
        handle = (key, 0)

        _log = replace_format_handler(logger)
        if OAS.debug:
            _log.setLevel(logging.DEBUG)
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
                return callback(environ, start_response, a1, handle)
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

CLAIMS_PROVIDER = "https://localhost:8093/"

USERDB = {
    "haho0032": {
        "user_id": "haho0032",
        "name": "Hans Hörberg",
        "given_name": "Hans",
        "family_name": "Hörberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "email_verified": False,
        "phone_number": "+46 90 7865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
    },
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
            CLAIMS_PROVIDER: ["geolocation"]
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
            CLAIMS_PROVIDER: ["geolocation"]
        }
    }
}

CLIENT_INFO = {
    CLAIMS_PROVIDER: {
        "userclaims_endpoint":"%suserclaims" % CLAIMS_PROVIDER,
        "client_id": "client_1",
        "client_secret": "hemlig",
        "x509_url": "%scp_keys/cert.pem" % CLAIMS_PROVIDER,
        "jwk_url": "%scp_keys/pub.jwk" % CLAIMS_PROVIDER,
        }
}

class BrokenProvider(Provider):
    def __init__(self, name, sdb, cdb, function, userdb, urlmap=None,
                 debug=0, ca_certs="", jwt_keys=None):
        Provider.__init__(self, name, sdb, cdb, function, userdb, urlmap,
                          ca_certs, jwt_keys)

    def id_token_as_signed_jwt(self, session, loa="2", alg="RS256", code=None,
                               access_token=None, user_info=None):

        _idt = self.server.make_id_token(session, loa, self.name, alg, code,
                                         access_token, user_info)

        # mess with the at_hash or the c_hash
        if "at_hash" in _idt:
            _idt["at_hash"] += "a"
        if "c_hash" in _idt:
            _idt["c_hash"] += "c"

        LOGGER.debug("Signing alg: %s" % alg)
        LOGGER.debug("keys: %s" % self.keystore.keys_by_owner(session["client_id"]))
        ckey = get_signing_key(self.keystore, alg2keytype(alg),
                               session["client_id"])
        LOGGER.debug("ckey: %s" % ckey)
        return _idt.to_jwt(key=ckey, algorithm=alg)

    def registration_endpoint(self, environ, start_response, **kwargs):
        before = self.cdb.keys()

        res = Provider.l_registration_endpoint(self, environ, **kwargs)

        after = [i for i in self.cdb.keys() if i not in before]
        print >> sys.stderr, after

        cid = after[0]
        for err in ["A", "B", "C"]:
            self.cdb["%s_ERR%s" % (cid,err)] = self.cdb[cid]

        return res(environ, start_response)

def mv_content(fro, to):
    txt = open(fro).read()
    (head, tail) = os.path.split(fro)
    name = "%s/%s" % (to, tail)
    f = open(name, 'w')
    f.write(txt)
    f.close()
    return name

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
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-t', dest='test', action='store_true')
    parser.add_argument('-A', dest='authn_as', default="")
    parser.add_argument('-P', dest='provider_conf')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    #cdb = shelve.open("client_db", writeback=True)
    # in memory session storage
    cdb = {}

    config = importlib.import_module(args.config)
    OAS = BrokenProvider(config.issuer, SessionDB(), cdb, FUNCTIONS,  USERDB)

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

    if args.authn_as:
        OAS.authn_as = args.authn_as

    if args.provider_conf:
        prc = ProviderConfigurationResponse().from_json(open(args.provider_conf).read())
        endpoints = []
        for key in prc.keys():
            if key.endswith("_endpoint"):
                endpoints.append(key)
    else:
        endpoints = ENDPOINTS

    add_endpoints(endpoints)
    OAS.endpoints = endpoints

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
                    name = mv_content(info["cert"], "static")
                    OAS.cert.append(name)
                except KeyError:
                    pass
                try:
                    new_name = mv_content(info["jwk"], "static")
                    OAS.jwk.append("%s%s" % (OAS.baseurl, new_name))
                except KeyError:
                    pass
        except Exception, err:
            OAS.key_setup("static", sig={"format":"jwk", "alg":"rsa"})

#    OAS.claims_clients = init_claims_clients(CLIENT_INFO)
#
#    for key, cc in OAS.claims_clients.items():
#        OAS.keystore.update(cc.keystore)

    # Add the claims providers keys
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)
    SRV.ssl_adapter = ssl_builtin.BuiltinSSLAdapter("certs/server.crt",
                                                    "certs/server.key")

    LOGGER.info("OC4 server starting listening on port:%s" % args.port)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
