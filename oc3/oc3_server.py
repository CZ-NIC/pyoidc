#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __builtin__ import int, open, hasattr, isinstance
import sys
import os
import traceback

from exceptions import KeyError
from exceptions import Exception
from exceptions import ValueError
from exceptions import OSError
from exceptions import IndexError
from exceptions import AttributeError
from exceptions import KeyboardInterrupt
from oic.utils.authn import UsernamePasswordMako, verify_client

from oic.oauth2 import rndstr
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import KeyBundle
from oic.utils.userinfo import DistributedAggregatedUserInfo

__author__ = 'rohe0002'

import logging
import re

from logging.handlers import BufferingHandler

from oic.utils import http_util
from oic.oic.provider import Provider
from oic.oic.provider import STR

from oic.utils.http_util import *
from oic.oic.message import ProviderConfigurationResponse

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oc3.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

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
URLMAP = {}

NAME = "pyoic"

OAS = None

PASSWD = [("diana", "krall"), ("babs", "howes"), ("upper", "crust")]


#noinspection PyUnusedLocal
def devnull(txt):
    pass


def create_session_logger(log_format="CPC"):
    global HANDLER

    logger = logging.getLogger("")
    try:
        logger.addHandler(HANDLER["%s-buffer" % log_format])
    except KeyError:
        _formatter = logging.Formatter(log_format)
        handl = BufferingHandler(10000)
        handl.setFormatter(_formatter)
        logger.addHandler(handl)

    logger.setLevel(logging.INFO)

    return logger


def replace_format_handler(logger, log_format="CPC"):
    global ACTIVE_HANDLER
    global HANDLER
    global LOGFILE_NAME

    if ACTIVE_HANDLER == log_format:
        return logger

    _handler = HANDLER["%s-file" % log_format]
    if _handler in logger.handlers:
        return logger

    # remove all present handler
    logger.handlers = []

    try:
        logger.addHandler(HANDLER["%s-file" % log_format])
    except KeyError:
        _formatter = logging.Formatter(log_format)
        handl = logging.FileHandler(LOGFILE_NAME)
        handl.setFormatter(_formatter)
        logger.addHandler(handl)

    ACTIVE_HANDLER = format
    return logger

# #noinspection PyUnusedLocal
# def simple_user_info(oicsrv, userdb, user_id, client_id="",
#                      user_info_claims=None):
#     result = {"user_id": "diana"}
#     return OpenIDSchema(**result)

# ----------------------------------------------------------------------------


#noinspection PyUnusedLocal
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
    except OSError:
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------


def token(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.token_endpoint,
                        logger=logger, handle=handle)


#noinspection PyUnusedLocal
def authorization(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.authorization_endpoint,
                        logger=logger, handle=handle)


#noinspection PyUnusedLocal
def authenticated(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.authenticated,
                        logger=logger, handle=handle)


#noinspection PyUnusedLocal
def userinfo(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.userinfo_endpoint,
                        logger=logger, handle=handle)


#noinspection PyUnusedLocal
def op_info(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]
    LOGGER.info("op_info")
    return wsgi_wrapper(environ, start_response, _oas.providerinfo_endpoint,
                        logger=logger, handle=handle)


#noinspection PyUnusedLocal
def registration(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.registration_endpoint,
                        logger=logger, handle=handle)


#noinspection PyUnusedLocal
def check_id(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.check_id_endpoint,
                        logger=logger, handle=handle)


#noinspection PyUnusedLocal
def swd_info(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.discovery_endpoint,
                        logger=logger, handle=handle)


def trace_log(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.tracelog_endpoint,
                        logger=logger, handle=handle)


#noinspection PyUnusedLocal
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


#noinspection PyUnusedLocal
def verify(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]
    return _oas.authn.verify(environ, start_response, get_post(environ))


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
    (r'^verify', verify),
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
        URLS.append(("^%s" % endp.etype, endp))

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
    global OAS

    #user = environ.get("REMOTE_USER", "")
    path = environ.get('PATH_INFO', '').lstrip('/')

    logger = logging.getLogger('oicServer')

    if path == "robots.txt":
        return static(environ, start_response, logger, "static/robots.txt")

    environ["oic.oas"] = OAS
    remote = environ.get("REMOTE_ADDR")

    kaka = environ.get("HTTP_COOKIE", '')
    a1 = None
    handle = ""
    key = ""
    if kaka:
        try:
            handle = parse_cookie(OAS.cookie_name, OAS.seed, kaka)
            try:
                sid = handle[0]
            except TypeError:
                sid = ""

            if hasattr(OAS, "trace_log"):
                try:
                    _log = OAS.trace_log[sid]
                except KeyError:
                    _log = create_session_logger(sid)
                    OAS.trace_log[sid] = _log
            else:
                _log = replace_format_handler(logger)

            a1 = logging.LoggerAdapter(_log,
                                       {'path': path,
                                        'client': remote,
                                        "sid": sid})

        except ValueError:
            pass

    if not a1:
        sid = STR + rndstr() + STR
        handle = (sid, 0)

        if hasattr(OAS, "trace_log"):
            try:
                _log = OAS.trace_log[sid]
            except KeyError:
                _log = OAS.new_trace_log(sid)
        else:
            _log = replace_format_handler(logger)

        a1 = logging.LoggerAdapter(_log, {'path': path, 'client': remote,
                                          "sid": sid})

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
            except Exception, err:
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

class TestProvider(Provider):
    #noinspection PyUnusedLocal
    def __init__(self, name, sdb, cdb, function, userdb, urlmap=None,
                 debug=0, ca_certs="", jwt_keys=None):
        Provider.__init__(self, name, sdb, cdb, function, userdb, urlmap,
                          ca_certs, jwt_keys)
        self.test_mode = True
        self.trace_log = {}
        self.sessions = []
        self.max_sessions = 100

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

        del self.trace_log[handle[0]]
        self.sessions.remove(handle[0])
        resp = Response("no info", content="text/plain")
        return resp(environ, start_response)

    def re_link_log(self, old, new):
        self.trace_log[new] = self.trace_log[old]

    def new_trace_log(self, key):
        _log = create_session_logger(key)
        if len(self.trace_log) > self.max_sessions:
            # remove the oldest
            oldest = self.sessions[0]
            del self.trace_log[oldest]
            self.sessions = self.sessions[1:]
        self.trace_log[key] = _log
        return _log


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
    #from cherrypy.wsgiserver import ssl_builtin
    from cherrypy.wsgiserver import ssl_pyopenssl

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

    cdb = shelve.open("client_db", writeback=True)
    # in memory session storage

    config = importlib.import_module(args.config)
    # Authentication method
    authn = UsernamePasswordMako(None, "login.mako", TemplateLookup, PASSWD,
                                 "authenticated")
    # dealing with authorization
    authz = AuthzHandling()
    # User info database
    userdb = None   # will be set later
    if args.test:
        URLS.append((r'tracelog', trace_log))
        OAS = TestProvider(config.issuer, SessionDB(), cdb, authn, userdb,
                           authz, config.SYM_KEY)
    else:
        OAS = Provider(config.issuer, SessionDB(), cdb, authn, userdb, authz,
                       verify_client, config.SYM_KEY)

    authn.srv = OAS

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

    if args.authn_as:
        OAS.authn_as = args.authn_as

    if args.provider_conf:
        prc = ProviderConfigurationResponse().from_json(
            open(args.provider_conf).read())
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

    LOGGER.info("OC3 server keyjar: %s" % OAS.keyjar)

    if not OAS.baseurl.endswith("/"):
        OAS.baseurl += "/"

    try:
        OAS.keyjar[""] = []
        for typ, info in config.keys.items():
            LOGGER.info("OC3 server key init: %s, %s" % (typ, info))
            kc = KeyBundle(source="file://%s" % info["key"])
            OAS.keyjar[""].append(kc)
            try:
                new_name = mv_content(info["jwk"], "static")
                OAS.jwks_uri.append("%s%s" % (OAS.baseurl, new_name))
            except KeyError:
                pass
        for b in OAS.keyjar[""]:
            LOGGER.info("OC3 server keys: %s" % b)
    except Exception, err:
        OAS.key_setup("static", sig={"format": "jwk", "alg": "rsa"})

    OAS.userdb = DistributedAggregatedUserInfo(config.USERDB, OAS,
                                               config.CLIENT_INFO)

    for key, cc in OAS.userdb.claims_clients.items():
        OAS.keyjar.update(cc.keyjar)

    # Add the claims providers keys
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)

    SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(config.SERVER_CERT,
                                                     config.SERVER_KEY,
                                                     config.CERT_CHAIN)

    LOGGER.info("OC3 server starting listening on port:%s" % args.port)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
