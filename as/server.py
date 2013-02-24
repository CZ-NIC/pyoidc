#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __builtin__ import int, open, hasattr, isinstance
import base64
import sys
import os
import traceback
import logging
import re

from logging.handlers import BufferingHandler

from exceptions import KeyError
from exceptions import Exception
from exceptions import ValueError
from exceptions import OSError
from exceptions import IndexError
from exceptions import AttributeError
from exceptions import KeyboardInterrupt

from oic.oauth2 import rndstr

from oic.utils import http_util
from oic.oauth2.provider import Provider, AuthnFailure
from oic.utils.http_util import *

from mako.lookup import TemplateLookup

__author__ = 'rohe0002'

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

    argv = {"sid": sid,
            "login": "",
            "password": "",
            "action": "authenticated",
            "policy_url": policy_url,
            "logo_url": logo_url}
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
    if user in [u for u, p in PASSWD]:
        return "ALL"
    else:
        raise Exception("No Authorization defined")


#noinspection PyUnusedLocal
def verify_client(environ, areq, cdb):
    authz_info = environ["HTTP_AUTHORIZATION"]
    if authz_info.startswith("Basic "):
        _info = base64.b64decode(authz_info[6:])
        LOGGER.debug("Authz_info: %s" % _info)
        (client, secret) = _info.split(":")
        if client in cdb:
            assert cdb[client]["client_secret"] == secret
    else:
        client = ""

    return client


FUNCTIONS = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify_user": verify_username_and_password,
    "verify_client": verify_client,
}

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
    except Exception:
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------


def token(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.token_endpoint(environ, start_response)


#noinspection PyUnusedLocal
def authorization(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.authorization_endpoint(environ, start_response, logger=logger,
                                       handle=handle)


#noinspection PyUnusedLocal
def authenticated(environ, start_response, logger, handle):
    _oas = environ["oic.oas"]

    return _oas.authenticated(environ, start_response)


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
from oic.oauth2.provider import AuthorizationEndpoint
from oic.oauth2.provider import TokenEndpoint

ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
]

URLS = [
    (r'^authenticated', authenticated),
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

LOOKUP = TemplateLookup(directories=[ROOT + 'templates'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

# ----------------------------------------------------------------------------

STR = 5 * "_"


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
            try:
                key = handle[0]
            except TypeError:
                key = ""

            if hasattr(OAS, "trace_log"):
                try:
                    _log = OAS.trace_log[key]
                except KeyError:
                    _log = create_session_logger(key)
                    OAS.trace_log[key] = _log
            else:
                _log = replace_format_handler(logger)

            a1 = logging.LoggerAdapter(_log,
                                       {'path': path,
                                        'client': remote,
                                        "cid": key})

        except ValueError:
            pass

    if not a1:
        key = STR + rndstr() + STR
        handle = (key, 0)

        if hasattr(OAS, "trace_log"):
            try:
                _log = OAS.trace_log[key]
            except KeyError:
                _log = OAS.new_trace_log(key)
        else:
            _log = replace_format_handler(logger)

        a1 = logging.LoggerAdapter(_log, {'path': path, 'client': remote,
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
    import importlib

    from cherrypy import wsgiserver
    #from cherrypy.wsgiserver import ssl_builtin
    from cherrypy.wsgiserver import ssl_pyopenssl

    from oic.utils.sdb import SessionDB

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-A', dest='authn_as', default="")
    parser.add_argument('-P', dest='provider_conf')
    parser.add_argument(dest="config")
    args = parser.parse_args()


    config = importlib.import_module(args.config)

    OAS = Provider(config.issuer, SessionDB(), config.CLIENT, FUNCTIONS,
                   config.USERDB)

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
