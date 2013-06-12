#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import traceback

from exceptions import KeyError
from exceptions import Exception
from exceptions import OSError
from exceptions import IndexError
from exceptions import AttributeError
from exceptions import KeyboardInterrupt
from oic.utils.authn.client import verify_client

from oic.utils.authz import AuthzHandling
from oic.utils.userinfo import UserInfo

__author__ = 'rohe0002'

import logging
import re

from oic.utils import http_util
from oic.oauth2.provider import Provider

from oic.utils.http_util import *

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oa.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

URLMAP = {}

NAME = "pyoic"

OAS = None

PASSWD = {"diana": "krall",
          "babs": "howes",
          "upper": "crust",
          "rohe0002": "StevieRay",
          "haho0032": "qwerty"}


#noinspection PyUnusedLocal
def devnull(txt):
    pass


# ----------------------------------------------------------------------------


#noinspection PyUnusedLocal
def safe(environ, start_response, logger):
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
def css(environ, start_response, logger):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except OSError:
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------


#noinspection PyUnusedLocal
def token(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.token_endpoint,
                        logger=logger)


#noinspection PyUnusedLocal
def authorization(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.authorization_endpoint,
                        logger=logger)


#noinspection PyUnusedLocal
def verify(environ, start_response, logger):
    _oas = environ["oic.oas"]
    return wsgi_wrapper(environ, start_response, _oas.authn.verify,
                        logger=logger)


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

ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
]

URLS = [
    (r'^verify', verify),
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

    #remote = environ.get("REMOTE_ADDR")
    #kaka = environ.get("HTTP_COOKIE", '')

    if path.startswith("static/"):
        return static(environ, start_response, logger, path)
#    elif path.startswith("oc_keys/"):
#        return static(environ, start_response, logger, path)

    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = path

            logger.info("callback: %s" % callback)
            try:
                return callback(environ, start_response, logger)
            except Exception, err:
                print >> sys.stderr, "%s" % err
                message = traceback.format_exception(*sys.exc_info())
                print >> sys.stderr, message
                logger.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    LOGGER.debug("unknown side: %s" % path)
    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

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
    parser.add_argument('-X', dest='XpressConnect', action='store_true')
    parser.add_argument('-A', dest='authn_as', default="")
    parser.add_argument('-P', dest='provider_conf')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # Client data base
    cdb = shelve.open("client_db", writeback=True)

    config = importlib.import_module(args.config)
    config.issuer = config.issuer % args.port
    config.SERVICE_URL = config.SERVICE_URL % args.port

    if config.AUTHN == 'CasAuthnMethod':
        from oic.utils.authn.user_cas import CasAuthnMethod
        from oic.utils.authn.ldap_member import UserLDAPMemberValidation

        config.LDAP_EXTRAVALIDATION.update(config.LDAP)
        authn = CasAuthnMethod(
            None, config.CAS_SERVER, config.SERVICE_URL,
            "%s/authorization" % config.issuer,
            UserLDAPMemberValidation(**config.LDAP_EXTRAVALIDATION))
    else:
        from oic.utils.authn.user import UsernamePasswordMako
        authn = UsernamePasswordMako(None, "login.mako", LOOKUP, PASSWD,
                                     "%s/authorization" % config.issuer)

    # dealing with authorization
    authz = AuthzHandling()
    # User info database
    OAS = Provider(config.issuer, SessionDB(), cdb, authn, authz,
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

    OAS.cookie_func = http_util.make_cookie
    #print URLS
    if args.debug:
        OAS.debug = True
    if args.test:
        OAS.test_mode = True
    else:
        OAS.test_mode = False

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

    if config.USERINFO == "LDAP":
        from oic.utils.userinfo.ldap_info import UserInfoLDAP
        OAS.userinfo = UserInfoLDAP(**config.LDAP)
    elif config.USERINFO == "SIMPLE":
        OAS.userinfo = UserInfo(config.DISTDB)
    elif config.USERINFO == "DISTRIBUTED":
        from oic.utils.userinfo.distaggr import DistributedAggregatedUserInfo
        OAS.userinfo = DistributedAggregatedUserInfo(config.USERDB, OAS,
                                                     config.CLIENT_INFO)

    LOGGER.debug("URLS: '%s" % (URLS,))
    # Add the claims providers keys
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)

    SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(config.SERVER_CERT,
                                                     config.SERVER_KEY,
                                                     config.CERT_CHAIN)

    LOGGER.info("OC server starting listening on port:%s" % args.port)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
