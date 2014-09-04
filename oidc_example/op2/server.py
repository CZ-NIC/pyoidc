#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import sys
import os
import traceback

from exceptions import KeyError
from exceptions import Exception
from exceptions import OSError
from exceptions import IndexError
from exceptions import AttributeError
from exceptions import KeyboardInterrupt
from urlparse import parse_qs
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO
from oic.utils.authn.javascript_login import JavascriptFormMako

from oic.utils.authn.client import verify_client
from oic.utils.authn.multi_auth import setup_multi_auth, AuthnIndexedEndpointWrapper
from oic.utils.authn.saml import SAMLAuthnMethod
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import KeyBundle, dump_jwks
from oic.utils.userinfo import UserInfo
from oic.utils.userinfo.aa_info import AaUserInfo
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.authn.authn_context import AuthnBroker, make_auth_verify

__author__ = 'rohe0002'

import re

from oic.oic.provider import Provider
from oic.oic.provider import EndSessionEndpoint
from oic.utils.http_util import *

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oc.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = ('%(asctime)s %(name)s:%(levelname)s '
       '[%(client)s,%(path)s,%(cid)s] %(message)s')
cpc_formatter = logging.Formatter(CPC)

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

URLMAP = {}
NAME = "pyoic"
OAS = None

PASSWD = {
    "diana": "krall",
    "babs": "howes",
    "upper": "crust"
}


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

    info = "'%s' secrets" % _sinfo["sub"]
    resp = Response(info)
    return resp(environ, start_response)


#noinspection PyUnusedLocal
def css(environ, start_response, logger):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except (OSError, IOError):
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
def userinfo(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.userinfo_endpoint,
                        logger=logger)


#noinspection PyUnusedLocal
def op_info(environ, start_response, logger):
    _oas = environ["oic.oas"]
    LOGGER.info("op_info")
    return wsgi_wrapper(environ, start_response, _oas.providerinfo_endpoint,
                        logger=logger)


#noinspection PyUnusedLocal
def registration(environ, start_response, logger):
    _oas = environ["oic.oas"]

    if environ["REQUEST_METHOD"] == "POST":
        return wsgi_wrapper(environ, start_response, _oas.registration_endpoint,
                            logger=logger)
    elif environ["REQUEST_METHOD"] == "GET":
        return wsgi_wrapper(environ, start_response, _oas.read_registration,
                            logger=logger)
    else:
        resp = ServiceError("Method not supported")
        return resp(environ, start_response)


#noinspection PyUnusedLocal
def check_id(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.check_id_endpoint,
                        logger=logger)


#noinspection PyUnusedLocal
def swd_info(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.discovery_endpoint,
                        logger=logger)


#noinspection PyUnusedLocal
def trace_log(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.tracelog_endpoint,
                        logger=logger)


#noinspection PyUnusedLocal
def endsession(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.endsession_endpoint,
                        logger=logger)


#noinspection PyUnusedLocal
def meta_info(environ, start_response, logger):
    """
    Returns something like this::

         {"links":[
             {
                "rel":"http://openid.net/specs/connect/1.0/issuer",
                "href":"https://openidconnect.info/"
             }
         ]}

    """
    pass


def webfinger(environ, start_response, _):
    query = parse_qs(environ["QUERY_STRING"])
    try:
        assert query["rel"] == [OIC_ISSUER]
        resource = query["resource"][0]
    except KeyError:
        resp = BadRequest("Missing parameter in request")
    else:
        wf = WebFinger()
        resp = Response(wf.response(subject=resource, base=OAS.baseurl))
    return resp(environ, start_response)


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
from oic.oic.provider import RegistrationEndpoint

ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
    UserinfoEndpoint(userinfo),
    RegistrationEndpoint(registration),
    EndSessionEndpoint(endsession),
]

URLS = [
    (r'^.well-known/openid-configuration', op_info),
    (r'^.well-known/simple-web-discovery', swd_info),
    (r'^.well-known/host-meta.json', meta_info),
    (r'^.well-known/webfinger', webfinger),
#    (r'^.well-known/webfinger', webfinger),
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
    from cherrypy.wsgiserver import ssl_pyopenssl

    from oic.utils.sdb import SessionDB

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # Client data base
    cdb = shelve.open("client_db", writeback=True)

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    config.issuer = config.issuer % args.port
    config.SERVICE_URL = config.SERVICE_URL % args.port

    ac = AuthnBroker()

    saml_authn = SAMLAuthnMethod(None, LOOKUP, config.SAML, config.SP_CONFIG, config.issuer,
                                    "%s/authorization" % config.issuer,
                                    userinfo=config.USERINFO)
    ac.add("", saml_authn,"","")


    end_points = config.AUTHENTICATION["UserPassword"]["END_POINTS"]
    full_end_point_paths = ["%s/%s" % (config.issuer, ep) for ep in end_points]
    username_password_authn = UsernamePasswordMako(None, "login.mako", LOOKUP, PASSWD,"%s/authorization" % config.issuer,
                                        None, full_end_point_paths)
    ac.add("", username_password_authn,"","")

    for authkey, value in config.AUTHENTICATION.items():
        authn = None

        if "UserPassword" == authkey:
            PASSWORD_END_POINT_INDEX = 0
            end_point = config.AUTHENTICATION[authkey]["END_POINTS"][PASSWORD_END_POINT_INDEX]
            authn = AuthnIndexedEndpointWrapper(username_password_authn, PASSWORD_END_POINT_INDEX)
            URLS.append((r'^' + end_point, make_auth_verify(authn.verify)))

        # if "JavascriptLogin" == authkey:
        #     authn = JavascriptFormMako(None, "javascript_login.mako", LOOKUP, PASSWD,
        #                      "%s/authorization" % config.issuer)

        if "SAML" == authkey:
            SAML_END_POINT_INDEX = 0
            end_point = config.AUTHENTICATION[authkey]["END_POINTS"][SAML_END_POINT_INDEX]
            end_point_indexes = {BINDING_HTTP_REDIRECT: 2, BINDING_HTTP_POST: 4, "disco_end_point_index": 1}
            authn = AuthnIndexedEndpointWrapper(saml_authn, end_point_indexes)
            URLS.append((r'^' + end_point, make_auth_verify(authn.verify)))

        if "SamlPass" == authkey:
            PASSWORD_END_POINT_INDEX = 1
            SAML_END_POINT_INDEX = 1
            password_end_point = config.AUTHENTICATION["UserPassword"]["END_POINTS"][PASSWORD_END_POINT_INDEX]
            saml_endpoint = config.AUTHENTICATION["SAML"]["END_POINTS"][SAML_END_POINT_INDEX]

            end_point_indexes = {BINDING_HTTP_REDIRECT: 1, BINDING_HTTP_POST: 3, "disco_end_point_index": 0}
            multi_saml = AuthnIndexedEndpointWrapper(saml_authn, end_point_indexes)
            multi_password = AuthnIndexedEndpointWrapper(username_password_authn, PASSWORD_END_POINT_INDEX)

            auth_modules = [(multi_saml, r'^' + saml_endpoint), (multi_password, r'^' + password_end_point)]
            authn = setup_multi_auth(ac, URLS, auth_modules)

        if authn is not None:
            ac.add(config.AUTHENTICATION[authkey]["ACR"], authn,
                   config.AUTHENTICATION[authkey]["WEIGHT"],
                   "")

    # dealing with authorization
    authz = AuthzHandling()

    kwargs = {
        "template_lookup": LOOKUP,
        "template": {"form_post": "form_response.mako"},
        #"template_args": {"form_post": {"action": "form_post"}}
    }

    # Should I care about verifying the certificates used other entities
    if args.insecure:
        kwargs["verify_ssl"] = False
    else:
        kwargs["verify_ssl"] = True

    OAS = Provider(config.issuer, SessionDB(), cdb, ac, None, authz,
                   verify_client, config.SYM_KEY, **kwargs)

    for authn in ac:
        authn.srv = OAS

    if config.USERINFO == "SIMPLE":
        # User info is a simple dictionary in this case statically defined in
        # the configuration file
        OAS.userinfo = UserInfo(config.USERDB)
    elif config.USERINFO == "SAML":
        OAS.userinfo = UserInfo(config.SAML)
    elif config.USERINFO == "AA":
        OAS.userinfo = AaUserInfo(config.SP_CONFIG, config.issuer, config.SAML)
    else:
        raise Exception("Unsupported userinfo source")

    try:
        OAS.cookie_ttl = config.COOKIETTL
    except AttributeError:
        pass

    try:
        OAS.cookie_name = config.COOKIENAME
    except AttributeError:
        pass

    #print URLS
    if args.debug:
        OAS.debug = True

    # All endpoints the OpenID Connect Provider should answer on
    add_endpoints(ENDPOINTS)
    OAS.endpoints = ENDPOINTS

    if args.port == 80:
        OAS.baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        OAS.baseurl = "%s:%d" % (config.baseurl, args.port)

    if not OAS.baseurl.endswith("/"):
        OAS.baseurl += "/"

    # Add own keys for signing/encrypting JWTs
    try:
        OAS.keyjar[""] = []
        kbl = []
        for typ, info in config.keys.items():
            typ = typ.upper()
            LOGGER.info("OC server key init: %s, %s" % (typ, info))
            kb = KeyBundle(source="file://%s" % info["key"], fileformat="der",
                           keytype=typ)
            OAS.keyjar.add_kb("", kb)
            kbl.append(kb)

        try:
            new_name = "static/jwks.json"
            dump_jwks(kbl, new_name)
            OAS.jwks_uri.append("%s%s" % (OAS.baseurl, new_name))
        except KeyError:
            pass

        for b in OAS.keyjar[""]:
            LOGGER.info("OC3 server keys: %s" % b)
    except Exception, err:
        LOGGER.error("Key setup failed: %s" % err)
        OAS.key_setup("static", sig={"format": "jwk", "alg": "rsa"})

    # Setup the web server
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)

    if config.SERVICE_URL.startswith("https"):
        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            config.SERVER_CERT, config.SERVER_KEY, config.CERT_CHAIN)

    LOGGER.info("OC server starting listening on port:%s" % args.port)
    print "OC server starting listening on port:%s" % args.port
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
