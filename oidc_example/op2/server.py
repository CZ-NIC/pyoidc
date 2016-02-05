#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import sys
import os
import traceback

from six.moves.urllib.parse import parse_qs
from jwkest import as_unicode
from oic.utils import shelve_wrapper
from oic.utils.authn.javascript_login import JavascriptFormMako

from oic.utils.authn.client import verify_client
from oic.utils.authn.multi_auth import setup_multi_auth
from oic.utils.authn.multi_auth import AuthnIndexedEndpointWrapper
from oic.utils.authn.saml import SAMLAuthnMethod
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import keyjar_init
from oic.utils.userinfo import UserInfo
from oic.utils.userinfo.aa_info import AaUserInfo
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.authn_context import make_auth_verify

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

JWKS_FILE_NAME = "static/jwks.json"

# ----------------------------------------------------------------------------


# noinspection PyUnusedLocal
def safe(environ, start_response, logger):
    _oas = environ["oic.oas"]
    _srv = _oas.server
    _log_info = _oas.logger.info

    _log_info("- safe -")
    # _log_info("env: %s" % environ)
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


# noinspection PyUnusedLocal
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
def static(environ, start_response, path):
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


def check_session_iframe(environ, start_response, logger):
    return static(environ, start_response, "htdocs/op_session_iframe.html")


# ----------------------------------------------------------------------------


def key_rollover(environ, start_response, _):
    # expects a post containing the necessary information
    _txt = get_post(environ)
    _jwks = json.loads(_txt)
    logger.info("Key rollover to")
    OAS.do_key_rollover(_jwks, "key_%d_%%d" % int(time.time()))
    # Dump to file
    f = open(JWKS_FILE_NAME, "w")
    f.write(json.dumps(OAS.keyjar.export_jwks()))
    f.close()
    resp = Response("OK")
    return resp(environ, start_response)


def clear_keys(environ, start_response, _):
    OAS.remove_inactive_keys()
    resp = Response("OK")
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
    (r'^keyrollover', key_rollover),
    (r'^clearkeys', clear_keys),
    (r'^check_session', check_session_iframe)
    #    (r'tracelog', trace_log),
]


def add_endpoints(extra):
    global URLS

    for endp in extra:
        URLS.append(("^%s" % endp.etype, endp.func))

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
        return static(environ, start_response, "static/robots.txt")

    environ["oic.oas"] = OAS

    if path.startswith("static/"):
        return static(environ, start_response, path)

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
            except Exception as err:
                print("%s" % err)
                message = traceback.format_exception(*sys.exc_info())
                print(message)
                logger.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    LOGGER.debug("unknown side: %s" % path)
    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

if __name__ == '__main__':
    import argparse
    import importlib

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

    from oic.utils.sdb import SessionDB

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(
        '-c', dest='capabilities',
        help="A file containing a JSON representation of the capabilities")
    parser.add_argument('-b', dest='baseurl', help="base url of the OP")
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # Client data base
    cdb = shelve_wrapper.open("client_db")

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    if args.baseurl:
        config.baseurl = args.baseurl

    config.issuer = config.issuer.format(base=config.baseurl, port=args.port)
    config.SERVICE_URL = config.SERVICE_URL.format(issuer=config.issuer)

    ac = AuthnBroker()

    saml_authn = None

    end_points = config.AUTHENTICATION["UserPassword"]["END_POINTS"]
    full_end_point_paths = ["%s%s" % (config.issuer, ep) for ep in end_points]
    username_password_authn = UsernamePasswordMako(
        None, "login.mako", LOOKUP, PASSWD, "%sauthorization" % config.issuer,
        None, full_end_point_paths)

    for authkey, value in config.AUTHENTICATION.items():
        authn = None

        if "UserPassword" == authkey:
            PASSWORD_END_POINT_INDEX = 0
            end_point = config.AUTHENTICATION[authkey]["END_POINTS"][
                PASSWORD_END_POINT_INDEX]
            authn = AuthnIndexedEndpointWrapper(username_password_authn,
                                                PASSWORD_END_POINT_INDEX)
            URLS.append((r'^' + end_point, make_auth_verify(authn.verify)))

        # Ensure javascript_login_authn to be defined
        try:
            javascript_login_authn
        except NameError:
            javascript_login_authn = None

        if "JavascriptLogin" == authkey:
            if not javascript_login_authn:
                end_points = config.AUTHENTICATION[
                    "JavascriptLogin"]["END_POINTS"]
                full_end_point_paths = [
                    "%s/%s" % (config.issuer, ep) for ep in end_points]
                javascript_login_authn = JavascriptFormMako(
                    None, "javascript_login.mako", LOOKUP, PASSWD,
                    "%s/authorization" % config.issuer, None,
                    full_end_point_paths)
            ac.add("", javascript_login_authn, "", "")
            JAVASCRIPT_END_POINT_INDEX = 0
            end_point = config.AUTHENTICATION[authkey]["END_POINTS"][
                JAVASCRIPT_END_POINT_INDEX]
            authn = AuthnIndexedEndpointWrapper(javascript_login_authn,
                                                JAVASCRIPT_END_POINT_INDEX)
            URLS.append((r'^' + end_point, make_auth_verify(authn.verify)))

        if "SAML" == authkey:
            from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST

            if not saml_authn:
                saml_authn = SAMLAuthnMethod(
                    None, LOOKUP, config.SAML, config.SP_CONFIG, config.issuer,
                    "%s/authorization" % config.issuer,
                    userinfo=config.USERINFO)
            ac.add("", saml_authn, "", "")
            SAML_END_POINT_INDEX = 0
            end_point = config.AUTHENTICATION[authkey]["END_POINTS"][
                SAML_END_POINT_INDEX]
            end_point_indexes = {BINDING_HTTP_REDIRECT: 0, BINDING_HTTP_POST: 0,
                                 "disco_end_point_index": 0}
            authn = AuthnIndexedEndpointWrapper(saml_authn, end_point_indexes)
            URLS.append((r'^' + end_point, make_auth_verify(authn.verify)))

        if "SamlPass" == authkey:
            from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST

            if not saml_authn:
                saml_authn = SAMLAuthnMethod(
                    None, LOOKUP, config.SAML, config.SP_CONFIG, config.issuer,
                    "%s/authorization" % config.issuer,
                    userinfo=config.USERINFO)
            PASSWORD_END_POINT_INDEX = 1
            SAML_END_POINT_INDEX = 1
            password_end_point = config.AUTHENTICATION["UserPassword"][
                "END_POINTS"][PASSWORD_END_POINT_INDEX]
            saml_endpoint = config.AUTHENTICATION["SAML"]["END_POINTS"][
                SAML_END_POINT_INDEX]

            end_point_indexes = {BINDING_HTTP_REDIRECT: 1, BINDING_HTTP_POST: 1,
                                 "disco_end_point_index": 1}
            multi_saml = AuthnIndexedEndpointWrapper(saml_authn,
                                                     end_point_indexes)
            multi_password = AuthnIndexedEndpointWrapper(
                username_password_authn, PASSWORD_END_POINT_INDEX)

            auth_modules = [(multi_saml, r'^' + saml_endpoint),
                            (multi_password, r'^' + password_end_point)]
            authn = setup_multi_auth(ac, URLS, auth_modules)

        if "JavascriptPass" == authkey:
            if not javascript_login_authn:
                end_points = config.AUTHENTICATION[
                    "JavascriptLogin"]["END_POINTS"]
                full_end_point_paths = [
                    "%s/%s" % (config.issuer, ep) for ep in end_points]
                javascript_login_authn = JavascriptFormMako(
                    None, "javascript_login.mako", LOOKUP, PASSWD,
                    "%s/authorization" % config.issuer, None,
                    full_end_point_paths)

            PASSWORD_END_POINT_INDEX = 2
            JAVASCRIPT_POINT_INDEX = 1

            password_end_point = config.AUTHENTICATION["UserPassword"][
                "END_POINTS"][PASSWORD_END_POINT_INDEX]
            javascript_end_point = config.AUTHENTICATION["JavascriptLogin"][
                "END_POINTS"][JAVASCRIPT_POINT_INDEX]

            multi_password = AuthnIndexedEndpointWrapper(
                username_password_authn, PASSWORD_END_POINT_INDEX)
            multi_javascript = AuthnIndexedEndpointWrapper(
                javascript_login_authn, JAVASCRIPT_POINT_INDEX)

            auth_modules = [(multi_password, r'^' + password_end_point),
                            (multi_javascript, r'^' + javascript_end_point)]
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

    # Should I care about verifying the certificates used by other entities
    if args.insecure:
        kwargs["verify_ssl"] = False
    else:
        kwargs["verify_ssl"] = True

    if args.capabilities:
        kwargs["capabilities"] = json.loads(open(args.capabilities).read())
    else:
        pass

    OAS = Provider(config.issuer, SessionDB(config.baseurl), cdb, ac, None,
                   authz, verify_client, config.SYM_KEY, **kwargs)
    OAS.baseurl = config.issuer

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

    try:
        jwks = keyjar_init(OAS, config.keys, kid_template="op%d")
    except Exception as err:
        LOGGER.error("Key setup failed: %s" % err)
        OAS.key_setup("static", sig={"format": "jwk", "alg": "rsa"})
    else:
        jwks_file_name = JWKS_FILE_NAME
        f = open(jwks_file_name, "w")

        for key in jwks["keys"]:
            for k in key.keys():
                key[k] = as_unicode(key[k])

        f.write(json.dumps(jwks))
        f.close()
        OAS.jwks_uri = "%s%s" % (OAS.baseurl, jwks_file_name)

    for b in OAS.keyjar[""]:
        LOGGER.info("OC3 server keys: %s" % b)

    # Setup the web server
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)

    https = ""
    if config.SERVICE_URL.startswith("https"):
        https = "using HTTPS"
        # SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
        #     config.SERVER_CERT, config.SERVER_KEY, config.CERT_CHAIN)
        SRV.ssl_adapter = BuiltinSSLAdapter(config.SERVER_CERT, config.SERVER_KEY, config.CERT_CHAIN)

    LOGGER.info("OC server starting listening on port:%s %s" % (args.port,
                                                                https))
    print ("OC server starting listening on port:%s %s" % (args.port, https))
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
