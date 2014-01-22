#!/usr/bin/env python
"""
A very simple OAuth2 AS
"""
import logging
import re
import sys
import traceback

from authn_setup import authn_setup
from oic.oauth2.provider import Provider
from oic.oauth2.provider import AuthorizationEndpoint
from oic.oauth2.provider import TokenEndpoint
from oic.utils.authn.client import verify_client
from oic.utils.authz import Implicit
from oic.utils.http_util import wsgi_wrapper, NotFound, ServiceError

__author__ = 'roland'

# ============================================================================
# First define how logging is supposed to be done
# ============================================================================

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oauth2_as.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

# ============================================================================
# Endpoint functions
# ============================================================================


#noinspection PyUnusedLocal
def token(environ, start_response):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.token_endpoint)


#noinspection PyUnusedLocal
def authorization(environ, start_response):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.authorization_endpoint)


ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
]


#noinspection PyUnusedLocal
def verify(environ, start_response):
    _oas = environ["oic.oas"]
    return wsgi_wrapper(environ, start_response, _oas.verify_endpoint)

# ---------------------------------------------------------------------------
# For static files


def static(environ, start_response, path):
    LOGGER.info("[static]sending: %s" % (path,))

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

URLS = [
    (r'^verify', verify),
]

for endp in ENDPOINTS:
    URLS.append(("^%s" % endp.etype, endp))

# ============================================================================
# The main web server function
# ============================================================================


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

    LOGGER.info("path: %s" % path)
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

            LOGGER.debug("callback: %s" % callback)
            try:
                return callback(environ, start_response)
            except Exception, err:
                print >> sys.stderr, "%s" % err
                message = traceback.format_exception(*sys.exc_info())
                print >> sys.stderr, message
                LOGGER.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    LOGGER.debug("unknown side: %s" % path)
    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ============================================================================
# Below is what's needed to start the server
# ============================================================================

START_MESG = "OAuth2 server starting listening on port:%s at %s"

if __name__ == "__main__":
    import argparse
    import shelve
    import importlib

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_pyopenssl

    # This is where session information is stored
    # This serve is stateful.
    from oic.utils.sdb import SessionDB

    # Parse the command arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    # Who it should report as being responsible for the authentication
    parser.add_argument('-A', dest='authn_as', default="")
    parser.add_argument('-c', dest='conf_path')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # Client data base
    cdb = shelve.open("client_db", writeback=True)

    # Load the configuration file, which must be a python file
    # The default; first look for it in the directory from where this program
    # is run.
    sys.path.insert(0, ".")
    # If a specific configuration directory is specified look there first
    if args.conf_path:
        sys.path.insert(0, args.conf_path)
    config = importlib.import_module(args.config)
    # Add port number information
    config.issuer = config.issuer % args.port
    config.SERVICE_URL = config.SERVICE_URL % args.port

    for cnf in config.AUTHN_METHOD.values():
        try:
            cnf["config"]["return_to"] = cnf["config"]["return_to"] % args.port
        except KeyError:
            pass

    # Initiate the authentication broker. This is the service that
    # chooses which authentication method that is to be used.

    broker = authn_setup(config)

    # dealing with authorization, this is just everything goes.
    authz = Implicit()

    # Initiate the OAuth2 provider instance
    OAS = Provider(config.issuer, SessionDB(), cdb, broker, authz,
                   client_authn=verify_client, symkey=config.SYM_KEY)

    # set some parameters
    try:
        OAS.cookie_ttl = config.COOKIETTL
    except AttributeError:
        pass

    try:
        OAS.cookie_name = config.COOKIENAME
    except AttributeError:
        pass

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)
        OAS.debug = True

    if args.authn_as:
        OAS.authn_as = args.authn_as

    OAS.endpoints = ENDPOINTS

    if args.port == 80:
        OAS.baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        OAS.baseurl = "%s:%d" % (config.baseurl, args.port)

    if not OAS.baseurl.endswith("/"):
        OAS.baseurl += "/"

    LOGGER.debug("URLS: '%s" % (URLS,))

    # Initiate the web server
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)
    SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(config.SERVER_CERT,
                                                     config.SERVER_KEY,
                                                     config.CERT_CHAIN)

    LOGGER.info(START_MESG % (args.port, config.HOST))
    print START_MESG % (args.port, config.HOST)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
