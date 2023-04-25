#!/usr/bin/env python
"""
A very simple OAuth2 AS
"""
import json
import logging
import os
import re
import sys
import traceback

import cherrypy
from authn_setup import authn_setup
from requests.packages import urllib3

from oic.extension.provider import IntrospectionEndpoint
from oic.extension.provider import Provider
from oic.extension.provider import RevocationEndpoint
from oic.extension.token import JWTToken
from oic.oauth2.provider import AuthorizationEndpoint
from oic.oauth2.provider import TokenEndpoint
from oic.oic.provider import RegistrationEndpoint
from oic.utils.authn.client import verify_client
from oic.utils.authz import Implicit
from oic.utils.http_util import NotFound
from oic.utils.http_util import ServiceError
from oic.utils.http_util import wsgi_wrapper
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import keyjar_init

urllib3.disable_warnings()

__author__ = "roland"

# ============================================================================
# First define how logging is supposed to be done
# ============================================================================

LOGGER = logging.getLogger("")
LOGFILE_NAME = "oauth2_as.log"
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

JWKS_FILE_NAME = os.path.join(os.path.dirname(__file__), "static/jwks.json")


# ---------------------------------------------------------------------------
# For static files


def static(environ, start_response, path):
    LOGGER.info("[static]sending: %s" % (path,))

    try:
        with open(path, "rb") as fd:
            content = fd.read()
        if path.endswith(".ico"):
            start_response("200 OK", [("Content-Type", "image/x-icon")])
        elif path.endswith(".html"):
            start_response("200 OK", [("Content-Type", "text/html")])
        elif path.endswith(".json"):
            start_response("200 OK", [("Content-Type", "application/json")])
        elif path.endswith(".txt"):
            start_response("200 OK", [("Content-Type", "text/plain")])
        elif path.endswith(".css"):
            start_response("200 OK", [("Content-Type", "text/css")])
        else:
            start_response("200 OK", [("Content-Type", "text/xml")])
        return [content]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)


# ============================================================================
# The main web server function
# ============================================================================


class Application(object):
    def __init__(self, oas):
        self.oas = oas

        self.endpoints = [
            AuthorizationEndpoint(self.authorization),
            TokenEndpoint(self.token),
            RegistrationEndpoint(self.registration),
            IntrospectionEndpoint(self.introspection),
            RevocationEndpoint(self.revocation),
        ]

        self.urls = [
            (r"^verify", self.verify),
            (r".well-known/openid-configuration", self.config),
        ]

        for endp in self.endpoints:
            self.urls.append(("^%s" % endp.etype, endp))

    # noinspection PyUnusedLocal
    def verify(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.oas.verify_endpoint)

    # noinspection PyUnusedLocal
    def token(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.oas.token_endpoint)

    # noinspection PyUnusedLocal
    def authorization(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.oas.authorization_endpoint)

    # noinspection PyUnusedLocal
    def config(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.oas.providerinfo_endpoint)

    # noinspection PyUnusedLocal
    def registration(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.oas.registration_endpoint)

    # noinspection PyUnusedLocal
    def introspection(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.oas.introspection_endpoint)

    # noinspection PyUnusedLocal
    def revocation(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.oas.revocation_endpoint)

    def application(self, environ, start_response):
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

        path = environ.get("PATH_INFO", "").lstrip("/")

        LOGGER.info("path: %s" % path)
        if path == "robots.txt":
            return static(environ, start_response, "static/robots.txt")

        if path.startswith("static/"):
            return static(environ, start_response, path)

        for regex, callback in self.urls:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ["oic.url_args"] = match.groups()[0]
                except IndexError:
                    environ["oic.url_args"] = path

                LOGGER.debug("callback: %s" % callback)
                try:
                    return callback(environ, start_response)
                except Exception as err:
                    print("{}".format(err), file=sys.stderr)
                    message = traceback.format_exception(*sys.exc_info())
                    print(message, file=sys.stderr)
                    LOGGER.exception("%s" % err)
                    resp = ServiceError("%s" % err)
                    return resp(environ, start_response)

        LOGGER.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")
        return resp(environ, start_response)


# ============================================================================
# Below is what's needed to start the server
# ============================================================================

START_MESG = "OAuth2 server starting listening on port:{} at {}"

if __name__ == "__main__":
    import argparse
    import importlib
    import shelve  # nosec

    # This is where session information is stored
    # This serve is stateful.
    from oic import rndstr
    from oic.utils.sdb import DefaultToken
    from oic.utils.sdb import SessionDB

    # Parse the command arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="debug", action="store_true")
    parser.add_argument("-k", dest="insecure", action="store_true")
    parser.add_argument("-p", dest="port", default=80, type=int)
    # Who it should report as being responsible for the authentication
    parser.add_argument("-A", dest="authn_as", default="")
    parser.add_argument("-c", dest="conf_path")
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # Client data base
    cdb = shelve.open("client_db", writeback=True)  # nosec

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

    try:
        capabilities = config.CAPABILITIES
    except AttributeError:
        capabilities = None

    if args.insecure:
        kwargs = {"verify_ssl": False}
    else:
        kwargs = {}

    # Initiate the Provider
    oas = Provider(
        config.issuer,
        None,
        cdb,
        broker,
        authz,
        baseurl=config.issuer,
        client_authn=verify_client,
        symkey=config.SYM_KEY,
        hostname=config.HOST,
        capabilities=capabilities,
        behavior=config.BEHAVIOR,
        **kwargs
    )

    try:
        jwks = keyjar_init(oas, config.keys, kid_template="op%d")
    except Exception as err:
        LOGGER.error("Key setup failed: {}".format(err))
        print("Key setup failed: {}".format(err))
        exit()
    else:
        jwks_file_name = JWKS_FILE_NAME

        with open(jwks_file_name, "w") as f:
            for key in jwks["keys"]:
                for k in key.keys():
                    key[k] = key[k]
            f.write(json.dumps(jwks))

        oas.jwks_uri = "{}/{}".format(oas.baseurl, jwks_file_name)

    # Initiate the SessionDB
    _code = DefaultToken(rndstr(32), rndstr(32), typ="A", lifetime=600)
    _token = JWTToken(
        "T",
        oas.keyjar,
        {"code": 3600, "token": 900},
        iss=config.issuer,
        sign_alg="RS256",
    )
    _refresh_token = JWTToken(
        "R",
        oas.keyjar,
        {"": 86400},
        iss=config.issuer,
        sign_alg="RS256",
        token_storage={},
    )
    oas.sdb = SessionDB(
        config.SERVICE_URL,
        db={},
        code_factory=_code,
        token_factory=_token,
        refresh_token_factory=_refresh_token,
    )

    # set some parameters
    try:
        oas.cookie_ttl = config.COOKIETTL
    except AttributeError:
        pass

    try:
        oas.cookie_name = config.COOKIENAME
    except AttributeError:
        pass

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)
        oas.debug = True

    if args.authn_as:
        oas.authn_as = args.authn_as

    if args.port == 80:
        oas.baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        oas.baseurl = "%s:%d" % (config.baseurl, args.port)

    if not oas.baseurl.endswith("/"):
        oas.baseurl += "/"

    # load extra keys
    try:
        extern = config.TRUSTED_REGISTRATION_ENTITIES
    except AttributeError:
        pass
    else:
        for ent in extern:
            iss = ent["iss"]
            kb = KeyBundle()
            kb.imp_jwks = json.load(open(ent["jwks"]))
            kb.do_keys(kb.imp_jwks["keys"])
            oas.keyjar.add_kb(iss, kb)

    # Initiate the web server
    cherrypy.config.update({"server.socket_port": args.port})

    _app = Application(oas)
    cherrypy.tree.graft(_app.application, "/")

    https = ""
    if config.SERVICE_URL.startswith("https"):
        https = " using HTTPS"
        cherrypy.config.update(
            {
                "cherrypy.server.ssl_certificate": config.SERVER_CERT,
                "cherrypy.server.ssl_private_key": config.SERVER_KEY,
            }
        )

    _info = START_MESG.format(args.port, config.HOST)
    if https:
        _info += https
    LOGGER.info(_info)
    print(_info)
    try:
        cherrypy.engine.start()
    except KeyboardInterrupt:
        pass
