#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import re

from oic.oic.claims_provider import UserClaimsEndpoint
from oic.oic.claims_provider import UserClaimsInfoEndpoint
from oic.oic.message import OpenIDSchema
#from oic.oic.provider import CheckIDEndpoint
from oic.oic.provider import RegistrationEndpoint
from oic.oic.provider import UserinfoEndpoint
from oic.utils.http_util import *
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.userinfo import UserInfo

__author__ = 'rohe0002'



LOGGER = logging.getLogger("")
hdlr = logging.FileHandler('oc3cp.log')
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

# ----------------------------------------------------------------------------


#noinspection PyUnusedLocal
def verify_client(environ, req, cdb):
    identity = req["client_id"]
    secret = req["client_secret"]
    if identity:
        if identity in cdb:
            if cdb[identity]["client_secret"] == secret:
                return True

    return False


#noinspection PyUnusedLocal
def user_info(oicsrv, userdb, sub, client_id="", user_info_claims=None):
    #print >> sys.stderr, "claims: %s" % user_info_claims

    identity = userdb[sub]
    if user_info_claims:
        result = {}
        claims = user_info_claims["claims"]
        for key, restr in claims.items():
            try:
                result[key] = identity[key]
            except KeyError:
                if restr == {"essential": True}:
                    raise Exception("Missing property '%s'" % key)
    else:
        result = identity

    return OpenIDSchema(**result)


USER2MODE = {"diana": "aggregate",
             "upper": "distribute",
             "babs": "aggregate"}


#noinspection PyUnusedLocal
def claims_mode(info, uid):
    if USER2MODE[uid] == "aggregate":
        return True
    else:
        return False

FUNCTIONS = {
    "verify_client": verify_client,
    "userinfo": user_info,
    "claims_mode": claims_mode
}

# ----------------------------------------------------------------------------


#noinspection PyUnusedLocal
def userinfo(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.userinfo_endpoint(environ, start_response, LOGGER)


#noinspection PyUnusedLocal
def check_id(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.check_id_endpoint(environ, start_response, LOGGER)


#noinspection PyUnusedLocal
def op_info(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.providerinfo_endpoint(environ, start_response, LOGGER)


#noinspection PyUnusedLocal
def userclaims(environ, start_response, handle):
    _oas = environ["oic.oas"]

    LOGGER.info("claims_endpoint")
    return _oas.claims_endpoint(environ, start_response, LOGGER)


#noinspection PyUnusedLocal
def registration(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.registration_endpoint(environ, start_response)


#noinspection PyUnusedLocal
def userclaimsinfo(environ, start_response, handle):
    _oas = environ["oic.oas"]

    LOGGER.info("claims_info_endpoint")
    return _oas.claims_info_endpoint(environ, start_response, LOGGER)

# ----------------------------------------------------------------------------


def static(environ, start_response, path):

    _txt = open(path).read()
    if "x509" in path:
        content = "text/xml"
    else:
        content = "application/json"

    resp = Response(_txt, content=content)
    return resp(environ, start_response)

# ----------------------------------------------------------------------------


ENDPOINTS = [
    UserinfoEndpoint(userinfo),
    #CheckIDEndpoint(check_id),
    RegistrationEndpoint(registration),
    UserClaimsEndpoint(userclaims),
    UserClaimsInfoEndpoint(userclaimsinfo)
]

URLS = [
    (r'^.well-known/openid-configuration', op_info)
]

for endp in ENDPOINTS:
    URLS.append(("^%s$" % endp.etype, endp))


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
    kaka = environ.get("HTTP_COOKIE", '')

    if kaka:
        handle = parse_cookie(OAS.name, OAS.seed, kaka)
        LOGGER.debug("Cookie: %s" % (kaka,))
    else:
        handle = ""

    environ["oic.oas"] = OAS

    LOGGER.info("path: %s" % path)
    if path in OAS.cert or path in OAS.jwk:
        return static(environ, start_response, path)
    else:
        for regex, callback in URLS:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['oic.url_args'] = match.groups()[0]
                except IndexError:
                    environ['oic.url_args'] = path
                return callback(environ, start_response, handle)

    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

USERDB = {
    "diana": {
        "geolocation": {"longitude": 20.3076, "latitude": 63.8206},
    },
    "upper": {
        "geolocation": {"longitude": 17.0393, "latitude": 59.65075},
    },
    "babs": {
        "geolocation": {"longitude": 4.8890, "latitude": 52.3673},
    }
}


SERVER_DB = {}

if __name__ == '__main__':
    import argparse
    import json

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_builtin

    from oic.oic.claims_provider import ClaimsServer
    from oic.utils.sdb import create_session_db

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=8093, type=int)
    parser.add_argument(dest="config")
    args = parser.parse_args()

    cdb = json.loads(open("claims_client.json").read())
    userinfo = UserInfo(USERDB)

    # in memory session storage

    config = json.loads(open(args.config).read())
    sdb = create_session_db(config["issuer"],
                            config["SESSION_KEY"],
                            password="changethis")
    OAS = ClaimsServer(config["issuer"], sdb, cdb, userinfo,
                       verify_client)

    if "keys" in config:
        for typ, info in config["keys"].items():
            OAS.keyjar.add_kb("", keybundle_from_local_file(info["key"], "rsa",
                                                            ["ver", "sig"]))
            try:
                OAS.jwks_uri.append(info["jwk"])
            except KeyError:
                pass

    #print URLS
    if args.debug:
        OAS.debug = True

    OAS.endp = ENDPOINTS
    if args.port == 80:
        OAS.baseurl = config["baseurl"]
    else:
        if config["baseurl"].endswith("/"):
            config["baseurl"] = config["baseurl"][:-1]
        OAS.baseurl = "%s:%d" % (config["baseurl"], args.port)

    if not OAS.baseurl.endswith("/"):
        OAS.baseurl += "/"

    OAS.claims_userinfo_endpoint = "%s%s" % (
        OAS.baseurl, UserClaimsInfoEndpoint.etype)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)
    SRV.ssl_adapter = ssl_builtin.BuiltinSSLAdapter("certs/server.crt",
                                                    "certs/server.key")

    LOGGER.info("Starting server")
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
