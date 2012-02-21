#!/usr/bin/env python
# -*- coding: utf-8 -*-
#import sys

__author__ = 'rohe0002'

import logging
import re

from oic.utils.http_util import *
from oic.oic.message import OpenIDSchema
#from oic.oic.server import AuthnFailure

LOGGER = logging.getLogger("oicServer")
hdlr = logging.FileHandler('oc3cp.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

# ----------------------------------------------------------------------------
#noinspection PyUnusedLocal
def verify_client(environ, req, cdb):
    identity = req.client_id
    secret = req.client_secret
    if identity:
        if identity in cdb:
            if cdb[identity]["client_secret"] == secret:
                return True

    return False

#noinspection PyUnusedLocal
def user_info(userdb, user_id, client_id="", user_info_claims=None):
    #print >> sys.stderr, "claims: %s" % user_info_claims

    identity = userdb[user_id]
    if user_info_claims:
        result = {}
        for claim in user_info_claims.claims:
            for key, restr in claim.items():
                try:
                    result[key] = identity[key]
                except KeyError:
                    if restr == {"optional": True}:
                        pass
                    else:
                        raise Exception("Missing property '%s'" % key)
    else:
        result = identity

    return OpenIDSchema(**result)

FUNCTIONS = {
    "verify_client": verify_client,
    "userinfo": user_info,
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
def claims(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.claims_endpoint(environ, start_response, LOGGER)

#noinspection PyUnusedLocal
def registration(environ, start_response, handle):
    _oas = environ["oic.oas"]

    return _oas.registration_endpoint(environ, start_response, LOGGER)

# ----------------------------------------------------------------------------

def static(environ, start_response, path):
    _log_info = environ["oic.logger"].info

    _txt = open(path).read()
    if "x509" in path:
        content = "text/xml"
    else:
        content = "application/json"

    _log_info(_txt)

    resp = Response(_txt, content=content)
    return resp(environ, start_response)

# ----------------------------------------------------------------------------

from oic.oic.server import UserinfoEndpoint
from oic.oic.server import CheckIDEndpoint
from oic.oic.server import RegistrationEndpoint

ENDPOINTS = [
    UserinfoEndpoint(userinfo),
    CheckIDEndpoint(check_id),
    RegistrationEndpoint(registration)
]

URLS = [
    (r'^.well-known/openid-configuration', op_info),
    ("claims", claims)
]

for endp in ENDPOINTS:
    URLS.append(("^%s" % endp.type, endp))

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
    global LOGGER

    #user = environ.get("REMOTE_USER", "")
    path = environ.get('PATH_INFO', '').lstrip('/')
    kaka = environ.get("HTTP_COOKIE", '')

    if kaka:
        handle = parse_cookie(OAS.name, OAS.seed, kaka)
        if OAS.debug:
            OAS.logger.debug("Cookie: %s" % (kaka,))
    else:
        handle = ""

    environ["oic.oas"] = OAS
    environ["oic.logger"] = LOGGER

    LOGGER.info("path: %s" % path)
    if path in OAS.cert or OAS.jwk:
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
    "diana":{
        "birthdate": "02/14/2012",
        "gender": "female",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
    }
}

SERVER_DB = {

}

if __name__ == '__main__':
    import argparse
    import json
    from oic.utils import jwt

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_builtin

    from oic.oic.claims_provider import ClaimsServer
    from oic.utils.sdb import SessionDB

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=8089, type=int)
    parser.add_argument(dest="config")
    args = parser.parse_args()

    cdb = json.loads(open("claims_client.json").read())

    # in memory session storage

    config = json.loads(open(args.config).read())
    OAS = ClaimsServer(config["issuer"], SessionDB(), cdb, FUNCTIONS,
                       USERDB)

    if "keys" in config:
        for type, info in config["keys"].items():
            OAS.keystore.add_key(jwt.rsa_load(info["key"]), type, "sign")
            OAS.cert.append(info["cert"])

    #print URLS
    if args.debug:
        OAS.debug = True

    OAS.endpoints = ENDPOINTS
    if args.port == 80:
        OAS.baseurl = config["baseurl"]
    else:
        if config["baseurl"].endswith("/"):
            config["baseurl"] = config["baseurl"][:-1]
        OAS.baseurl = "%s:%d" % (config["baseurl"], args.port)

    if not OAS.baseurl.endswith("/"):
        OAS.baseurl += "/"

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), application)
    #SRV.ssl_adapter = ssl_builtin.BuiltinSSLAdapter("certs/server.crt",
    #                                                "certs/server.key")
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
