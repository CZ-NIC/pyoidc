#!/usr/bin/env python
# -*- coding: utf-8 -*-
#import sys

__author__ = 'rohe0002'

import logging
import re

from oic.utils.http_util import *
#from oic.oic.message import OpenIDSchema
#from oic.oic.server import AuthnFailure

LOGGER = logging.getLogger("oicServer")
hdlr = logging.FileHandler('oc3.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

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

# ----------------------------------------------------------------------------

from oic.oic.server import UserinfoEndpoint
from oic.oic.server import CheckIDEndpoint

ENDPOINTS = [
    UserinfoEndpoint(userinfo),
    CheckIDEndpoint(check_id),
]

URLS = [
    (r'^.well-known/openid-configuration', op_info),
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
    global LOOKUP
    global OAS

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
    environ["mako.lookup"] = LOOKUP

    LOGGER.info("path: %s" % path)
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

FUNCTIONS = {}

USERDB = {
    "diana":{
        "birthdate": "02/14/2012",
        "gender": "female"
    }
}

SERVER_DB = {

}

if __name__ == '__main__':
    import argparse
    import json
    import shelve

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_builtin

    from oic.oic.server import Server
    from oic.utils.sdb import SessionDB

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument(dest="config")
    args = parser.parse_args()

    cdb = shelve.open("client_db", writeback=True)
    # in memory session storage

    config = json.loads(open(args.config).read())
    OAS = Server(config["issuer"], SessionDB(), cdb, FUNCTIONS,
                 config["keys"], USERDB)

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
    SRV.ssl_adapter = ssl_builtin.BuiltinSSLAdapter("certs/server.crt",
                                                    "certs/server.key")
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
