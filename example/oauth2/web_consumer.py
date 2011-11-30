#!/usr/bin/env python

__author__ = 'rohe0002'

import logging
import re

from oic.utils import http_util
from oic.oauth2.consumer import Consumer
from oic.oauth2.consumer import TokenError
from oic.oauth2.consumer import AuthzError
from oic.oauth2.consumer import UnknownState
from oic.oauth2 import consumer

LOGGER = logging.getLogger("oicClient")
hdlr = logging.FileHandler('oauth2Client.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://connect-op.heroku.com",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
    #"user_info_endpoint":"http://localhost:8088/user_info",
    #"check_id_endpoint":"http://localhost:8088/id_token",
    #"registration_endpoint":"https://connect-op.heroku.com/connect/client",
    #"scopes_supported":["openid","profile","email","address","PPID"],
    "flows_supported":["code","token","code token"],
    #"identifiers_supported":["public","ppid"],
    #"x509_url":"https://connect-op.heroku.com/cert.pem"
}


# ----------------------------------------------------------------

#noinspection PyUnusedLocal
def resource(environ, start_response, logger, kaka=None):
    """

    """
    _log_info = logger.info

    _session_db = environ["oic.sessiondb"]
    _conc = environ["oic.consumer.config"]

    _oac = consumer.factory(kaka, _session_db, _conc)

    if _oac is None:
        resp = http_util.Unauthorized("No valid cookie")
        return resp(environ, start_response)
    
    url = "http://localhost:8088/safe"
    response, content = _oac.fetch_protected_resource(url)

    if _oac.debug:
        _log_info("response: %s (%s)" % (response, type(response)))

    resp = http_util.factory(response.status, content)
#    if kaka:
#        resp.headers.append(kaka)

    return resp(environ, start_response)

#noinspection PyUnusedLocal
def register(environ, start_response, logger, kaka=None):
    """
    Initialize the OAuth2 flow
    """
    _session_db = environ["oic.sessiondb"]
    _cc = environ["oic.client_config"]
    _conc = environ["oic.consumer.config"]
    _server_info = environ["oic.server.info"]
    
    # get the redirect to the authorization server endpoint
    _oac = Consumer(_session_db, _conc, _cc, _server_info)
    location = _oac.begin(environ, start_response, logger)

    resp = http_util.Redirect(location)
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def authz(environ, start_response, logger, kaka=None):
    """
    This is where I get back to after authentication at the Authorization
    service
    """
    _session_db = environ["oic.sessiondb"]
    _cc = environ["oic.client_config"]
    _conc = environ["oic.consumer.config"]
    _server_info = environ["oic.server.info"]

    _log_info = logger.info

    try:
        _cli = Consumer(_session_db, _conc, _cc, _server_info)
        response = _cli.parse_authz(environ, start_response, logger)
    except (AuthzError, TokenError), err:
        resp = http_util.Unauthorized("%s" % err)
        return resp(environ, start_response)
    except UnknownState, err:
        resp = http_util.BadRequest("Unsolicited Response")
        return resp(environ, start_response)

    if _conc["flow_type"] == "code": # Not done yet
        try:
            _cli.complete(logger) # get the access token from the token
                                    # endpoint
        except TokenError, err:
            resp = http_util.Unauthorized("%s" % err)
            return resp(environ, start_response)

    # Valid for 6 hours (=360 minutes)
    kaka = http_util.cookie(_cc["client_id"], _cli.state, _cli.seed,
                            expire=360, path="/")

    _log_info("DUMP: %s" % (_cli.sdb[_cli.sdb["seed:%s" % _cli.seed]],))
    
    resp = http_util.Response("Your will is registered", headers=[kaka])
    _log_info("Cookie: %s" % (kaka,))
    return resp(environ, start_response)

# ----------------------------------------------------------------------------

URLS = [
    (r'resource', resource),
    (r'register$', register),
    (r'authz', authz),
]

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

    global CLIENT_CONFIG
    global SESSIONS
    global LOGGER

    path = environ.get('PATH_INFO', '').lstrip('/')
    kaka = environ.get("HTTP_COOKIE", '')
    #_debug = CONSUMER_CONFIG["debug"]

    LOGGER.info("environ: %s" % environ)
    if kaka:
        LOGGER.info("Incomming Cookie: %s" % (kaka,))

    if "oic.consumer.config" not in environ:
        environ["oic.consumer.config"] = CONSUMER_CONFIG
    if "oic.server.info" not in environ:
        environ["oic.server.info"] = SERVER_INFO
    if "oic.sessiondb" not in environ:
        environ["oic.sessiondb"] = SESSION_DB
    if "oic.client_config" not in environ:
        environ["oic.client_config"] = CLIENT_CONFIG

    for regex, callback in URLS:
        if kaka:
            return resource(environ, start_response, LOGGER, kaka)
        else:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['oic.url_args'] = match.groups()[0]
                except IndexError:
                    environ['oic.url_args'] = path
                return callback(environ, start_response, LOGGER, kaka)

    resp = http_util.NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

SESSION_DB = {}
CLIENT_CONFIG = {}
CONSUMER_CONFIG = {}

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', dest='scope', nargs='*', help='Scope')
    parser.add_argument('-t', dest="type", nargs=1, help='Flow type',
                        default="code")
    parser.add_argument('-i', dest="client_id", default="a1b2c3")
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=8087, type=int)
    parser.add_argument('-r', dest="response_type", nargs='?')
    parser.add_argument('-w', dest="passwd")
    parser.add_argument('-e', dest='expire_in', default=600, type=int)
    parser.add_argument('-x', dest='server_info')
    parser.add_argument('-c', dest='client_secret')

    args = parser.parse_args()

    CLIENT_CONFIG = {
        "client_id": args.client_id,
    }

    if not args.passwd and not args.client_secret:
        print "One of password or client_secret must be set"
        exit()
        
    CONSUMER_CONFIG = {
        "debug": args.debug,
        "server_info": SERVER_INFO,
        "authz_page": "/authz",
        "flow_type": args.type,
        "password": args.passwd,
        "scope": args.scope,
        "expire_in": args.expire_in,
        "client_secret": args.client_secret,
    }

    if args.type == "implicit":
        CONSUMER_CONFIG["response_type"] =["token"]
    else:
        CONSUMER_CONFIG["response_type"] =["code"]


    srv = make_server('localhost', args.port, application)
    print "OAuth client listening on port: %s" % args.port
    srv.serve_forever()