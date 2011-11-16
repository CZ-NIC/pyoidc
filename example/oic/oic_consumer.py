#!/usr/bin/env python

__author__ = 'rohe0002'

#import cgitb
#cgitb.enable()

import re
import os
import logging

from mako.lookup import TemplateLookup

from oic.oic import CLAIMS
from oic.oic import UserInfoClaim
from oic.oic import IDTokenClaim
from oic.oic import OpenIDRequest
from oic.oic import consumer
from oic.oauth2.consumer import TokenError
from oic.oauth2.consumer import AuthzError
from oic.oauth2.consumer import UnknownState

from oic.oic.consumer import Consumer

from oic.utils import http_util

def construct_openid_request(arq, key):
    """
    Construct the specification of what I want returned.
    The request will be signed
    """

    # Should be configurable !!
    claims = CLAIMS(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    uic = UserInfoClaim(claims, format="signed", locale="us-en")

    id_token = IDTokenClaim(max_age=86400, iso29115="2")

    oir = OpenIDRequest(arq.response_type, arq.client_id,
                            arq.redirect_uri,
                            arq.scope, arq.state, uic, id_token)

    return oir.get_jwt(key)


# ----------------------------------------------------------------------------

#noinspection PyUnusedLocal
def resource(environ, start_response, logger, kaka=None):
    """

    """
    _log_info = logger.info

    _session_db = environ["oic.session_db"]
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
    _session_db = environ["oic.session_db"]
    _cc = environ["oic.client_config"]
    _conc = environ["oic.consumer.config"]
    _server_info = environ["oic.server.info"]

    # get the redirect to the authorization server endpoint
    _oac = Consumer(_session_db, _conc, _cc, _server_info)
    location = _oac.begin(environ, start_response, logger)

    logger.info("[1] %s" % (_oac.__dict__,))
    resp = http_util.Redirect(location)
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def authz(environ, start_response, logger, kaka=None):
    """
    This is where I am returned to after authentication at the Authorization
    service
    """
    _session_db = environ["oic.session_db"]
    _cc = environ["oic.client_config"]
    _conc = environ["oic.consumer.config"]
    _server_info = environ["oic.server.info"]

    _log_info = logger.info

    try:
        _cli = Consumer(_session_db, _conc, _cc, _server_info)
        aresp, atr, idt = _cli.parse_authz(environ, start_response, logger)
    except (AuthzError, TokenError), err:
        resp = http_util.Unauthorized("%s" % err)
        return resp(environ, start_response)
    except UnknownState, err:
        resp = http_util.BadRequest("Unsolicited Response")
        return resp(environ, start_response)

    #_log_info("CLI: %s" % (_cli.__dict__,))

    if _conc["response_type"] == ["code"] or _conc["response_type"] == "code":
        # Not  done yet
        try:
            atr = _cli.complete(logger) # get the access token from the token
                                        # endpoint
        except TokenError, err:
            _log_info("Err: %s" % err)
            resp = http_util.Unauthorized("%s" % err)
            return resp(environ, start_response)
        except Exception, err:
            _log_info("Exception err: %s" % err)
            raise
    else:
        pass

    _log_info("AU: %s" % aresp)
    _log_info("AT: %s" % atr)
    _log_info("DUMP: %s" % (_cli.sdb[_cli.state],))

    _log_info("[2] %s" % (_cli.__dict__,))

    # Valid for 6 hours (=360 minutes)
    kaka = http_util.cookie(_conc["name"], _cli.state, _cli.seed, expire=360,
                            path="/")

    resp = http_util.Response("Your will is registered", headers=[kaka])
    _log_info("Cookie: %s" % (kaka,))
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def userinfo(environ, start_response, logger, kaka=None):

    _session_db = environ["oic.session_db"]
    _cc = environ["oic.client_config"]
    _conc = environ["oic.consumer.config"]
    _server_info = environ["oic.server.info"]

    _log_info = logger.info

    _oac = consumer.factory(kaka, _session_db, _conc)

    _log_info("_server_info: %s" % (_server_info, ))
    _log_info("[3]: %s" % (_oac.__dict__, ))
    
    try:
        uinfo = _oac.userinfo(logger)
    except (AuthzError, TokenError), err:
        resp = http_util.Unauthorized("%s" % err)
        return resp(environ, start_response)

    _log_info("userinfo: %s" % (uinfo.dictionary(),))

    if not _oac.id_token:
        # get id_token from the authorization end point
        pass

    tab = ["<h2>User Info</h2>",
           '<table border="1">',
           "<tr><th>attribute</th><th>value</th></tr>"]

    for attr in uinfo.c_attributes.keys():
        v = getattr(uinfo, attr, "")
        if v:
            tab.append("<tr><td>%s</td><td>%s</td></tr>" % (attr, v))
    tab.append("</table>")

    resp = http_util.Response("\n".join(tab))
    return resp(environ, start_response)

#def fragment(environ, start_response, logger, kaka=None):
#    _session_db = environ["oic.session_db"]
#    _cc = environ["oic.client_config"]
#    _conc = environ["oic.consumer.config"]
#    _server_info = environ["oic.server.info"]
#
#    _log_info = logger.info
#
#    _log_info("environ: %s" % environ)
#
#    try:
#        _cli = Consumer(_session_db, _conc, _cc, _server_info)
#        response = _cli.parse_authz(environ, start_response, logger)
#
#    aresp =
#    resp = http_util.Response("Yipee!")
#    return resp(environ, start_response)


# ========================================================================

def do_request_file(environ, start_response, path):
    _path = os.path.join(os.getcwd(), path)
    _fp = open(_path)
    _req = _fp.read()
    _fp.close()
    # Can only be used once
    #os.unlink(path)
    resp = http_util.Response(_req)
    return resp(environ, start_response)

def scripts(environ, start_response, path):
    _path = os.path.join(os.getcwd(), path)
    resp = http_util.Response(open(_path).read())
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def jqauthz(environ, start_response, path):
    resp = http_util.Response(mako_template="jqa.mako", 
                              template_lookup=environ["mako.lookup"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------

URLS = [
    (r'resource', resource),
    (r'register$', register),
    (r'authz', authz),
    (r'scripts', scripts),
    (r'userinfo', userinfo),
#    (r'fragment', fragment),
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
    global CONSUMER_CONFIG
    global LOGGER
    global SERVER_INFO
    global SESSION_DB
    global CLIENT_CONFIG
    global LOOKUP

    path = environ.get('PATH_INFO', '').lstrip('/')
    kaka = environ.get("HTTP_COOKIE", '')

    LOGGER.info("PATH: %s" % path)
    if kaka:
        if CONSUMER_CONFIG["debug"]:
            LOGGER.debug("Cookie: %s" % (kaka,))

    environ["oic.consumer.config"] = CONSUMER_CONFIG
    environ["oic.server.info"] = SERVER_INFO
    environ["oic.session_db"] = SESSION_DB
    environ["oic.client_config"] = CLIENT_CONFIG
    environ["mako.lookup"] = LOOKUP

    if path.startswith(CONSUMER_CONFIG["temp_dir"]):
        return do_request_file(environ, start_response, path)

    if path.startswith("scripts"):
        return scripts(environ, start_response, path)

    if path == "jqauthz":
        return jqauthz(environ, start_response, path)

    for regex, callback in URLS:
        if kaka:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['oic.url_args'] = match.groups()[0]
                except IndexError:
                    environ['oic.url_args'] = path
                return callback(environ, start_response, LOGGER, kaka)
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

ROOT = '../'
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

LOGGER = logging.getLogger("oicClient")
hdlr = logging.FileHandler('oicClient.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

SESSION_DB = {}
CLIENT_CONFIG = {}
CONSUMER_CONFIG = {}
SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://connect-op.heroku.com",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
    "user_info_endpoint":"http://localhost:8088/user_info",
    #"check_id_endpoint":"http://localhost:8088/id_token",
    #"registration_endpoint":"https://connect-op.heroku.com/connect/client",
    #"scopes_supported":["openid","profile","email","address","PPID"],
    "flows_supported":["code","token","code token"],
    #"identifiers_supported":["public","ppid"],
    #"x509_url":"https://connect-op.heroku.com/cert.pem"
}

FUNCTION = {
    "openid_request": construct_openid_request,
}

if __name__ == '__main__':
    #from wsgiref.simple_server import make_server
    from cherrypy import wsgiserver
    #from cherrypy.wsgiserver import ssl_builtin

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', dest='scope', nargs='*', help='Scope')
    parser.add_argument('-i', dest="client_id", default="a1b2c3")
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=8087, type=int)
    parser.add_argument('-r', dest="response_type", nargs='?')
    parser.add_argument('-w', dest="passwd")
    parser.add_argument('-e', dest='expire_in', default=600, type=int)
    parser.add_argument('-x', dest='server_info')
    parser.add_argument('-c', dest='client_secret')
    parser.add_argument('-m', dest='request_method', default="parameter")
    parser.add_argument('-T', dest='temp_dir', default="tmp")
    parser.add_argument('-j', dest='jwt_key', default="client_key")

    args = parser.parse_args()

    CLIENT_CONFIG = {
        "client_id": args.client_id,
    }

    if not args.passwd and not args.client_secret:
        print "One of password or client_secret must be set"
        exit()

    if not args.scope:
        args.scope = ["openid"]
    else:
        assert "openid" in args.scope
        
    CONSUMER_CONFIG = {
        "debug": args.debug,
        "server_info": SERVER_INFO,
        "authz_page": "/jqauthz",
        "name": "pyoic",
        "password": args.passwd,
        "scope": args.scope,
        "expire_in": args.expire_in,
        "client_secret": args.client_secret,
        "function": FUNCTION,
        "request_method": args.request_method,
        "temp_dir": args.temp_dir,
        "key": args.jwt_key,
    }

    if args.response_type:
        CONSUMER_CONFIG["response_type"] = args.response_type.split(" ")
    else:
        CONSUMER_CONFIG["response_type"] = []

    print "Response type: %s" % CONSUMER_CONFIG["response_type"]
    
    if CONSUMER_CONFIG["response_type"] == ["code"]:
        CONSUMER_CONFIG["flow_type"]= "code"
    else:
        CONSUMER_CONFIG["flow_type"]= "implicit"

    print "flow type: %s" % CONSUMER_CONFIG["flow_type"]

    srv = wsgiserver.CherryPyWSGIServer(('localhost', args.port), application)
    print "OIC client listening on port: %s" % args.port
    try:
        srv.start()
    except KeyboardInterrupt:
        srv.stop()
