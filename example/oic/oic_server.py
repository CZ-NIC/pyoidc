#!/usr/bin/env python

__author__ = 'rohe0002'

import logging
import re
import base64

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

from oic.utils.http_util import *
from oic.oauth2.server import AuthnFailure

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("oicServer")
hdlr = logging.FileHandler('oicServer.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

SERVER = None

USERS = [("foo", "bar")]

def do_authentication(environ, start_response, sid):
    """
    Put up the login form
    """
    resp = Response(mako_template="login.mako",
                    template_lookup=environ["mako.lookup"])

    argv = { "sid": sid,
             "login": "",
             "password": "",
             "action": "authenticated"
    }
    return resp(environ, start_response, **argv)

def verify_username_and_password(dic):
    # verify username and password
    for user in USERS:
        if user[0] == dic["login"][0]:
            if user[1] == dic["password"][0]:
                return True, user[0]
            else:
                raise AuthnFailure("Wrong password")

    return False, ""

#noinspection PyUnusedLocal
def do_authorization(user, session):
    """
    :param user: The user identifier
    :param session: Session information as a dictionary
    :return: A tuple containing scope and permission specifications
        scope is a string, permission is whatever you want.
    """
    return session["scope"], "ALL"

# ----------------------------------------------------------------------------

#noinspection PyUnusedLocal
def client_basic_auth(environ, atr, cdb):
    user, passwd = base64.decodestring(environ["HTTP_AUTHORIZATION"]).split(":")
    try:
        assert cdb[user]["password"] == passwd
    except (KeyError, AssertionError):
        return False

    return True

#noinspection PyUnusedLocal
def client_secret(environ, atr, cdb):
    try:
        item = cdb[atr.client_id]
        assert item["client_secret"] == atr.client_secret
    except (KeyError, AssertionError):
        return False
    return True

def verify_client(environ, atr, cdb):
    try:
        return client_basic_auth(environ, atr, cdb)
    except KeyError:
        return client_secret(environ, atr, cdb)

# ----------------------------------------------------------------------------

def safe(environ, start_response, logger, handle):
    _oas = environ["oic.server"]
    _sdb = _oas.sdb
    _log_info = logger.info

    _log_info("- safe -")
    _log_info("env: %s" % environ)
    _log_info("handle: %s" % (handle,))

    try:
        authz = environ["HTTP_AUTHORIZATION"]
        (typ, code) = authz.split(" ")
        code = base64.decodestring(code)
        assert typ == "Bearer"
    except KeyError:
        resp = BadRequest("Missing authorization information")
        return resp(environ, start_response)

    try:
        _sinfo = _sdb[code]
    except KeyError:
        resp = Unauthorized("Not authorized")
        return resp(environ, start_response)

    info = "'%s' permissions: %s" % (_sinfo["userid"], _sinfo["permission"])
    resp = Response(info)
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def css(environ, start_response, handle, logger):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except Exception:
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------

#noinspection PyUnusedLocal
def token(environ, start_response, logger, handle):
    _oas = environ["oic.server"]

    return _oas.token_endpoint(environ, start_response, logger, handle)

#noinspection PyUnusedLocal
def authorization(environ, start_response, logger, handle):
    _oas = environ["oic.server"]

    return _oas.authorization_endpoint(environ, start_response, logger, handle)

#noinspection PyUnusedLocal
def authenticated(environ, start_response, logger, handle):
    _oas = environ["oic.server"]

    return _oas.authenticated(environ, start_response, logger, handle)

# ----------------------------------------------------------------------------

URLS = [
    (r'^authorization', authorization),
    (r'^authenticated', authenticated),
    (r'^token', token),
    (r'.+\.css$', css),
    (r'safe', safe)
]

# ----------------------------------------------------------------------------

ROOT = '../'

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
    global LOOKUP
    global SERVER

    #user = environ.get("REMOTE_USER", "")
    path = environ.get('PATH_INFO', '').lstrip('/')
    kaka = environ.get("HTTP_COOKIE", '')

    if kaka:
        handle = parse_cookie(SERVER.name, SERVER.seed, kaka)
        if SERVER.debug:
            SERVER.logger.debug("Cookie: %s" % (kaka,))
    else:
        handle = ""

    environ["oic.server"] = SERVER
    environ["mako.lookup"] = LOOKUP

    LOGGER.info("path: %s" % path)
    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = path
            return callback(environ, start_response, LOGGER, handle)

    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

from oic.utils import sdb
from oic.oic.server import Server

CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        "jwt_key": "",
    },
}

FUNCTION = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify user": verify_username_and_password,
    "verify client": verify_client,
}

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=8088, type=int)
    args = parser.parse_args()

    URLMAP={}

    # in memory session storage

    SERVER = Server("http://localhost:8088/",
                    sdb.SessionDB(),
                    CDB,
                    FUNCTION,
                    "1234567890",
                    debug=args.debug)

    srv = make_server('localhost', args.port, application)
    print "OIC Authz server listening on port: %s" % args.port
    srv.serve_forever()