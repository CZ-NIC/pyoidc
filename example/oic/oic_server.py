#!/usr/bin/env python

__author__ = 'rohe0002'

import logging
import re
import base64
import os
import json

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

from oic.utils.http_util import *

from oic.oic import ProviderConfigurationResponse

from oic.utils import sdb
from oic.oic.server import Server
from oic.oic.server import UserInfo
from oic.oic.consumer import ISSUER_URL
from authentication import Authentication

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("oicServer")
hdlr = logging.FileHandler('oicServer.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

SERVER = None

def userinfo(user_db, user_id, client_id, user_info_claim):
    global LOGGER

    LOGGER.info("userid: %s, client_id: %s" % (user_id, client_id))

    claims = user_info_claim.claims
    _locale = user_info_claim.locale
    LOGGER.info("locale: %s, claims: %s" % (_locale, claims))
    LOGGER.info("-info-: %s" % user_db.db[user_id])
    return user_db.pick(user_id, client_id, claims, _locale)

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
    (type, key) = environ["HTTP_AUTHORIZATION"].split(" ")
    assert type == "Basic"
    user, passwd = base64.b64decode(key).split(":")
    try:
        assert cdb[user]["password"] == passwd
    except (KeyError, AssertionError), err:
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
    print "Verify client"
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

    _log_info("SINFO: %s" % _sinfo)
    
    info = "'%s' permissions: %s" % (_sinfo["user_id"], _sinfo["permission"])
    resp = Response(info)
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def css(environ, start_response, handle, logger):
    _wd = os.getcwd()
    try:
        info = open(os.path.join(_wd, environ["PATH_INFO"])).read()
        resp = Response(info)
    except Exception:
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------

#noinspection PyUnusedLocal
def token(environ, start_response, logger, handle):
    _oas = environ["oic.server"]

    try:
        return _oas.token_endpoint(environ, start_response, logger, handle)
    except Exception,err:
        logger.info("exception: %s" % err)
        resp = ServiceError("%s" % err)
        return resp(environ, start_response)

#noinspection PyUnusedLocal
def authorization(environ, start_response, logger, handle):
    _oas = environ["oic.server"]

    return _oas.authorization_endpoint(environ, start_response, logger, handle)

#noinspection PyUnusedLocal
def authenticated(environ, start_response, logger, handle):
    _oas = environ["oic.server"]

    return _oas.authenticated(environ, start_response, logger, handle)

#noinspection PyUnusedLocal
def user_info(environ, start_response, logger, handle):
    _oas = environ["oic.server"]

    return _oas.user_info_endpoint(environ, start_response, logger)

#noinspection PyUnusedLocal
def openid_configuration(environ, start_response, logger, handle):
    _oas = environ["oic.server"]
    _path = geturl(environ, False, False)

    conf = ProviderConfigurationResponse(issuer=_oas.name,
            authorization_endpoint=_path+"/authorization",
            token_endpoint=_path+"/token",
            user_info_endpoint=_path+"/user_info",
            check_session_endpoint=_path+"/check",
            refresh_session_endpoint=_path+"/refresh_session",
            end_session_endpoint=_path+"/end_session",
            registration_endpoint=_path+"/registration",
            scopes_supported=["openid"],
            flows_supported=["code", "id_token", "token"])

    resp = Response(conf.to_json())
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def well_known(environ, start_response, logger, handle):
    #_oas = environ["oic.server"]
    #_path = geturl(environ, False, False)

    args = environ['oic.url_args']
    if args == "simple-web-discovery":
        qs = parse_qs(environ["QUERY_STRING"])

        if len(qs["service"]) == 1 and qs["service"][0] == ISSUER_URL:
            result = {"locations": ["http://localhost:8088/"]}
            resp = Response(json.dumps(result))
        else:
            resp = BadRequest("Unknown service")
    else:
        resp = BadRequest("Unknown type")
        
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def client_registration(environ, start_response, logger, handle):
    _oas = environ["oic.server"]

    return _oas.registration_endpoint(environ, start_response, logger)

# ----------------------------------------------------------------------------

URLS = [
    (r'^authorization', authorization),
    (r'^authenticated', authenticated),
    (r'^token', token),
    (r'.+\.css$', css),
    (r'safe', safe),
    (r'user_info', user_info),
    (r'\.well-known/openid-configuration$', openid_configuration),
    (r'\.well-known/(.*)$', well_known),
    (r'registration', client_registration)

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

    if not "oic.server" in environ:
        environ["oic.server"] = SERVER
    if not "mako.lookup" in environ:
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


CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        "jwt_key": "",
    },
}

AUTHN = Authentication("userdb")

FUNCTION = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify user": AUTHN.verify_username_and_password,
    "verify client": verify_client,
    "user info": userinfo,
}

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    import argparse
    import importlib

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=8088, type=int)
    parser.add_argument('-u', dest='user_info')
    parser.add_argument('-r', dest='claim_rules')
    args = parser.parse_args()

    URLMAP={}
    if args.user_info and args.claim_rules:
        uinfo = importlib.import_module(args.user_info)
        rules = importlib.import_module(args.claim_rules)
        USERDB = UserInfo(rules.RULES, uinfo.DB)
    else:
        USERDB = None

    # in memory session storage

    SERVER = Server("http://localhost:8088/",
                    sdb.SessionDB(),
                    CDB,
                    FUNCTION,
                    "1234567890",
                    USERDB,
                    debug=args.debug)

    srv = make_server('localhost', args.port, application)
    print "OIC Authz server listening on port: %s" % args.port
    srv.serve_forever()