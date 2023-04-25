import argparse
import importlib
import logging
import sys
import uuid
from urllib.parse import parse_qs
from urllib.parse import unquote

import cherrypy
from beaker.middleware import SessionMiddleware

from oic.oauth2.consumer import Consumer
from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from oic.utils.http_util import SeeOther
from oic.utils.http_util import get_or_post

# ============================================================================
# First define how logging is supposed to be done
# ============================================================================

LOGGER = logging.getLogger("")
LOGFILE_NAME = "rp.log"
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.INFO)

SERVER_ENV = {}
RP = None
RP_CONF = None
CONSUMER = {}

# ============================================================================
# Endpoint functions
# ============================================================================


def as_choice(environ, start_response):
    resp = Response(
        mako_template="as_choice.mako", template_lookup=RP_CONF.LOOKUP, headers=[]
    )
    argv = {"as_list": RP_CONF.AS_CONF.keys(), "action": "as", "method": "POST"}
    return resp(environ, start_response, **argv)


# noinspection PyUnresolvedReferences
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

Token = {}
Clients = {}


def store_client(cli):
    lookup_key = str(uuid.uuid4())
    Clients[lookup_key] = cli
    return lookup_key


def get_client(lookup_key):
    return Clients.get(lookup_key)


def application(environ, start_response):
    session = environ["beaker.session"]

    path = environ.get("PATH_INFO", "").lstrip("/")
    if path == "robots.txt":
        return static(environ, start_response, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, path)

    if path == "logout":
        session.invalidate()
        resp = SeeOther("static/log_out_message.html")
        return resp(environ, start_response)

    if path == "as":
        session["callback"] = True
        request = parse_qs(get_or_post(environ))
        _cli = CONSUMER[unquote(request["authzsrv"][0])]
        session["client"] = store_client(_cli)
        sid, redirect_uri = _cli.begin(RP_CONF.BASE, path)
        resp = SeeOther(redirect_uri)
        return resp(environ, start_response)

    if path == "rp":
        session["callback"] = True
        request = parse_qs(get_or_post(environ))
        _cli = CONSUMER[unquote(request["iss"][0])]
        session["client"] = store_client(_cli)
        sid, redirect_uri = _cli.begin(RP_CONF.BASE, path)
        resp = SeeOther(redirect_uri)
        return resp(environ, start_response)

    if path == "authz_cb":
        _cli = get_client(session["client"])
        request = get_or_post(environ)
        aresp = _cli.handle_authorization_response(request)
        rargs = {"code": aresp["code"]}
        atresp = _cli.do_access_token_request(request_args=rargs)
        # Access token should be stored somewhere for later usage
        Token[atresp["state"]] = atresp
        resp = Response("Got access token: %s" % atresp["access_token"])
        return resp(environ, start_response)

    return as_choice(environ, start_response)


# ============================================================================
# Below is what's needed to start the server
# ============================================================================

START_MESG = "OAuth2 relaying party listening on port:%s at %s"

if __name__ == "__main__":
    session_opts = {
        "session.type": "memory",
        "session.cookie_expires": True,
        "session.auto": True,
        "session.timeout": 900,
    }

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", dest="conf_path")
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # Load the configuration file, which must be a python file
    # The default; first look for it in the directory from where this program
    # is run.
    sys.path.insert(0, ".")
    # If a specific configuration directory is specified look there first
    if args.conf_path:
        sys.path.insert(0, args.conf_path)
    RP_CONF = importlib.import_module(args.config)

    # per AS instantiate a consumer
    for name, info in RP_CONF.AS_CONF.items():
        c_conf = {"client_id": info["client_id"]}

        CONSUMER[name] = Consumer(
            session_db={},
            client_config=c_conf,
            server_info={
                "authorization_endpoint": info["authorization_endpoint"],
                "token_endpoint": info["token_endpoint"],
            },
            authz_page="authz_cb",
            response_type="code",
        )

        CONSUMER[name].client_secret = info["client_secret"]

    app = SessionMiddleware(application, session_opts)
    cherrypy.config.update({"server.socket_port": RP_CONF.PORT})
    cherrypy.tree.graft(app, "/")

    if RP_CONF.BASE.startswith("https"):
        cherrypy.config.update(
            {
                "cherrypy.server.ssl_certificate": RP_CONF.SERVER_CERT,
                "cherrypy.server.ssl_private_key": RP_CONF.SERVER_KEY,
            }
        )

    LOGGER.info(START_MESG % (RP_CONF.PORT, RP_CONF.HOST))
    print(START_MESG % (RP_CONF.PORT, RP_CONF.HOST))
    try:
        cherrypy.engine.start()
    except KeyboardInterrupt:
        pass
