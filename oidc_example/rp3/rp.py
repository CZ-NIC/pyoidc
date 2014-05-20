#!/usr/bin/env python
import urllib
from jwkest.jws import alg2keytype
from mako.lookup import TemplateLookup
from urlparse import parse_qs

from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect

import logging

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'rp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = ('%(asctime)s %(name)s:%(levelname)s '
       '[%(client)s,%(path)s,%(cid)s] %(message)s')
cpc_formatter = logging.Formatter(CPC)

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

SERVER_ENV = {}


#noinspection PyUnresolvedReferences
def static(environ, start_response, logger, path):
    logger.info("[static]sending: %s" % (path,))

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


def opchoice(environ, start_response, clients):
    resp = Response(mako_template="opchoice.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "op_list": clients.keys()
    }
    return resp(environ, start_response, **argv)


def opresult(environ, start_response, userinfo):
    resp = Response(mako_template="opresult.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "userinfo": userinfo,
    }
    return resp(environ, start_response, **argv)


def operror(environ, start_response, error=None):
    resp = Response(mako_template="operror.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "error": error
    }
    return resp(environ, start_response, **argv)


#
def get_id_token(client, session):
    return client.grant[session["state"]].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


def clear_session(session):
    for key in session:
        session.pop(key, None)
    session.invalidate()


def application(environ, start_response):
    session = environ['beaker.session']

    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    query = parse_qs(environ["QUERY_STRING"])

    if path == "rp":  # After having chosen which OP to authenticate at
        if "uid" in query:
            client = CLIENTS.dynamic_client(query["uid"][0])
            session["op"] = client.provider_info["issuer"]
        else:
            client = CLIENTS[query["op"][0]]
            session["op"] = query["op"][0]

        try:
            resp = client.create_authn_request(session)
        except Exception:
            raise
        else:
            return resp(environ, start_response)
    elif path == "authz_cb":  # After having authenticated at the OP
        client = CLIENTS[session["op"]]
        try:
            userinfo = client.callback(query)
        except OIDCError as err:
            return operror(environ, start_response, "%s" % err)
        except Exception:
            raise
        else:
            return opresult(environ, start_response, userinfo)
    elif path == "logout":  # After the user has pressed the logout button
        client = CLIENTS[session["op"]]
        logout_url = client.endsession_endpoint
        try:
            # Specify to which URL the OP should return the user after
            # log out. That URL must be registered with the OP at client
            # registration.
            logout_url += "?" + urllib.urlencode(
                {"post_logout_redirect_uri": client.registration_response[
                    "post_logout_redirect_uris"][0]})
        except KeyError:
            pass
        else:
            # If there is an ID token send it along as a id_token_hint
            _idtoken = get_id_token(client, session)
            if _idtoken:
                logout_url += "&" + urllib.urlencode({
                    "id_token_hint": id_token_as_signed_jwt(client, _idtoken,
                                                            "HS256")})

        clear_session(session)
        resp = Redirect(str(logout_url))
        return resp(environ, start_response)

    return opchoice(environ, start_response, CLIENTS)


if __name__ == '__main__':
    from oidc import OIDCClients
    from oidc import OIDCError
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver
    import conf

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    CLIENTS = OIDCClients(conf)
    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": conf.BASE})

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', conf.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    if conf.BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            conf.SERVER_CERT, conf.SERVER_KEY, conf.CA_BUNDLE)

    LOGGER.info("RP server starting listening on port:%s" % conf.PORT)
    print "RP server starting listening on port:%s" % conf.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
