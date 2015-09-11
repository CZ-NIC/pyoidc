#!/usr/bin/env python
import importlib
import argparse
from jwkest.jws import alg2keytype
from mako.lookup import TemplateLookup
from six.moves.urllib import parse as urlparse
import six
import logging

from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect


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


# noinspection PyUnresolvedReferences
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
        "op_list": list(clients.keys())
    }
    return resp(environ, start_response, **argv)


def opresult(environ, start_response, userinfo, check_session_iframe_url=None):
    resp = Response(mako_template="opresult.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "userinfo": userinfo,
    }
    if check_session_iframe_url:
        argv["check_session_iframe_url"] = check_session_iframe_url

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


def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    query = urlparse.parse_qs(environ["QUERY_STRING"])

    if path == "rp":  # After having chosen which OP to authenticate at
        if "uid" in query:
            client = CLIENTS.dynamic_client(query["uid"][0])
            session["op"] = client.provider_info["issuer"]
        else:
            client = CLIENTS[query["op"][0]]
            session["op"] = query["op"][0]

        try:
            resp = client.create_authn_request(session, ACR_VALUES)
        except Exception:
            raise
        else:
            return resp(environ, start_response)
    elif path in ["authz_cb", "google"]:  # After having authenticated at the OP
        client = CLIENTS[session["op"]]
        try:
            result = client.callback(query, session)
            if isinstance(result, Redirect):
                return result(environ, start_response)
        except OIDCError as err:
            return operror(environ, start_response, "%s" % err)
        except Exception:
            raise
        else:
            check_session_iframe_url = None
            try:
                check_session_iframe_url = client.provider_info[
                    "check_session_iframe"]

                session["session_management"] = {
                    "session_state": query["session_state"][0],
                    "client_id": client.client_id,
                    "issuer": client.provider_info["issuer"]
                }
            except KeyError:
                pass

            return opresult(environ, start_response, result,
                            check_session_iframe_url)
    elif path == "logout":  # After the user has pressed the logout button
        client = CLIENTS[session["op"]]
        logout_url = client.end_session_endpoint
        try:
            # Specify to which URL the OP should return the user after
            # log out. That URL must be registered with the OP at client
            # registration.
            logout_url += "?" + urlparse.urlencode(
                {"post_logout_redirect_uri": client.registration_response[
                    "post_logout_redirect_uris"][0]})
        except KeyError:
            pass
        else:
            # If there is an ID token send it along as a id_token_hint
            _idtoken = get_id_token(client, session)
            if _idtoken:
                logout_url += "&" + urlparse.urlencode({
                    "id_token_hint": id_token_as_signed_jwt(client, _idtoken,
                                                            "HS256")})
            # Also append the ACR values
            logout_url += "&" + urlparse.urlencode({"acr_values": ACR_VALUES},
                                                 True)

        LOGGER.debug("Logout URL: %s" % str(logout_url))
        LOGGER.debug("Logging out from session: %s" % str(session))
        session.delete()
        resp = Redirect(str(logout_url))
        return resp(environ, start_response)
    elif path == "logout_success":  # post_logout_redirect_uri
        return Response("Logout successful!")(environ, start_response)
    elif path == "session_iframe":  # session management
        kwargs = session["session_management"]
        resp = Response(mako_template="rp_session_iframe.mako",
                        template_lookup=LOOKUP)
        return resp(environ, start_response,
                    session_change_url="{}session_change".format(
                        SERVER_ENV["base_url"]),
                    **kwargs)
    elif path == "session_change":
        try:
            client = CLIENTS[session["op"]]
        except KeyError:
            return Response("No valid session.")(environ, start_response)

        kwargs = {"prompt": "none"}
        # If there is an ID token send it along as a id_token_hint
        idt = get_id_token(client, session)
        if idt:
            kwargs["id_token_hint"] = id_token_as_signed_jwt(client, idt,
                                                             "HS256")
        resp = client.create_authn_request(session, ACR_VALUES, **kwargs)
        return resp(environ, start_response)

    return opchoice(environ, start_response, CLIENTS)


if __name__ == '__main__':
    from oidc import OIDCClients
    from oidc import OIDCError
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument(dest="config")
    parser.add_argument("-p", default=8666, dest="port", help="port of the RP")
    parser.add_argument("-b", dest="base_url", help="base url of the RP")
    args = parser.parse_args()
    conf = importlib.import_module(args.config)

    if args.base_url:
        conf.BASE = args.base_url

    conf.BASE = "{base}:{port}/".format(base=conf.BASE, port=args.port)
    conf.ME["redirect_uris"] = [url.format(base=conf.BASE) for url in
                                conf.ME["redirect_uris"]]
    conf.ME["post_logout_redirect_uris"] = [url.format(base=conf.BASE) for url
                                            in conf.ME[
            "post_logout_redirect_uris"]]

    for client, client_conf in six.iteritems(conf.CLIENTS):
        if "client_registration" in client_conf:
            client_reg = client_conf["client_registration"]
            client_reg["redirect_uris"] = [url.format(base=conf.BASE) for url in
                                           client_reg["redirect_uris"]]

    global ACR_VALUES
    ACR_VALUES = conf.ACR_VALUES

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(
            urlparse.urlparse(conf.BASE).netloc.replace(":", "."))
    }

    CLIENTS = OIDCClients(conf)
    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": conf.BASE})

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', int(args.port)),
                                        SessionMiddleware(application,
                                                          session_opts))

    if conf.BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            conf.SERVER_CERT, conf.SERVER_KEY, conf.CA_BUNDLE)

    LOGGER.info("RP server starting listening on port:%s" % args.port)
    print ("RP server starting listening on port:%s" % args.port)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
