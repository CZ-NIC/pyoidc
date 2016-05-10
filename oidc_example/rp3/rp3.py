#!/usr/bin/env python
import importlib
import json
import argparse
import six
import logging

from requests import ConnectionError
from mako.lookup import TemplateLookup
from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import urlencode
from future.backports.urllib.parse import urlparse

from jwkest.jws import alg2keytype
from oic.utils.http_util import NotFound, get_post
from oic.utils.http_util import Response
from oic.utils.http_util import SeeOther

from requests.packages import urllib3
from oic.utils.keyio import build_keyjar
from oic.utils.rp.oauth2 import OAuthClients

urllib3.disable_warnings()

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


def opresult(environ, start_response, **kwargs):
    resp = Response(mako_template="opresult.mako",
                    template_lookup=LOOKUP,
                    headers=[])

    args = {}
    for param in ['userinfo', 'userid', 'id_token']:
        try:
            args[param] = kwargs[param]
        except KeyError:
            args[param] = None

    return resp(environ, start_response, **args)


def operror(environ, start_response, error=None):
    resp = Response(mako_template="operror.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "error": error
    }
    return resp(environ, start_response, **argv)


def opresult_fragment(environ, start_response):
    resp = Response(mako_template="opresult_repost.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {}
    return resp(environ, start_response, **argv)


def sorry_response(environ, start_response, homepage, err):
    resp = Response(mako_template="sorry.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {"htmlpage": homepage,
            "error": str(err)}
    return resp(environ, start_response, **argv)


def get_id_token(client, session):
    return client.grant[session["state"]].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


def url_eq(a, b):
    if a.endswith('/'):
        if b.endswith('/'):
            return a == b
        else:
            return a[:-1] == b
    else:
        if b.endswith('/'):
            return a == b[:-1]
        else:
            return a == b


def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")
    elif path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)
    elif '/static/' in path:
        pre, post = path.split('static')
        return static(environ, start_response, LOGGER, 'static'+post)

    query = parse_qs(environ["QUERY_STRING"])
    acr_values = session._params['acrs']
    clients = session._params['clients']
    server_env = session._params['server_env']

    LOGGER.info(50 * "=")
    LOGGER.info("[{}] path: {}".format(session.id, path))
    LOGGER.info(50 * "=")

    if path == '':
        if 'access_token' not in session:
            return opchoice(environ, start_response, clients)
        else:
            client = clients[session["op"]]
            # check_session_iframe_url = None
            try:
                # check_session_iframe_url = client.provider_info[
                #     "check_session_iframe"]

                session["session_management"] = {
                    "session_state": query["session_state"][0],
                    "client_id": client.client_id,
                    "issuer": client.provider_info["issuer"]
                }
            except KeyError:
                pass

            kwargs = dict(
                [(p, session[p]) for p in ['id_token', 'userinfo', 'user_id'] if
                 p in session])

            return opresult(environ, start_response, **kwargs)
    elif path == "rp":  # After having chosen which OP to authenticate at
        if "uid" in query:
            try:
                client = clients.dynamic_client(userid=query["uid"][0])
            except (ConnectionError, OIDCError) as err:
                return operror(environ, start_response, '{}'.format(err))
        elif 'issuer' in query:
            try:
                client = clients[query["issuer"][0]]
            except (ConnectionError, OIDCError) as err:
                return operror(environ, start_response, '{}'.format(err))
        else:
            client = clients[query["op"][0]]

        client.get_userinfo = session._params['userinfo']
        try:
            client.resource_server = session._params['resource_server']
        except KeyError:
            pass

        try:
            session['response_format'] = query["response_format"][0]
        except KeyError:
            session['response_format'] = 'html'

        session["op"] = client.provider_info["issuer"]

        try:
            resp = client.create_authn_request(session, acr_values)
        except Exception as err:
            logging.error(err)
            raise
        else:
            return resp(environ, start_response)
    elif path.endswith('authz_post'):
        try:
            _iss = session['op']
        except KeyError:
            LOGGER.info(
                '[{}] No active session with {}'.format(session.id,
                                                        environ['REMOTE_ADDR']))
            return opchoice(environ, start_response, clients)
        else:
            client = clients[_iss]

        query = parse_qs(get_post(environ))
        try:
            info = query["fragment"][0]
        except KeyError:
            return sorry_response(environ, start_response, conf.BASE,
                                  "missing fragment ?!")
        if info == ['x']:
            return sorry_response(environ, start_response, conf.BASE,
                                  "Expected fragment didn't get one ?!")

        LOGGER.info('[{}] Fragment part: {}'.format(session.id, info))

        try:
            result = client.callback(info, session, 'urlencoded')
            if isinstance(result, SeeOther):
                return result(environ, start_response)
        except OIDCError as err:
            return operror(environ, start_response, "%s" % err)
        except Exception as err:
            raise
        else:
            session.update(result)
            res = SeeOther(server_env['base_url'])
            return res(environ, start_response)
    elif path in clients.return_paths():  # After having authenticated at the OP
        try:
            _iss = session['op']
        except KeyError:
            LOGGER.info(
                '[{}]No active session with {}'.format(session.id,
                                                       environ['REMOTE_ADDR']))
            return opchoice(environ, start_response, clients)

        # mismatch between callback and return_uri
        # ignore trailing '/'
        if not url_eq(_iss, clients.path[path]):
            LOGGER.warning(
                '[{}]issuer mismatch: {} != {}'.format(session.id, _iss,
                                                       clients.path[path]))
            return operror(environ, start_response, "%s" % 'Not allowed')

        client = clients[clients.path[path]]

        _response_type = client.behaviour["response_type"]
        try:
            _response_mode = client.authz_req[session['state']]['response_mode']
        except KeyError:
            _response_mode = ''

        LOGGER.info(
            "[{}]response_type: {}, response_mode: {}".format(session.id,
                                                              _response_type,
                                                              _response_mode))
        if _response_type and _response_type != "code":
            # Fall through if it's a query response anyway
            if query:
                pass
            elif _response_mode:
                # form_post encoded
                pass
            else:
                return opresult_fragment(environ, start_response)

        LOGGER.info("[{}]Query part: {}".format(session.id, query))

        try:
            result = client.callback(query, session)
            if isinstance(result, SeeOther):
                return result(environ, start_response)
        except OIDCError as err:
            return operror(environ, start_response, "%s" % err)
        except Exception:
            raise
        else:
            session.update(result)
            res = SeeOther(server_env['base_url'])
            return res(environ, start_response)
    elif path == "logout":  # After the user has pressed the logout button
        try:
            _iss = session['op']
        except KeyError:
            LOGGER.info(
                '[{}]No active session with {}'.format(session.id,
                                                       environ['REMOTE_ADDR']))
            return opchoice(environ, start_response, clients)
        client = clients[_iss]
        try:
            del client.authz_req[session['state']]
        except KeyError:
            pass

        logout_url = client.end_session_endpoint
        try:
            # Specify to which URL the OP should return the user after
            # log out. That URL must be registered with the OP at client
            # registration.
            logout_url += "?" + urlencode(
                {"post_logout_redirect_uri": client.registration_response[
                    "post_logout_redirect_uris"][0]})
        except KeyError:
            pass
        else:
            # If there is an ID token send it along as a id_token_hint
            _idtoken = get_id_token(client, session)
            if _idtoken:
                logout_url += "&" + urlencode({
                    "id_token_hint": id_token_as_signed_jwt(client, _idtoken,
                                                            "HS256")})
            # Also append the ACR values
            logout_url += "&" + urlencode({"acr_values": acr_values},
                                          True)

        LOGGER.debug("[{}]Logout URL: {}".format(session.id, logout_url))
        LOGGER.debug("Logging out from session: [{}]".format(session.id))
        session.delete()
        resp = SeeOther(str(logout_url))
        return resp(environ, start_response)
    elif path == "logout_success":  # post_logout_redirect_uri
        return Response("Logout successful!")(environ, start_response)
    elif path == "session_iframe":  # session management
        kwargs = session["session_management"]
        resp = Response(mako_template="rp_session_iframe.mako",
                        template_lookup=LOOKUP)
        return resp(environ, start_response,
                    session_change_url="{}session_change".format(
                        server_env["base_url"]),
                    **kwargs)
    elif path == "session_change":
        try:
            _iss = session['op']
        except KeyError:
            LOGGER.info(
                '[{}]No active session with {}'.format(session.id,
                                                       environ['REMOTE_ADDR']))
            return opchoice(environ, start_response, clients)

        try:
            client = clients[_iss]
        except KeyError:
            return Response("No valid session.")(environ, start_response)

        kwargs = {"prompt": "none"}
        # If there is an ID token send it along as a id_token_hint
        idt = get_id_token(client, session)
        if idt:
            kwargs["id_token_hint"] = id_token_as_signed_jwt(client, idt,
                                                             "HS256")
        resp = client.create_authn_request(session, acr_values, **kwargs)
        return resp(environ, start_response)

    return opchoice(environ, start_response, clients)


if __name__ == '__main__':
    from oic.utils.rp import OIDCClients
    from oic.utils.rp import OIDCError
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument(dest="config")
    parser.add_argument("-p", default=8666, dest="port", help="port of the RP")
    parser.add_argument("-b", dest="base_url", help="base url of the RP")
    parser.add_argument('-k', dest='verify_ssl', action='store_false')
    args = parser.parse_args()
    conf = importlib.import_module(args.config)

    if args.base_url:
        conf.BASE = args.base_url

    _base = "{base}:{port}/".format(base=conf.BASE, port=args.port)

    for _client, client_conf in six.iteritems(conf.CLIENTS):
        if "client_registration" in client_conf:
            client_reg = client_conf["client_registration"]
            client_reg["redirect_uris"] = [url.format(base=conf.BASE) for url in
                                           client_reg["redirect_uris"]]

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(
            urlparse(conf.BASE).netloc.replace(":", "."))
    }

    try:
        key_spec = conf.KEY_SPECIFICATION
    except AttributeError:
        jwks_info = {}
    else:
        jwks, keyjar, kidd = build_keyjar(key_spec)
        jwks_info = {
            'jwks_uri': '{}static/jwks_uri.json'.format(_base),
            'keyjar': keyjar,
            'kid': kidd
        }
        f = open('static/jwks_uri.json', 'w')
        f.write(json.dumps(jwks))
        f.close()

    try:
        ctype = conf.CLIENT_TYPE
    except KeyError:
        ctype = 'OIDC'

    if ctype == 'OIDC':
        _clients = OIDCClients(conf, _base, jwks_info=jwks_info,
                               verify_ssl=args.verify_ssl)
    else:
        _clients = OAuthClients(conf, _base, jwks_info=jwks_info,
                                verify_ssl=args.verify_ssl)

    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": _base})

    kwargs = {'clients': _clients,
              'acrs': conf.ACR_VALUES,
              'server_env': SERVER_ENV,
              'userinfo': conf.USERINFO}
    try:
        kwargs['resource_server'] = conf.RESOURCE_SERVER
    except AttributeError:
        pass

    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(args.port)),
        SessionMiddleware(application, session_opts, **kwargs))

    if conf.BASE.startswith("https"):
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(conf.SERVER_CERT, conf.SERVER_KEY,
                                            conf.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "RP server starting listening on port:%s%s" % (args.port, extra)
    LOGGER.info(txt)
    print(txt)

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
