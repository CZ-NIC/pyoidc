#!/usr/bin/env python
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import argparse
import importlib
import json
import logging

from jwkest.jws import alg2keytype
from mako.lookup import TemplateLookup
from requests import ConnectionError
from requests.packages import urllib3

from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from oic.utils.http_util import SeeOther
from oic.utils.http_util import get_post
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


class JLog(object):
    def __init__(self, logger, sid):
        self.logger = logger
        self.id = sid

    def info(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.info(json.dumps(_dict))

    def error(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.error(json.dumps(_dict))

    def warning(self, info):
        _dict = {'id': self.id}
        _dict.update(info)
        self.logger.warning(json.dumps(_dict))


# noinspection PyUnresolvedReferences
def static(environ, start_response, logger, path):
    logger.info("[static]sending: %s" % (path,))

    try:
        data = open(path, 'rb').read()
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
        return [data]
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

    _args = {}
    for param in ['userinfo', 'userid', 'id_token']:
        try:
            _args[param] = kwargs[param]
        except KeyError:
            _args[param] = None

    return resp(environ, start_response, **_args)


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


KEY_MAP = {'state': 'state', 'iss': 'op'}


class Application(object):
    def __init__(self, acrs, clients, conf, userinfo, base, **extra_args):
        self.acr_values = acrs
        self.clients = clients
        self.conf = conf
        self.userinfo = userinfo
        self.base = base
        self.extra_args = extra_args
        self.session = {}

    def find_session(self, **kwargs):
        _f = 0
        _n = 0
        for _ses in self.session.values():
            for key, vals in kwargs.items():
                try:
                    _val = _ses[KEY_MAP[key]]
                except KeyError:
                    pass
                else:
                    _n += 1
                    if _val in vals:
                        _f += 1

            if _f and _f == _n:
                return _ses

        return None

    def init_client(self, client, session, query, environ, start_response):
        client.get_userinfo = self.userinfo
        try:
            client.resource_server = session['resource_server']
        except KeyError:
            pass

        try:
            session['response_format'] = query["response_format"][0]
        except KeyError:
            session['response_format'] = 'html'

        session["op"] = client.provider_info["issuer"]

        try:
            resp = client.create_authn_request(session, self.acr_values)
        except Exception as err:
            logging.error(err)
            raise
        else:
            return resp(environ, start_response)

    def application(self, environ, start_response):
        b_session = environ['beaker.session']

        jlog = JLog(LOGGER, b_session.id)

        path = environ.get('PATH_INFO', '').lstrip('/')
        try:
            jlog.info({'cookie': environ['HTTP_COOKIE'].split(';'),
                       'path': path})
        except KeyError:
            jlog.info({'path': path})

        if path == "robots.txt":
            return static(environ, start_response, LOGGER, "static/robots.txt")
        elif path.startswith("static/"):
            return static(environ, start_response, LOGGER, path)
        elif '/static/' in path:
            pre, post = path.split('static')
            return static(environ, start_response, LOGGER, 'static' + post)

        query = parse_qs(environ["QUERY_STRING"])

        try:
            session = b_session['session_info']
        except KeyError:
            session = self.find_session(**query)
            if session:
                b_session['session_info'] = session
            else:
                session = {}
                b_session['session_info'] = session
                self.session[b_session.id] = session

        if path == '':
            if 'access_token' not in session:
                return opchoice(environ, start_response, self.clients)
            else:
                client = self.clients[session["op"]]
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
                    [(p, session[p]) for p in
                     ['id_token', 'userinfo', 'user_id'] if
                     p in session])

                return opresult(environ, start_response, **kwargs)
        elif path == "rp":  # After having chosen which OP to authenticate at
            if "uid" in query:
                try:
                    client = self.clients.dynamic_client(userid=query["uid"][0])
                except (ConnectionError, OIDCError) as err:
                    return operror(environ, start_response, '{}'.format(err))
            elif 'issuer' in query:
                try:
                    client = self.clients[query["issuer"][0]]
                except (ConnectionError, OIDCError) as err:
                    return operror(environ, start_response, '{}'.format(err))
            else:
                client = self.clients[query["op"][0]]

            return self.init_client(client, session, query, environ,
                                    start_response)
        elif path.endswith('authz_post'):
            try:
                _iss = session['op']
            except KeyError:
                jlog.error({'reason': 'No active session',
                            'remote_addr': environ['REMOTE_ADDR']})

                return opchoice(environ, start_response, self.clients)
            else:
                client = self.clients[_iss]

            query = parse_qs(get_post(environ))
            try:
                info = query["fragment"][0]
            except KeyError:
                return sorry_response(environ, start_response, self.base,
                                      "missing fragment ?!")
            if info == ['x']:
                return sorry_response(environ, start_response, self.base,
                                      "Expected fragment didn't get one ?!")

            jlog.info({'fragment': info})

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
                res = SeeOther(self.conf['base_url'])
                return res(environ, start_response)
        elif path in self.clients.return_paths():  # After having
            # authenticated at the OP
            jlog.info({'query': query})

            _client = None
            for cli in self.clients.client.values():
                if query['state'][0] in cli.authz_req:
                    _client = cli
                    break

            if not _client:
                jlog.error({
                    'reason': 'No active session',
                    'remote_addr': environ['REMOTE_ADDR'],
                    'state': query['state'][0]
                })
                return opchoice(environ, start_response, self.clients)

            if 'error' in query:  # something amiss
                if query['error'][0] == 'access_denied':  # Try reregistering
                    _iss = _client.provider_info['issuer']
                    del self.clients[_iss]
                    try:
                        client = self.clients[_iss]
                    except (ConnectionError, OIDCError) as err:
                        return operror(environ, start_response,
                                       '{}'.format(err))
                    return self.init_client(client, session, query, environ,
                                            start_response)

            try:
                _iss = query['iss'][0]
            except KeyError:
                pass
            else:
                if _iss != _client.provider_info['issuer']:
                    jlog.error({'reason': 'Got response from wrong OP'})
                    return opchoice(environ, start_response, self.clients)

            _response_type = _client.behaviour["response_type"]
            try:
                _response_mode = _client.authz_req[session['state']][
                    'response_mode']
            except KeyError:
                _response_mode = ''

            jlog.info({
                "response_type": _response_type,
                "response_mode": _response_mode})

            if _response_type and _response_type != "code":
                # Fall through if it's a query response anyway
                if query:
                    pass
                elif _response_mode:
                    # form_post encoded
                    pass
                else:
                    return opresult_fragment(environ, start_response)

            try:
                result = _client.callback(query, session)
                if isinstance(result, SeeOther):
                    return result(environ, start_response)
            except OIDCError as err:
                return operror(environ, start_response, "%s" % err)
            except Exception:
                raise
            else:
                session.update(result)
                res = SeeOther(self.conf['base_url'])
                return res(environ, start_response)
        elif path == "logout":  # After the user has pressed the logout button
            try:
                _iss = session['op']
            except KeyError:
                jlog.error(
                    {'reason': 'No active session',
                     'remote_addr': environ['REMOTE_ADDR']})
                return opchoice(environ, start_response, self.clients)
            client = self.clients[_iss]
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
                        "id_token_hint": id_token_as_signed_jwt(client,
                                                                _idtoken,
                                                                "HS256")})
                # Also append the ACR values
                logout_url += "&" + urlencode({"acr_values": self.acr_values},
                                              True)

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
                            self.conf["base_url"]),
                        **kwargs)
        elif path == "session_change":
            try:
                _iss = session['op']
            except KeyError:
                jlog.error({
                    'reason': 'No active session',
                    'remote_addr': environ['REMOTE_ADDR']})
                return opchoice(environ, start_response, self.clients)

            try:
                client = self.clients[_iss]
            except KeyError:
                return Response("No valid session.")(environ, start_response)

            kwargs = {"prompt": "none"}
            # If there is an ID token send it along as a id_token_hint
            idt = get_id_token(client, session)
            if idt:
                kwargs["id_token_hint"] = id_token_as_signed_jwt(client, idt,
                                                                 "HS256")
            resp = client.create_authn_request(session, self.acr_values,
                                               **kwargs)
            return resp(environ, start_response)

        return opchoice(environ, start_response, self.clients)


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
    _conf = importlib.import_module(args.config)

    if args.base_url:
        _conf.BASE = args.base_url

    _base = "{base}:{port}/".format(base=_conf.BASE, port=args.port)
    for _client, client_conf in _conf.CLIENTS.items():
        if "client_registration" in client_conf:
            client_reg = client_conf["client_registration"]
            client_reg["redirect_uris"] = [
                url.format(base=_conf.BASE) for url in
                client_reg["redirect_uris"]]

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(
            urlparse(_conf.BASE).netloc.replace(":", "."))
    }

    try:
        key_spec = _conf.KEY_SPECIFICATION
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
        ctype = _conf.CLIENT_TYPE
    except KeyError:
        ctype = 'OIDC'

    if ctype == 'OIDC':
        _clients = OIDCClients(_conf, _base, jwks_info=jwks_info,
                               verify_ssl=args.verify_ssl)
    else:
        _clients = OAuthClients(_conf, _base, jwks_info=jwks_info,
                                verify_ssl=args.verify_ssl)

    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": _base})

    app_args = {'clients': _clients,
                'acrs': _conf.ACR_VALUES,
                'conf': SERVER_ENV,
                'userinfo': _conf.USERINFO,
                'base': _conf.BASE}
    try:
        app_args['resource_server'] = _conf.RESOURCE_SERVER
    except AttributeError:
        pass

    _app = Application(**app_args)

    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(args.port)),
        SessionMiddleware(_app.application, session_opts))

    if _conf.BASE.startswith("https"):
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(_conf.SERVER_CERT, _conf.SERVER_KEY,
                                            _conf.CERT_CHAIN)
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
