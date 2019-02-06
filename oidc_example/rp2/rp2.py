#!/usr/bin/env python
from urllib.parse import parse_qs
from urllib.parse import urlencode

import base64
import hashlib
import logging
import uuid

import requests
from beaker.middleware import SessionMiddleware
from cherrypy import wsgiserver
from jwkest.jws import alg2keytype
from mako.lookup import TemplateLookup

from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from oic.utils.http_util import SeeOther
from oic.utils.http_util import ServiceError

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
RP = None


def setup_server_env(conf):
    global SERVER_ENV

    SERVER_ENV = dict([(k, v) for k, v in conf.__dict__.items()
                       if not k.startswith("__")])
    SERVER_ENV["template_lookup"] = LOOKUP
    SERVER_ENV["base_url"] = conf.BASE
    #SERVER_ENV["CACHE"] = {}
    SERVER_ENV["OIC_CLIENT"] = {}


class Httpd(object):
    def http_request(self, url):
        return requests.get(url, verify=False)


class Session(object):
    def __init__(self, session):
        self.session = session

    def __getitem__(self, item):
        if item == 'state':
            return uuid.uuid4().urn

        try:
            return self.session[item]
        except KeyError:
            return None

    def __setitem__(self, key, value):
        self.session[key] = value

    def clear(self):
        for key in list(self.session.keys()):
            del self.session[key]

    def get_acr_value(self, key):
        try:
            self.session["acr_value"][key]
        except KeyError:
            return None

    def set_acr_value(self, key, val):
        try:
            self.session['acr_value'][key] = val
        except KeyError:
            self.session['acr_value'] = {key: val}


#noinspection PyUnresolvedReferences
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


def opbyuid(environ, start_response):
    resp = Response(mako_template="opbyuid.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
    }
    return resp(environ, start_response, **argv)


def post_logout(environ, start_response):
    resp = Response(mako_template="post_logout.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {}
    return resp(environ, start_response, **argv)


def choose_acr_value(environ, start_response, session):
    resp = Response(mako_template="acrvalue.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "acrvalues": session['acr_values']
    }
    return resp(environ, start_response, **argv)


def id_token_as_signed_jwt(client, alg="RS256"):
    if alg.startswith("HS"):
        ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    else:
        ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = client.id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


def application(environ, start_response):
    session = Session(environ['beaker.session'])

    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    query = parse_qs(environ["QUERY_STRING"])

    if path == "logout":
        try:
            logoutUrl = session['client'].end_session_endpoint
            plru = "{}post_logout".format(SERVER_ENV["base_url"])
            logoutUrl += "?" + urlencode({"post_logout_redirect_uri": plru})
            try:
                logoutUrl += "&" + urlencode({
                    "id_token_hint": id_token_as_signed_jwt(
                        session['client'], "HS256")})
            except AttributeError as err:
                pass
            session.clear()
            resp = SeeOther(str(logoutUrl))
            return resp(environ, start_response)
        except Exception as err:
            pass

    if path == "post_logout":
        return post_logout(environ, start_response)

    if session['callback']:
        _uri = "%s%s" % (conf.BASE, path)
        for _cli in SERVER_ENV["OIC_CLIENT"].values():
            if _uri in _cli.redirect_uris:
                session['callback'] = False
                func = getattr(RP, "callback")
                return func(environ, SERVER_ENV, start_response, query, session)

    if path == "rpAcr":
        return choose_acr_value(environ, start_response, session)

    if path == "rpAuth":
    # Only called if multiple arc_values (that is authentications) exists.
        if "acr" in query and query["acr"][0] in session['acr_values']:
            func = getattr(RP, "create_authnrequest")
            return func(environ, SERVER_ENV, start_response, session,
                        query["acr"][0])

    if session["client"] is not None:
        session['callback'] = True
        func = getattr(RP, "begin")
        return func(environ, SERVER_ENV, start_response, session, "")

    if path == "rp":
        if "uid" in query:
            try:
                link = RP.find_srv_discovery_url(resource=query["uid"][0])
            except requests.ConnectionError:
                resp = ServiceError("Webfinger lookup failed, connection error")
                return resp(environ, start_response)

            RP.srv_discovery_url = link
            md5 = hashlib.md5()
            md5.update(link.encode("utf-8"))
            opkey = base64.b16encode(md5.digest()).decode("utf-8")
            session['callback'] = True
            func = getattr(RP, "begin")
            return func(environ, SERVER_ENV, start_response, session, opkey)

    return opbyuid(environ, start_response)


if __name__ == '__main__':
    from oidc import OpenIDConnect
    import conf

    setup_server_env(conf)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    RP = OpenIDConnect(registration_info=conf.ME,
                       ca_bundle=conf.CA_BUNDLE)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', conf.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    if conf.BASE.startswith("https"):
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(conf.SERVER_CERT, conf.SERVER_KEY, conf.CA_BUNDLE)

    LOGGER.info("RP server starting listening on port:%s" % conf.PORT)
    print ("RP server starting listening on port:%s" % conf.PORT)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
