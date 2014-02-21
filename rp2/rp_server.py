#!/usr/bin/env python
import urllib
import uuid
import requests
import hashlib
import base64
from jwkest.jws import alg2keytype
from beaker.middleware import SessionMiddleware
from cherrypy import wsgiserver
from mako.lookup import TemplateLookup
from urlparse import parse_qs

from oic.utils.http_util import NotFound, Response, ServiceError, Redirect
from oidc import OpenIDConnect

import conf

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
RP = None


def setup_server_env(conf):
    global SERVER_ENV
    global logger

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
        self.get_callback()
        self.get_state()
        self.get_nonce()
        self.get_client()
        self.get_acrvalues()
        self.get_accesstoken()
        self.get_key()

    def clear_session(self):
        for key in self.session:
            self.session.pop(key, None)
        self.session.invalidate()

    def get_key(self):
        return self.session.get("key", None)

    def set_key(self, value):
        self.session["key"] = value

    def get_accesstoken(self):
        return self.session.get("Accesstoken", None)

    def set_accesstoken(self, value):
        self.session["Accesstoken"] = value

    def get_callback(self):
        return self.session.get("callback", False)

    def set_callback(self, value):
        self.session["callback"] = value

    def get_state(self):
        return self.session.get("state", uuid.uuid4().urn)

    def set_state(self, value):
        self.session["state"] = value

    def get_nonce(self):
        return self.session.get("nonce", None)

    def set_nonce(self, value):
        self.session["nonce"] = value

    def get_client(self):
        return self.session.get("client", None)

    def set_client(self, value):
        self.session["client"] = value

    def get_login(self):
        return self.session.get("login", None)

    def set_login(self, value):
        self.session["login"] = value

    def get_provider(self):
        return self.session.get("provider", None)

    def set_provider(self, value):
        self.session["provider"] = value

    def get_acrvalues(self):
        return self.session.get("acrvalues", None)

    def set_acrvalues(self, value):
        self.session["acrvalues"] = value

    def get_acrvalue(self, server):
        return self.session.get(server + "ACR_VALUE", None)

    def set_acrvalue(self, server, acr):
        self.session[server + "ACR_VALUE"] = acr


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


def opbyuid(environ, start_response):
    resp = Response(mako_template="opbyuid.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
    }
    return resp(environ, start_response, **argv)


def choose_acrvalue(environ, start_response, session):
    resp = Response(mako_template="acrvalue.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "acrvalues": session.get_acrvalues()
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

            arc_value = session.get_acrvalue(session.get_client().authorization_endpoint)

            logouturl = session.get_client().endsession_endpoint
            logouturl += "?" + urllib.urlencode(
                {"post_logout_redirect_uri": SERVER_ENV["base_url"], "acr_values": arc_value})
            try:
                logouturl += "&" + urllib.urlencode({
                    "id_token_hint": id_token_as_signed_jwt(
                        session.get_client(), "HS256")})
            except:
                pass
            SERVER_ENV["OIC_CLIENT"].pop(session.get_key(), None)
            session.clear_session()
            resp = Redirect(str(logouturl))
            return resp(environ, start_response)
        except:
            pass

    if session.get_callback():
        _uri = "%s%s" % (conf.BASE, path)
        for _cli in SERVER_ENV["OIC_CLIENT"].values():
            if _uri in _cli.redirect_uris:
                session.set_callback(False)
                func = getattr(RP, "callback")
                return func(environ, SERVER_ENV, start_response, query, session)

    if path == "rpAcr":
        return choose_acrvalue(environ, start_response, session)

    if path == "rpAuth":
    # Only called if multiple arc_values (that is authentications) exists.
        if "acr" in query and query["acr"][0] in session.get_acrvalues():
            func = getattr(RP, "create_authnrequest")
            return func(environ, SERVER_ENV, start_response, session,
                        query["acr"][0])

    if path == "updateUserInfo":
        func = getattr(RP, "updateUserInfo")
        return func(environ, SERVER_ENV, start_response, session, session.get_key())

    if session.get_client() is not None:
        session.set_callback(True)
        func = getattr(RP, "begin")
        return func(environ, SERVER_ENV, start_response, session, session.get_key())

    if path == "rp":
        if "uid" in query:
            try:
                link = RP.find_srv_discovery_url(resource=query["uid"][0])
            except requests.ConnectionError:
                resp = ServiceError("Webfinger lookup failed, connection error")
                return resp(environ, start_response)

            RP.srv_discovery_url = link
            md5 = hashlib.md5()
            md5.update(link)
            opkey = base64.b16encode(md5.digest())
            session.set_callback(True)
            session.set_key(opkey)
            func = getattr(RP, "begin")
            return func(environ, SERVER_ENV, start_response, session, opkey)

    return opbyuid(environ, start_response)


if __name__ == '__main__':
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
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            conf.SERVER_CERT, conf.SERVER_KEY, conf.CA_BUNDLE)

    LOGGER.info("RP server starting listening on port:%s" % conf.PORT)
    print "RP server starting listening on port:%s" % conf.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
