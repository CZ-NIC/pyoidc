import uuid
import requests
import hashlib
import base64

from beaker.middleware import SessionMiddleware
from cherrypy import wsgiserver
from mako.lookup import TemplateLookup
from urlparse import parse_qs

from oic.utils.http_util import NotFound, Response, ServiceError
from oidc import OpenIDConnect

import rp_conf

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


def setup_server_env(rp_conf):
    global SERVER_ENV
    global logger

    SERVER_ENV = dict([(k, v) for k, v in rp_conf.__dict__.items()
                       if not k.startswith("__")])
    SERVER_ENV["template_lookup"] = LOOKUP
    SERVER_ENV["base_url"] = rp_conf.BASE
    #SERVER_ENV["CACHE"] = {}
    SERVER_ENV["OIC_CLIENT"] = {}


class Httpd(object):
    def http_request(self, url):
        return requests.get(url, verify=False)


class Session(object):
    def __init__(self, session):
        self.session = session
        self.getState()
        self.getNonce()
        self.getClient()
        self.getAcrvalues()

    def getState(self):
        return self.session.get("state", uuid.uuid4().urn)

    def setState(self, value):
        self.session["state"] = value

    def getNonce(self):
        return self.session.get("nonce", None)

    def setNonce(self, value):
        self.session["nonce"] = value

    def getClient(self):
        return self.session.get("client", None)

    def setClient(self, value):
        self.session["client"] = value

    def getProvider(self):
        return self.session.get("provider", None)

    def setProvider(self, value):
        self.session["provider"] = value

    def getAcrvalues(self):
        return self.session.get("acrvalues", None)

    def setAcrvalues(self, value):
        self.session["acrvalues"] = value

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


def chooseAcrValue(environ, start_response, session):
    resp = Response(mako_template="acrvalue.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "acrvalues": session.getAcrvalues()
    }
    return resp(environ, start_response, **argv)


def application(environ, start_response):
    session = Session(environ['beaker.session'])

    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    query = parse_qs(environ["QUERY_STRING"])
    _uri = "%s%s" % (rp_conf.BASE, path)
    for _cli in SERVER_ENV["OIC_CLIENT"].values():
        if _uri in _cli.redirect_uris:
            func = getattr(RP, "callback")
            return func(environ, SERVER_ENV, start_response, query, session)

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
            func = getattr(RP, "begin")
            return func(environ, SERVER_ENV, start_response, session, opkey)

    if path == "rpAcr":
        return chooseAcrValue(environ, start_response, session)

    if path == "rpAuth":
    #Only called if multiple arc_values (that is authentications) exists.
        if "acr" in query and query["acr"][0] in session.getAcrvalues():
            func = getattr(RP, "create_authnrequest")
            return func(environ, SERVER_ENV, start_response, session,
                        query["acr"][0])

    return opbyuid(environ, start_response)


if __name__ == '__main__':
    setup_server_env(rp_conf)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    RP = OpenIDConnect(registration_info=rp_conf.ME,
                       ca_bundle=rp_conf.CA_BUNDLE)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', rp_conf.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    if rp_conf.BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            rp_conf.SERVER_CERT, rp_conf.SERVER_KEY, rp_conf.CA_BUNDLE)

    LOGGER.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print "RP server starting listening on port:%s" % rp_conf.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
