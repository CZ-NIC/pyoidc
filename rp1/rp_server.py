import urllib
import uuid
from jwkest.jws import alg2keytype
from rp1 import rp_conf
from rp1.pyoidc import pyoidcOIC
from cherrypy import wsgiserver
import logging
from logging.handlers import BufferingHandler
from oic.utils.http_util import NotFound
from oic.utils.http_util import Redirect
from saml2.httputil import Response
from mako.lookup import TemplateLookup
from urlparse import parse_qs
from oic.utils.webfinger import URINormalizer
from oic.utils.webfinger import WebFinger
import requests
import hashlib
import base64
#https://pypi.python.org/pypi/Beaker
from beaker.middleware import SessionMiddleware

__author__ = 'haho0032'

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

_formatter = logging.Formatter(CPC)
fil_handl = logging.FileHandler(LOGFILE_NAME)
fil_handl.setFormatter(_formatter)

buf_handl = BufferingHandler(10000)
buf_handl.setFormatter(_formatter)

LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

SERVER_ENV = {}


def setup_server_env(rp_conf):
    global SERVER_ENV
    global logger
    #noinspection PyUnboundLocalVariable
    SERVER_ENV = dict([(k, v) for k, v in rp_conf.__dict__.items()
                       if not k.startswith("__")])
    SERVER_ENV["service"] = rp_conf.SERVICE
    SERVER_ENV["template_lookup"] = LOOKUP
    SERVER_ENV["base_url"] = rp_conf.BASE
    #SERVER_ENV["CACHE"] = {}
    SERVER_ENV["OIC_CLIENT"] = {}


class Httpd(object):
    def http_request(self, url):
        return requests.get(url, verify=False)


class RpSession(object):
    def __init__(self, session):
        self.session = session
        self.get_callback()
        self.get_state()
        self.get_service()
        self.get_nonce()
        self.get_client()
        self.get_acrvalues()

    def clear_session(self):
        for key in self.session:
            self.session.pop(key, None)
        self.session.invalidate()

    def get_callback(self):
        return self.session.get("callback", False)

    def set_callback(self, value):
        self.session["callback"] = value

    def get_state(self):
        return self.session.get("state", uuid.uuid4().urn)

    def set_state(self, value):
        self.session["state"] = value

    def get_service(self):
        return self.session.get("service", None)

    def set_service(self, value):
        self.session["service"] = value

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

    def get_acrvalues(self):
        return self.session.get("acrvalues", None)

    def set_acrvalues(self, value):
        self.session["acrvalues"] = value

    def get_acrvalue(self, server):
        return self.session.get(server+"ACR_VALUE", None)

    def set_acrvalue(self, server, acr):
        self.session[server+"ACR_VALUE"] = acr


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


def start(environ, start_response):
    resp = Response(mako_template="start.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "service": rp_conf.SERVICE
    }
    return resp(environ, start_response, **argv)


def oplist(environ, start_response):
    resp = Response(mako_template="oplist.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "service": rp_conf.SERVICE
    }
    return resp(environ, start_response, **argv)


def about(environ, start_response):
    resp = Response(mako_template="about.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
    }
    return resp(environ, start_response, **argv)


def opbyuid(environ, start_response):
    resp = Response(mako_template="opbyuid.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
    }
    return resp(environ, start_response, **argv)


def choose_acrvalue(environ, start_response, session, key):
    resp = Response(mako_template="acrvalue.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "acrvalues": session.get_acrvalues(),
        "key": key
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
    session = environ['beaker.session']
    rpsession = RpSession(session)

    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    query = parse_qs(environ["QUERY_STRING"])

    if path == "logout":
        try:
            arc_value = rpsession.get_acrvalue(rpsession.get_client().authorization_endpoint)
            logouturl = rpsession.get_client().endsession_endpoint
            logouturl += "?" + urllib.urlencode({"post_logout_redirect_uri": SERVER_ENV["base_url"],
                                                 "acr_values": arc_value})
            try:
                logouturl += "&" + urllib.urlencode({"id_token_hint": id_token_as_signed_jwt(rpsession.get_client(),
                                                                                             "HS256")})
            except:
                pass
            rpsession.clear_session()
            resp = Redirect(str(logouturl))
            return resp(environ, start_response)
        except:
            pass

    if rpsession.get_callback():
        for key, _dict in rp_conf.SERVICE.items():
            if "opKey" in _dict and _dict["opKey"] == path:
                rpsession.set_callback(False)
                func = getattr(rp_conf.SERVICE[key]["instance"], "callback")
                return func(environ, SERVER_ENV, start_response, query, rpsession)

    if path == "rpAcr" and "key" in query and query["key"][0] in rp_conf.SERVICE:
        return choose_acrvalue(environ, start_response, rpsession, query["key"][0])
    #Only called if multiple arc_values (that is authentications) exists.
    if path == "rpAuth":
        if "acr" in query and query["acr"][0] in rpsession.get_acrvalues() \
                and "key" in query and query["key"][0] in rp_conf.SERVICE:
            func = getattr(rp_conf.SERVICE[query["key"][0]]["instance"], "create_authnrequest")
            rpsession.set_acrvalue(rpsession.get_client().authorization_endpoint, query["acr"][0])
            return func(environ, SERVER_ENV, start_response, rpsession, query["acr"][0])

    if rpsession.get_client() is not None:
        rpsession.set_callback(True)
        func = getattr(rp_conf.SERVICE[rpsession.get_service()]["instance"], "begin")
        return func(environ, SERVER_ENV, start_response, rpsession)

    if path == "rp":
        if "key" in query:
            print "key"
            key = query["key"][0]
            if key in rp_conf.SERVICE:
                rpsession.set_callback(True)
                func = getattr(rp_conf.SERVICE[key]["instance"], "begin")
                return func(environ, SERVER_ENV, start_response, rpsession)

        if "uid" in query:
            print "uid"
            _val = URINormalizer().normalize(query["uid"][0])
            wf = WebFinger(httpd=Httpd())
            link = wf.discovery_query(resource=_val)
            #requests.get(url, verify=True)
            md5 = hashlib.md5()
            md5.update(link)
            opkey = base64.b16encode(md5.digest())
            kwargs = {'opKey': opkey,
                      'description': 'OIDC server with discovery url: ' + link,
                      'class': pyoidcOIC,
                      'srv_discovery_url': link,
                      'scope': ["openid", "profile", "email", "address",
                                "phone"],
                      'name': link}
            rp_conf.SERVICE[opkey] = kwargs
            rp_conf.SERVICE[opkey]["instance"] = pyoidcOIC(None, None, **kwargs)
            rpsession.set_callback(True)
            func = getattr(rp_conf.SERVICE[opkey]["instance"], "begin")
            return func(environ, SERVER_ENV, start_response, rpsession)

    if path == "opbyuid":
        return opbyuid(environ, start_response)
    if path == "oplist":
        return oplist(environ, start_response)
    if path == "about":
        return about(environ, start_response)

    return start(environ, start_response)


if __name__ == '__main__':
    setup_server_env(rp_conf)
    print "Starting test rp with configuration:"
    for key, _dict in rp_conf.SERVICE.items():
        _dict["instance"] = _dict["class"](**_dict)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', rp_conf.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    LOGGER.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print "RP server starting listening on port:%s" % rp_conf.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
