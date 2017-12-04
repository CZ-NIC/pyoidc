#!/usr/bin/env python
__author__ = 'Vahid Jalili'

from future.backports.urllib.parse import parse_qs

import json
import os
import re
import sys
import traceback
import argparse
import importlib
from mako.lookup import TemplateLookup

from oic import rndstr

from oic.oic.provider import AuthorizationEndpoint
from oic.oic.provider import EndSessionEndpoint
from oic.oic.provider import Provider
from oic.oic.provider import RegistrationEndpoint
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import UserinfoEndpoint
from oic.utils import shelve_wrapper
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.authn_context import make_auth_verify
from oic.utils.authn.client import verify_client
from oic.utils.authn.multi_auth import AuthnIndexedEndpointWrapper
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import *
from oic.utils.keyio import keyjar_init
from oic.utils.userinfo import UserInfo
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import WebFinger


from cherrypy import wsgiserver
from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

from oic.utils.sdb import create_session_db



LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oc.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = ('%(asctime)s %(name)s:%(levelname)s '
       '[%(client)s,%(path)s,%(cid)s] %(message)s')
cpc_formatter = logging.Formatter(CPC)

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

logger = logging.getLogger('oicServer')


def static_file(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False


# noinspection PyUnresolvedReferences
def static(self, environ, start_response, path):
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


def check_session_iframe(self, environ, start_response, logger):
    return static(self, environ, start_response, "htdocs/op_session_iframe.html")


def key_rollover(self, environ, start_response, _):
    # expects a post containing the necessary information
    _txt = get_post(environ)
    _jwks = json.loads(_txt)
    # logger.info("Key rollover to")
    provider.do_key_rollover(_jwks, "key_%d_%%d" % int(time.time()))
    # Dump to file
    f = open(jwksFileName, "w")
    f.write(json.dumps(provider.keyjar.export_jwks()))
    f.close()
    resp = Response("OK")
    return resp(environ, start_response)


def clear_keys(self, environ, start_response, _):
    provider.remove_inactive_keys()
    resp = Response("OK")
    return resp(environ, start_response)


class Application(object):
    def __init__(self, provider, urls):
        self.provider = provider

        self.endpoints = [
            AuthorizationEndpoint(self.authorization),
            TokenEndpoint(self.token),
            UserinfoEndpoint(self.userinfo),
            RegistrationEndpoint(self.registration),
            EndSessionEndpoint(self.endsession),
        ]

        self.provider.endp = self.endpoints
        self.urls = urls
        self.urls.extend([
            (r'^.well-known/openid-configuration', self.op_info),
            (r'^.well-known/simple-web-discovery', self.swd_info),
            (r'^.well-known/host-meta.json', self.meta_info),
            (r'^.well-known/webfinger', self.webfinger),
            (r'.+\.css$', self.css),
            (r'safe', self.safe),
            (r'^keyrollover', key_rollover),
            (r'^clearkeys', clear_keys),
            (r'^check_session', check_session_iframe)
        ])

        for endp in self.endpoints:
            self.urls.append(("^%s" % endp.etype, endp.func))

    # noinspection PyUnusedLocal
    def safe(self, environ, start_response):
        _srv = self.provider.server
        _log_info = self.provider.logger.info
        _log_info("- safe -")

        try:
            authz = environ["HTTP_AUTHORIZATION"]
            (typ, code) = authz.split(" ")
            assert typ == "Bearer"
        except KeyError:
            resp = BadRequest("Missing authorization information")
            return resp(environ, start_response)

        try:
            _sinfo = _srv.sdb[code]
        except KeyError:
            resp = Unauthorized("Not authorized")
            return resp(environ, start_response)

        info = "'%s' secrets" % _sinfo["sub"]
        resp = Response(info)
        return resp(environ, start_response)

    # noinspection PyUnusedLocal
    def css(self, environ, start_response):
        try:
            info = open(environ["PATH_INFO"]).read()
            resp = Response(info)
        except (OSError, IOError):
            resp = NotFound(environ["PATH_INFO"])

        return resp(environ, start_response)

    # noinspection PyUnusedLocal
    def token(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.provider.token_endpoint,
                            logger=logger)

    # noinspection PyUnusedLocal
    def authorization(self, environ, start_response):
        return wsgi_wrapper(environ, start_response,
                            self.provider.authorization_endpoint, logger=logger)  # cookies required.

    # noinspection PyUnusedLocal
    def userinfo(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.provider.userinfo_endpoint,
                            logger=logger)

    # noinspection PyUnusedLocal
    def op_info(self, environ, start_response):
        return wsgi_wrapper(environ, start_response,
                            self.provider.providerinfo_endpoint, logger=logger)

    # noinspection PyUnusedLocal
    def registration(self, environ, start_response):
        if environ["REQUEST_METHOD"] == "POST":
            return wsgi_wrapper(environ, start_response,
                                self.provider.registration_endpoint,
                                logger=logger)
        elif environ["REQUEST_METHOD"] == "GET":
            return wsgi_wrapper(environ, start_response,
                                self.provider.read_registration, logger=logger)
        else:
            resp = ServiceError("Method not supported")
            return resp(environ, start_response)

    # noinspection PyUnusedLocal
    def check_id(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.provider.check_id_endpoint,
                            logger=logger)

    # noinspection PyUnusedLocal
    def swd_info(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.provider.discovery_endpoint,
                            logger=logger)

    # noinspection PyUnusedLocal
    def trace_log(self, environ, start_response):
        return wsgi_wrapper(environ, start_response, self.provider.tracelog_endpoint,
                            logger=logger)

    # noinspection PyUnusedLocal
    def endsession(self, environ, start_response):
        return wsgi_wrapper(environ, start_response,
                            self.provider.endsession_endpoint, logger=logger)

    # noinspection PyUnusedLocal
    def meta_info(self, environ, start_response):
        """
        Returns something like this::

             {"links":[
                 {
                    "rel":"http://openid.net/specs/connect/1.0/issuer",
                    "href":"https://openidconnect.info/"
                 }
             ]}

        """
        print '\n in meta-info'
        pass

    def webfinger(self, environ, start_response):
        query = parse_qs(environ["QUERY_STRING"])
        try:
            assert query["rel"] == [OIC_ISSUER]
            resource = query["resource"][0]
        except KeyError:
            resp = BadRequest("Missing parameter in request")
        else:
            wf = WebFinger()
            resp = Response(wf.response(subject=resource,
                                        base=self.provider.baseurl))
        return resp(environ, start_response)

    def application(self, environ, start_response):
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
        path = environ.get('PATH_INFO', '').lstrip('/')

        print 'start_response: ', start_response

        if path == "robots.txt":
            return static(self, environ, start_response, "static/robots.txt")

        environ["oic.oas"] = self.provider
        if path.startswith("static/"):
            return static(self, environ, start_response, path)

        for regex, callback in self.urls:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['oic.url_args'] = match.groups()[0]
                except IndexError:
                    environ['oic.url_args'] = path
                try:
                    return callback(environ, start_response)
                except Exception as err:
                    print("%s" % err)
                    message = traceback.format_exception(*sys.exc_info())
                    print(message)
                    logger.exception("%s" % err)
                    resp = ServiceError("%s" % err)
                    return resp(environ, start_response)

        LOGGER.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")
        return resp(environ, start_response)


if __name__ == '__main__':

    root = './'
    lookup = TemplateLookup(directories=[root + 'Templates', root + 'htdocs'],
                            module_directory=root + 'modules',
                            input_encoding='utf-8', output_encoding='utf-8')

    def mako_renderer(template_name, context):
        mte = lookup.get_template(template_name)
        return mte.render(**context)

    usernamePasswords = {
        "user1": "1",
        "user2": "2"
    }

    passwordEndPointIndex = 0  # what is this, and what does its value mean?

    # JWKS: JSON Web Key
    jwksFileName = "static/jwks.json"

    # parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', dest='config')
    parser.add_argument('-d', dest='debug', action='store_true')
    args = parser.parse_args()

    # parse and setup configuration
    config = importlib.import_module(args.config)
    config.ISSUER = config.ISSUER + ':{}/'.format(config.PORT)
    config.SERVICEURL = config.SERVICEURL.format(issuer=config.ISSUER)
    endPoints = config.AUTHENTICATION["UserPassword"]["EndPoints"]
    fullEndPointsPath = ["%s%s" % (config.ISSUER, ep) for ep in endPoints]

# TODO: why this instantiation happens so early? can I move it later?
    # An OIDC Authorization/Authentication server is designed to
    # allow more than one authentication method to be used by the server.
    # And that is what the AuthBroker is for.
    # Given information about the authorisation request, the AuthBroker
    # chooses which method(s) to be used for authenticating the person/entity.
    # According to the OIDC standard a Relaying Party can say
    # 'I want this type of authentication', and the AuthnBroker tries to pick
    # methods from the set it has been supplied, to map that request.
    authnBroker = AuthnBroker()

    # UsernamePasswordMako: authenticas a user using the username/password form in a
    # WSGI environment using Mako as template system
    usernamePasswordAuthn = UsernamePasswordMako(
        None,                               # server instance
        "login.mako",                       # a mako template
        lookup,                             # lookup template
        usernamePasswords,                  # username/password dictionary-like database
        "%sauthorization" % config.ISSUER,  # where to send the user after authentication
        None,                               # templ_arg_func ??!!
        fullEndPointsPath)                  # verification endpoints

    # AuthnIndexedEndpointWrapper is a wrapper class for using an authentication module with multiple endpoints.
    authnIndexedEndPointWrapper = AuthnIndexedEndpointWrapper(usernamePasswordAuthn, passwordEndPointIndex)

    authnBroker.add(config.AUTHENTICATION["UserPassword"]["ACR"],  # (?!)
           authnIndexedEndPointWrapper,                      # (?!) method: an identifier of the authentication method.
           config.AUTHENTICATION["UserPassword"]["WEIGHT"],  # security level
           "")                                               # (?!) authentication authority

    # ?!
    authz = AuthzHandling()
    clientDB = shelve_wrapper.open(config.CLIENTDB)

    # In-Memory non-persistent SessionDB issuing DefaultTokens
    sessionDB = create_session_db(config.ISSUER,
                                  secret=rndstr(32),
                                  password=rndstr(32))

    provider = Provider(
        name=config.ISSUER,                            # name
        sdb=sessionDB,                                 # session database.
        cdb=clientDB,                                  # client database
        authn_broker=authnBroker,                      # authn broker
        userinfo=None,                                 # user information
        authz=authz,                                   # authz
        client_authn=verify_client,                    # client authentication
        symkey=config.SYM_KEY,                         # Used for Symmetric key authentication
        # urlmap = None,                               # ?
        # keyjar = None,                               # ?
        # hostname = "",                               # ?
        template_renderer=mako_renderer,               # Rendering custom templates
        # verify_ssl = True,                           # Enable SSL certs
        # capabilities = None,                         # ?
        # schema = OpenIDSchema,                       # ?
        # jwks_uri = '',                               # ?
        # jwks_name = '',                              # ?
        baseurl=config.ISSUER,
        # client_cert = None                           # ?
        )

    # SessionDB:
    # This is database where the provider keeps information about
    # the authenticated/authorised users. It includes information
    # such as "what has been asked for (claims, scopes, and etc. )"
    # and "the state of the session". There is one entry in the
    # database per person
    #
    # __________ Note __________
    # provider.keyjar is an interesting parameter,
    # currently it uses default values, but
    # if you have time, it worth investigating.

    for authnIndexedEndPointWrapper in authnBroker:
        authnIndexedEndPointWrapper.srv = provider

    # TODO: this is a point to consider: what if user data in a database?
    if config.USERINFO == "SIMPLE":
        provider.userinfo = UserInfo(config.USERDB)

    provider.cookie_ttl = config.COOKIETTL
    provider.cookie_name = config.COOKIENAME

    if args.debug:
        provider.debug = True

    try:
        # JWK: JSON Web Key
        # JWKS: is a dictionary of JWK
        # __________ NOTE __________
        # JWKS contains private key information.
        #
        # keyjar_init configures cryptographic key
        # based on the provided configuration "keys".
        jwks = keyjar_init(
            provider,             # server/client instance
            config.keys,          # key configuration
            kid_template="op%d")  # template by which to build the kids (key ID parameter)
    except Exception as err:
        # LOGGER.error("Key setup failed: %s" % err)
        provider.key_setup("static", sig={"format": "jwk", "alg": "rsa"})
    else:
        for key in jwks["keys"]:
            for k in key.keys():
                key[k] = as_unicode(key[k])

        f = open(jwksFileName, "w")
        f.write(json.dumps(jwks))
        f.close()
        provider.jwks_uri = "%s%s" % (provider.baseurl, jwksFileName)

    # for b in OAS.keyjar[""]:
    #    LOGGER.info("OC3 server keys: %s" % b)

    # TODO: Questions:
    # END_POINT is defined as a dictionary in the configuration file,
    # why not defining it as string with "verify" value?
    # after all, we have only one end point.
    # can we have multiple end points for password? why?
    endPoint = config.AUTHENTICATION["UserPassword"]["EndPoints"][passwordEndPointIndex]

    _urls = []
    _urls.append((r'^' + endPoint, make_auth_verify(authnIndexedEndPointWrapper.verify)))

    _app = Application(provider, _urls)

    # Setup the web server
    server = wsgiserver.CherryPyWSGIServer(('0.0.0.0', config.PORT), _app.application)
    server.ssl_adapter = BuiltinSSLAdapter(config.SERVER_CERT, config.SERVER_KEY)

    print "OIDC Provider server started (issuer={}, port={})".format(config.ISSUER, config.PORT)

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
