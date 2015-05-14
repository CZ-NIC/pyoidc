#!/usr/bin/env python
import argparse
from functools import wraps, partial
import json
import mimetypes
import os
import urllib
import urlparse
import errno

import cherrypy
from cherrypy import wsgiserver
from cherrypy.wsgiserver import ssl_pyopenssl
from cherrypy.wsgiserver.wsgiserver2 import WSGIPathInfoDispatcher
from jinja2.environment import Environment
from jinja2.loaders import FileSystemLoader
import yaml

from oic.oauth2 import rndstr
from oic.oic.provider import Provider, AuthorizationEndpoint, TokenEndpoint, \
    UserinfoEndpoint, RegistrationEndpoint, EndSessionEndpoint
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import Redirect, SeeOther, Response, BadRequest, \
    get_or_post, get_post, NotFound
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
from oic.utils.webfinger import OIC_ISSUER, WebFinger
from provider.authn import make_cls_from_name


def VerifierMiddleware(verifier):
    """Common wrapper for the authentication modules.
        * Parses the request before passing it on to the authentication module.
        * Sets 'pyoidc' cookie if authentication succeeds.
        * Redirects the user to complete the authentication.
        * Allows the user to retry authentication if it fails.
    :param verifier: authentication module
    """

    @wraps(verifier.verify)
    def wrapper(environ, start_response):
        data = get_post(environ)
        kwargs = dict(urlparse.parse_qsl(data))
        kwargs["state"] = json.loads(urllib.unquote(kwargs["state"]))
        val, completed = verifier.verify(**kwargs)
        if not completed:
            return val(environ, start_response)
        if val:
            set_cookie, cookie_value = verifier.create_cookie(val, "auth")
            cookie_value += "; path=/"

            url = "{base_url}?{query_string}".format(
                base_url="/authorization",
                query_string=kwargs["state"]["query"])
            response = SeeOther(url, headers=[(set_cookie, cookie_value)])
            return response(environ, start_response)
        else:  # Unsuccessful authentication
            url = "{base_url}?{query_string}".format(
                base_url="/authorization",
                query_string=kwargs["state"]["query"])
            response = SeeOther(url)
            return response(environ, start_response)

    return wrapper


def pyoidcMiddleware(func):
    """Common wrapper for the underlying pyoidc library functions.
    Reads GET params and POST data before passing it on the library and
    converts the response from oic.utils.http_util to wsgi.
    :param func: underlying library function
    """

    def wrapper(environ, start_response):
        data = get_or_post(environ)
        cookies = environ.get("HTTP_COOKIE", "")
        resp = func(request=data, cookie=cookies)
        return resp(environ, start_response)

    return wrapper


def resp2flask(resp):
    """Convert an oic.utils.http_util instance to Flask."""
    if isinstance(resp, Redirect) or isinstance(resp, SeeOther):
        code = int(resp.status.split()[0])
        raise cherrypy.HTTPRedirect(resp.message, code)
    return resp.message, resp.status, resp.headers


def setup_authentication_methods(authn_config, template_env):
    """Add all authentication methods specified in the configuration."""
    routing = {}
    ac = AuthnBroker()
    for authn_method in authn_config:
        cls = make_cls_from_name(authn_method["class"])
        instance = cls(template_env=template_env, **authn_method["kwargs"])
        ac.add(authn_method["acr"], instance)
        routing[instance.url_endpoint] = VerifierMiddleware(instance)

    return ac, routing


def setup_endpoints(provider):
    """Setup the OpenID Connect Provider endpoints."""
    app_routing = {}
    endpoints = [
        AuthorizationEndpoint(
            pyoidcMiddleware(provider.authorization_endpoint)),
        TokenEndpoint(
            pyoidcMiddleware(provider.token_endpoint)),
        UserinfoEndpoint(
            pyoidcMiddleware(provider.userinfo_endpoint)),
        RegistrationEndpoint(
            pyoidcMiddleware(provider.registration_endpoint)),
        EndSessionEndpoint(
            pyoidcMiddleware(provider.endsession_endpoint))
    ]

    for ep in endpoints:
        app_routing["/{}".format(ep.etype)] = ep

    return app_routing


def _webfinger(provider, request, **kwargs):
    """Handle webfinger requests."""
    params = urlparse.parse_qs(request)
    if params["rel"][0] == OIC_ISSUER:
        wf = WebFinger()
        return Response(wf.response(params["resource"][0], provider.baseurl),
                        headers=[("Content-Type", "application/jrd+json")])
    else:
        return BadRequest("Incorrect webfinger.")


def make_static_handler(static_dir):
    def static(environ, start_response):
        path = environ['PATH_INFO']
        full_path = os.path.join(static_dir, os.path.normpath(path).lstrip("/"))

        if os.path.exists(full_path):
            with open(full_path, 'rb') as f:
                content = f.read()

            content_type, encoding = mimetypes.guess_type(full_path)
            headers = [('Content-Type', content_type)]
            start_response("200 OK", headers)
            return [content]
        else:
            response = NotFound(
                "File '{}' not found.".format(environ['PATH_INFO']))
            return response(environ, start_response)

    return static


def main():
    parser = argparse.ArgumentParser(description='Example OIDC Provider.')
    parser.add_argument("-p", "--port", default=80, type=int)
    parser.add_argument("-b", "--base", default="https://localhost", type=str)
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("settings")
    args = parser.parse_args()

    # Load configuration
    with open(args.settings, "r") as f:
        settings = yaml.load(f)

    issuer = args.base.rstrip("/")

    template_dirs = settings["server"].get("template_dirs", "templates")
    jinja_env = Environment(loader=FileSystemLoader(template_dirs))
    authn_broker, auth_routing = setup_authentication_methods(settings["authn"],
                                                              jinja_env)

    # Setup userinfo
    userinfo_conf = settings["userinfo"]
    cls = make_cls_from_name(userinfo_conf["class"])
    i = cls(**userinfo_conf["kwargs"])
    userinfo = UserInfo(i)

    client_db = {}
    provider = Provider(issuer, SessionDB(issuer), client_db, authn_broker,
                        userinfo, AuthzHandling(), verify_client, None)
    provider.baseurl = issuer
    provider.symkey = rndstr(16)

    # Setup keys
    path = os.path.join(os.path.dirname(__file__), "static")
    try:
        os.makedirs(path)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise e
        pass
    jwks = keyjar_init(provider, settings["provider"]["keys"])
    name = "jwks.json"
    with open(os.path.join(path, name), "w") as f:
        f.write(json.dumps(jwks))

    provider.jwks_uri.append(
        "{}/static/{}".format(provider.baseurl, name))

    # Mount the WSGI callable object (app) on the root directory
    app_routing = setup_endpoints(provider)
    app_routing["/.well-known/openid-configuration"] = pyoidcMiddleware(
        provider.providerinfo_endpoint)
    app_routing["/.well-known/webfinger"] = pyoidcMiddleware(
        partial(_webfinger, provider))
    routing = dict(auth_routing.items() + app_routing.items())
    routing["/static"] = make_static_handler(path)
    dispatcher = WSGIPathInfoDispatcher(routing)
    server = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port), dispatcher)

    # Setup SSL
    if provider.baseurl.startswith("https://"):
        server.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            settings["server"]["cert"], settings["server"]["key"],
            settings["server"]["cert_chain"])

    # Start the CherryPy WSGI web server
    try:
        print("Server started: {}".format(issuer))
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()