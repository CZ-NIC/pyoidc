import json
from http.cookies import SimpleCookie

import cherrypy
import cherrypy_cors
import logging

from future.backports.urllib.parse import urlparse

from jwkest import as_bytes
from jwkest import as_unicode

from oic.oauth2 import Message, ErrorResponse
from oic.utils.http_util import Response

logger = logging.getLogger(__name__)


def handle_error():
    cherrypy.response.status = 500
    cherrypy.response.body = [
        "<html><body>Sorry, an error occured</body></html>"
    ]


def conv_response(resp):
    if not isinstance(resp, Response):
        return as_bytes(resp)

    cookie = cherrypy.response.cookie
    for header, value in resp.headers:
        if header == 'Set-Cookie':
            cookie_obj = SimpleCookie(value)
            for name in cookie_obj:
                morsel = cookie_obj[name]
                cookie[name] = morsel.value
                for key in ['expires', 'path', 'comment', 'domain', 'max-age',
                            'secure', 'version']:
                    if morsel[key]:
                        cookie[name][key] = morsel[key]

    _stat = int(resp._status.split(' ')[0])
    #  if self.mako_lookup and self.mako_template:
    #    argv["message"] = message
    #    mte = self.mako_lookup.get_template(self.mako_template)
    #    return [mte.render(**argv)]
    if _stat < 300:
        cherrypy.response.status = _stat
        for key, val in resp.headers:
            cherrypy.response.headers[key] = val
        return as_bytes(resp.message)
    elif 300 <= _stat < 400:
        raise cherrypy.HTTPRedirect(resp.message, status=_stat)
    else:
        raise cherrypy.HTTPError(_stat, message=resp.message)


def parse_resource(resource):
    p = urlparse(resource)
    if p[0] == 'acct':
        loc, dom = p[2].split('@')  # Should I check the domain part ?
        return loc.split('.')
    elif p[0] in ['http', 'https']:
        return p[2][1:].split('/')  # skip leading '/'
    else:
        return None


class WebFinger(object):
    def __init__(self, srv):
        self.srv = srv

    @cherrypy.expose
    def index(self, resource, rel):
        logger.debug('webfinger request: res={}, rel={}'.format(resource, rel))

        if rel != 'http://openid.net/specs/connect/1.0/issuer':
            logger.error('unknown rel')
            try:
                op_id, test_id = parse_resource(resource)
            except (ValueError, TypeError):
                logger.error('webfinger resource specification faulty')
                raise cherrypy.HTTPError(
                    400, 'webfinger resource specification faulty')

            raise cherrypy.NotFound()

        try:
            op_id, test_id = parse_resource(resource)
        except (ValueError, TypeError):
            logger.error('webfinger resource specification faulty')
            raise cherrypy.HTTPError(
                400, 'webfinger resource specification faulty')
        else:
            _path = '/'.join([op_id, test_id])

        cnf = cherrypy.request.config
        subj = resource
        _base = cnf['base_url']

        # introducing an error
        if 'rp-discovery-webfinger-http-href' in resource:
            _base = _base.replace('https', 'http')

        if _base.endswith('/'):
            href = '{}{}'.format(_base, _path)
        else:
            href = '{}/{}'.format(_base, _path)

        return self.srv.response(subj, href)


class Configuration(object):
    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(
        methods=["GET", "OPTIONS"])
    def index(self, op):
        if cherrypy.request.method == "OPTIONS":
            logger.debug('Request headers: {}'.format(cherrypy.request.headers))
            cherrypy_cors.preflight(
                allowed_methods=["GET"],
                allowed_headers=['Authorization', 'content-type'],
                allow_credentials=True, origins='*'
            )
        else:
            logger.debug('ProviderInfo request')
            resp = op.providerinfo_endpoint()
            # cherrypy.response.headers['Content-Type'] = 'application/json'
            # return as_bytes(resp.message)
            return conv_response(resp)


class Token(object):
    _cp_config = {"request.methods_with_bodies": ("POST", "PUT")}

    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(
        methods=["POST", "OPTIONS"])
    def index(self, op, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            cherrypy_cors.preflight(
                allowed_methods=["POST"], origins='*',
                allowed_headers=['Authorization', 'content-type'])
        else:
            logger.debug('AccessTokenRequest')
            try:
                authn = cherrypy.request.headers['Authorization']
            except KeyError:
                authn = None
            logger.debug('Authorization: {}'.format(authn))
            resp = op.token_endpoint(as_unicode(kwargs), authn, 'dict')
            return conv_response(resp)


class UserInfo(object):
    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(
        methods=["GET", "POST", "OPTIONS"])
    def index(self, op, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            cherrypy_cors.preflight(
                allowed_methods=["GET", "POST"], origins='*',
                allowed_headers=['Authorization', 'content-type'])
        else:
            logger.debug('UserinfoRequest')
            if cherrypy.request.process_request_body is True:
                args = {'request': cherrypy.request.body.read()}
            else:
                args = {}
            try:
                args['authn'] = cherrypy.request.headers['Authorization']
            except KeyError:
                pass

            kwargs.update(args)
            resp = op.userinfo_endpoint(**kwargs)
            return conv_response(resp)


class Claims(object):
    @cherrypy.expose
    def index(self, op, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            cherrypy_cors.preflight(
                allowed_methods=["GET"], origins='*',
                allowed_headers='Authorization')
        else:
            try:
                authz = cherrypy.request.headers['Authorization']
            except KeyError:
                authz = None
            try:
                assert authz.startswith("Bearer")
            except AssertionError:
                logger.error("Bad authorization token")
                cherrypy.HTTPError(400, "Bad authorization token")

            tok = authz[7:]
            try:
                _claims = op.claim_access_token[tok]
            except KeyError:
                logger.error("Bad authorization token")
                cherrypy.HTTPError(400, "Bad authorization token")
            else:
                # one time token
                del op.claim_access_token[tok]
                _info = Message(**_claims)
                jwt_key = op.keyjar.get_signing_key()
                logger.error(_info.to_dict())
                cherrypy.response.headers["content-type"] = 'application/jwt'
                return as_bytes(_info.to_jwt(key=jwt_key, algorithm="RS256"))


class Root(object):
    @cherrypy.expose
    def index(self):
        response = [
            '<html><head>',
            '<title>My OpenID Connect Provider</title>',
            '<link rel="stylesheet" type="text/css" href="/static/theme.css">'
            '</head><body>'
            "<h1>Welcome to my OpenID Connect Provider</h1>",
            '</body></html>'
        ]
        return '\n'.join(response)


class Provider(Root):
    _cp_config = {'request.error_response': handle_error}

    def __init__(self, op, static_dir=None):
        self.op = op
        self.configuration = Configuration()
        self.static_dir = static_dir or ['static']

    def _cp_dispatch(self, vpath):
        # Only get here if vpath != None
        ent = cherrypy.request.remote.ip
        logger.info('ent:{}, vpath: {}'.format(ent, vpath))

        if vpath[0] in self.static_dir:
            return self
        elif len(vpath) == 2:
            a = vpath.pop(0)
            b = vpath.pop(0)
            endpoint = '{}/{}'.format(a, b)
            if endpoint == ".well-known/openid-configuration":
                cherrypy.request.params['op'] = self.op
                return self.configuration

        return self

    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(methods=["POST", "OPTIONS"])
    def registration(self, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            logger.debug('Request headers: {}'.format(cherrypy.request.headers))
            cherrypy_cors.preflight(
                allowed_methods=["POST"], origins='*',
                allowed_headers=['Authorization', 'content-type'])
        else:
            logger.debug('ClientRegistration request')
            if cherrypy.request.process_request_body is True:
                _request = cherrypy.request.body.read()
            else:
                raise cherrypy.HTTPError(400,
                                         'Missing Client registration body')
            logger.debug('request_body: {}'.format(_request))
            resp = self.op.registration_endpoint(as_unicode(_request))
            return conv_response(resp)

    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(
        methods=["GET", "OPTIONS"])
    def authorization(self, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            cherrypy_cors.preflight(
                allowed_methods=["GET"], origins='*',
                allowed_headers=['Authorization', 'content-type'])
        else:
            logger.debug('AuthorizationRequest')
            try:
                args = {'cookie': cherrypy.request.headers['Cookie']}
            except KeyError:
                args = {}

            try:
                _claims = json.loads(kwargs['claims'])
            except json.JSONDecodeError:
                try:
                    _claims = json.loads(
                        kwargs['claims'].replace("\'", '"').replace('True',
                                                                    'true'))
                except json.JSONDecodeError:
                    _err = ErrorResponse(
                        error="invalid_request",
                        error_description="Invalid claims value"
                    )
                    raise cherrypy.HTTPError(400, as_bytes(_err.to_json()))
                else:
                    kwargs['claims'] = _claims
            except KeyError:
                pass
            else:
                kwargs['claims'] = _claims

            try:
                resp = self.op.authorization_endpoint(kwargs, **args)
            except Exception as err:
                raise cherrypy.HTTPError(message=err)
            else:
                return conv_response(resp)

    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(
        methods=["POST", "GET", "OPTIONS"])
    def verify(self, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            cherrypy_cors.preflight(
                allowed_methods=["POST", "GET"], origins='*',
                allowed_headers=['Authorization', 'content-type'])
        else:
            logger.debug('AuthorizationRequest')
            resp, state = self.op.verify_endpoint(kwargs)
            return conv_response(resp)

    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(
        methods=["POST", "OPTIONS"])
    def token(self, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            cherrypy_cors.preflight(
                allowed_methods=["POST"], origins='*',
                allowed_headers=['Authorization', 'content-type'])
        else:
            logger.debug('AccessTokenRequest')
            try:
                authn = cherrypy.request.headers['Authorization']
            except KeyError:
                authn = None
            logger.debug('Authorization: {}'.format(authn))
            resp = self.op.token_endpoint(kwargs, authn, 'dict')
            return conv_response(resp)

    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(
        methods=["GET", "POST", "OPTIONS"])
    def userinfo(self, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            cherrypy_cors.preflight(
                allowed_methods=["GET", "POST"], origins='*',
                allowed_headers=['Authorization', 'content-type'])
        else:
            logger.debug('UserinfoRequest')
            args = {}
            if cherrypy.request.process_request_body is True:
                _req = cherrypy.request.body.read()
                if _req:
                    args = {'request': _req}

            try:
                args['authn'] = cherrypy.request.headers['Authorization']
            except KeyError:
                pass

            kwargs.update(args)
            resp = self.op.userinfo_endpoint(**kwargs)
            return conv_response(resp)

    @cherrypy.expose
    @cherrypy_cors.tools.expose_public()
    @cherrypy.tools.allow(
        methods=["GET", "OPTIONS"])
    def claims(self, **kwargs):
        if cherrypy.request.method == "OPTIONS":
            cherrypy_cors.preflight(
                allowed_methods=["GET"], origins='*',
                allowed_headers='Authorization')
        else:
            try:
                authz = cherrypy.request.headers['Authorization']
            except KeyError:
                authz = None
            try:
                assert authz.startswith("Bearer")
            except AssertionError:
                logger.error("Bad authorization token")
                cherrypy.HTTPError(400, "Bad authorization token")

            tok = authz[7:]
            try:
                _claims = self.op.claim_access_token[tok]
            except KeyError:
                logger.error("Bad authorization token")
                cherrypy.HTTPError(400, "Bad authorization token")
            else:
                # one time token
                del self.op.claim_access_token[tok]
                _info = Message(**_claims)
                jwt_key = self.op.keyjar.get_signing_key()
                logger.error(_info.to_dict())
                cherrypy.response.headers["content-type"] = 'application/jwt'
                return as_bytes(_info.to_jwt(key=jwt_key, algorithm="RS256"))
