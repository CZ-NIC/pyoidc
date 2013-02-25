#!/usr/bin/env python


from oic.oauth2 import Server as OAuth2Server
from oic.oauth2.provider import Provider

from oic.utils.sdb import SessionDB
from oic.utils.http_util import Response, NotFound

import base64
import logging

from mako import exceptions as mako_exceptions
from mako.lookup import TemplateLookup

from os import path


USERDB = {
        'diana': 'krall'
    }
AUTHORIZATIONS = {
        'diana': 'ALL'
    }
CLIENTS = {
        '42': 'puttefnask'
    }

ROOT = path.relpath(path.join(path.dirname(__file__), '..'))

LOCAL_CHERRY_CONFIG = {
        'request.throw_errors': True,
        '/css': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': path.join(ROOT,'static')
        },
    }

TEMPLATE_DIRS = [
        path.join(ROOT, d) for d in ['oc3/templates', 'oc3/htdocs']
    ]

CLIENT_URL_MAP = {
        '42': 'http://www.google.com/',
        }



logging.addLevelName(5, 'TRACE')
setattr(logging,'TRACE', 5)
def getLogger(*args, **kwargs):
    logger = logging.getLogger(*args, **kwargs)
    logger.trace = lambda msg, *variables: logger._log(5, msg, variables)
    return logger


class DefHash(object):
    def __init__(self, table=None,default=None):
        self._table = table or {}
        self._default = default

    def __getitem__(self, key):
        try:
            return self._table[key]
        except KeyError:
            return self._default

    def __setitem__(self, key, value):
        self._table[key] = value

    def _getdefault(self):
        return self._default
    def _setdefault(self, value):
        self._default = value
    default = property(_getdefault, _setdefault)


class SafeProvider(Provider):

    def token_endpoint(self, environ, start_response):
        try:
            return super(SafeProvider, self).token_endpoint(environ, start_response)
        except AssertionError as err:
            return self._error(environ, start_response,
                            error="unsupported_grant_type",
                            descr="Wrong value for grant_type")


class Dispatcher:
    """ A stupid url-lookup table.

    Gotcha: Uses public member provider of the aplication for all callbacks.
            Application should probably implement thin wrapper-methods for the
            used functionality.
    """

    _logger = getLogger('auth2.server.Dispatcher')

    def __init__(self, application):
        self.provider = application.provider
        self.urls = DefHash({
                '/authenticated': self._is_authenticated,
                '/authorization': self._authorization,
                '/token': self._token,
                }, default=self._error_404)

    def __call__(self, environ, start_response):
        # TODO: Do we need the "handle"?
        self._logger.trace('Getting page for %s',environ['PATH_INFO'])
        self.parse_cookie_data(environ)
        callback = self.urls[environ['PATH_INFO']]
        result = callback(environ, start_response)
        return result


    def _authorization(self, environ, start_response):
        return self.provider.authorization_endpoint(environ, start_response)

    def _is_authenticated(self, environ, start_response, *args, **kwargs):
        """ Determines if the user is authenticated
        """
        self._logger.trace("args(%s,%s)", args, kwargs)
        return self.provider.authenticated(environ, start_response)

    def _token(self, environ, start_response, *args, **kwargs):
        return self.provider.token_endpoint(environ, start_response)

    def _error_404(self, environ, start_response, *args, **kwargs):
        self._logger.debug("Couldn't find: %s", environ['PATH_INFO'])
        return NotFound()(environ, start_response)

    def parse_auth(self, environ):
        if "HTTP_AUTHORIZATION" in environ:
            authentication_type, code = environ["HTTP_AUTHORIZATION"].split(" ")
            if "Basic" == authentication_type:
                user, passwd = self.parse_basic_auth(code)

            environ["REMOTE_USER"] = user
            environ["REMOTE_PASSWD"] = passwd # TODO: Epic security fail

    def parse_basic_auth(self, code):
        user, passwd = base64.decodestring(code).split(":")
        return user, passwd

    def parse_cookie_data(self, environ):
        cookie_data = environ.get('HTTP_COOKIE', None)
        if cookie_data:
            handle = parse_cookie(self.provider.cookie_name,
                                  self.provider.seed, cookie_data)
            self._logger.debug("cookie handle: %s", repr(handle))


class Application:

    lookup = TemplateLookup(directories=TEMPLATE_DIRS)
    _logger = getLogger('auth2.server.Application')

    def __init__(self):
        self.issuer = None
        self.session_db = SessionDB()
        self.cookie_db = {} # TODO: Replace with shelve
        self.user_db = USERDB
        self.auth_db = AUTHORIZATIONS
        self.client_db = CLIENTS
        self.provider = SafeProvider(name=self.issuer,
                                 sdb=self.session_db, cdb=self.cookie_db,
                                 function=self, urlmap=CLIENT_URL_MAP)
        self.callbacks = {
                'authenticate': self._login,
                'authorize': self._authorization,
                'verify user': self._verify_user,
                'verify client': self._verify_client,
                }

    def __getitem__(self, key):
        self._logger.trace("Callback: %s", key)
        return self.callbacks[key]

    def _authorization(self, user, session=None):
        if self.auth_db.has_key(user):
            return self.auth_db[user]
        else:
            raise Exception("No Authorization defined")

    def _verify_user(self, form_data, *args, **kwargs):
        self._logger.trace("verifying (%s,%s)", form_data['login'][0], form_data['password'][0])
        try:
            user = form_data['login'][0]
            password = form_data['password'][0]
            if self.user_db[user] == password:
                return True, user
        except KeyError:
            pass
        return False, ""

    def _verify_client(self, environ, client_id, cookie_db):
        if client_id in self.client_db:
            if self.client_db[client_id] == environ["REMOTE_PASSWD"]:
                return True
        return False

    def _login(self, environ, start_response, session_id, cookie=None,
                      *args, **kwargs):
        """ Show login form
        """
        self._logger.trace("args(%s,%s)", args, kwargs)
        headers = [cookie] if cookie else []
        response = Response(mako_template="login.mako",
                            template_lookup=self.lookup,
                            headers=headers)
        d = {
                'action': 'authenticated',
                'sid': session_id,
                'login': '', 'password': '',
                }
        try:
            return response(environ, start_response, **d)
        except:
            print mako_exceptions.text_error_template().render()

def log_header():
    print('_'*100)
    print('%(asctime)23s   %(levelname)-5s   %(name)-24s %(funcName)-22s   %(message)s'%{
        'asctime': 'TIME          ', 'levelname': 'LEVEL', 'name': 'NAME',
        'funcName': 'FUNCTION', 'message': 'MESSAGE' })
    print('_'*100)

if "__main__" == __name__:
    from cherrypy import wsgiserver
    import cherrypy

    # Setting up logger for trace messages
    format_str = '%(asctime)23s | %(levelname)-5s | %(name)-24s %(funcName)-22s | %(message)s'
    stdout_log = logging.StreamHandler()
    stdout_formatter = logging.Formatter(format_str)
    stdout_log.setFormatter(stdout_formatter)
    logger = getLogger()
    logger.addHandler(stdout_log)
    logger.setLevel(logging.TRACE)

    address = ('0.0.0.0', 8080)
    server_url = "http://%s:%d/" % address

    # Config for cherrypy
    cherrypy._cprequest.Request.throw_errors = True
    cherrypy.config.update(LOCAL_CHERRY_CONFIG)

    server = wsgiserver.CherryPyWSGIServer(address, Dispatcher(Application()))

    try:
        print "Server url:", server_url
        log_header()
        server.start()
    except KeyboardInterrupt:
        server.stop()
