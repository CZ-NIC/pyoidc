import logging
import cgi
import time
import hashlib
import hmac

from six.moves.urllib.parse import quote
from six.moves.http_cookies import SimpleCookie
from jwkest import as_unicode
from oic.oauth2 import rndstr
from oic.exception import UnsupportedMethod
from oic.utils import time_util
from oic.utils.aes import encrypt
from oic.utils.aes import decrypt

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)


class Response(object):
    _template = None
    _status = '200 OK'
    _content_type = 'text/html'
    _mako_template = None
    _mako_lookup = None

    def __init__(self, message=None, **kwargs):
        self.status = kwargs.get("status", self._status)
        self.response = kwargs.get("response", self._response)
        self.template = kwargs.get("template", self._template)
        self.mako_template = kwargs.get("mako_template", self._mako_template)
        self.mako_lookup = kwargs.get("template_lookup", self._mako_lookup)

        self.message = message

        self.headers = []
        self.headers.extend(kwargs.get("headers", []))
        _content_type = kwargs.get("content", self._content_type)

        self.headers.append(("Content-type", _content_type))

    def __call__(self, environ, start_response, **kwargs):
        start_response(self.status, self.headers)
        return self.response(self.message, **kwargs)

    def _response(self, message="", **argv):
        if self.template:
            if ("Content-type", "application/json") in self.headers:
                return [message]
            else:
                return [str(self.template % message)]
        elif self.mako_lookup and self.mako_template:
            argv["message"] = message
            mte = self.mako_lookup.get_template(self.mako_template)
            return [mte.render(**argv)]
        else:
            return [message]


class Created(Response):
    _status = "201 Created"


class Accepted(Response):
    _status = "202 Accepted"


class NonAuthoritativeInformation(Response):
    _status = "203 Non Authoritative Information"


class NoContent(Response):
    _status = "204 No Content"


class Redirect(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
                '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
                '</body>\n</html>'
    _status = '302 Found'

    def __call__(self, environ, start_response, **kwargs):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))


class SeeOther(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
                '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
                '</body>\n</html>'
    _status = '303 See Other'

    def __call__(self, environ, start_response, **kwargs):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))


class Forbidden(Response):
    _status = '403 Forbidden'
    _template = "<html>Not allowed to mess with: '%s'</html>"


class BadRequest(Response):
    _status = "400 Bad Request"
    _template = "<html>%s</html>"


class Unauthorized(Response):
    _status = "401 Unauthorized"
    _template = "<html>%s</html>"


class NotFound(Response):
    _status = '404 NOT FOUND'


class NotSupported(Response):
    _status = '405 Not Support'


class NotAcceptable(Response):
    _status = '406 Not Acceptable'


class ServiceError(Response):
    _status = '500 Internal Service Error'


class InvalidCookieSign(Exception):
    pass


R2C = {
    200: Response,
    201: Created,
    202: Accepted,
    203: NonAuthoritativeInformation,
    204: NoContent,
    302: Redirect,
    303: SeeOther,
    400: BadRequest,
    401: Unauthorized,
    403: Forbidden,
    404: NotFound,
    405: NotSupported,
    406: NotAcceptable,
    500: ServiceError,
}


def factory(code, message, **kwargs):
    return R2C[code](message, **kwargs)


def extract(environ, empty=False, err=False):
    """Extracts strings in form data and returns a dict.

    :param environ: WSGI environ
    :param empty: Stops on empty fields (default: Fault)
    :param err: Stops on errors in fields (default: Fault)
    """
    formdata = cgi.parse(environ['wsgi.input'], environ, empty, err)
    # Remove single entries from lists
    for key, value in formdata.iteritems():
        if len(value) == 1:
            formdata[key] = value[0]
    return formdata


def geturl(environ, query=True, path=True):
    """Rebuilds a request URL (from PEP 333).

    :param query: Is QUERY_STRING included in URI (default: True)
    :param path: Is path included in URI (default: True)
    """
    url = [environ['wsgi.url_scheme'] + '://']
    if environ.get('HTTP_HOST'):
        url.append(environ['HTTP_HOST'])
    else:
        url.append(environ['SERVER_NAME'])
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url.append(':' + environ['SERVER_PORT'])
        else:
            if environ['SERVER_PORT'] != '80':
                url.append(':' + environ['SERVER_PORT'])
    if path:
        url.append(getpath(environ))
    if query and environ.get('QUERY_STRING'):
        url.append('?' + environ['QUERY_STRING'])
    return ''.join(url)


def getpath(environ):
    """Builds a path."""
    return ''.join([quote(environ.get('SCRIPT_NAME', '')),
                    quote(environ.get('PATH_INFO', ''))])


def _expiration(timeout, time_format=None):
    if timeout == "now":
        return time_util.instant(time_format)
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, time_format=time_format)


def cookie_signature(seed, *parts):
    """Generates a cookie signature."""
    sha1 = hmac.new(seed, digestmod=hashlib.sha1)
    for part in parts:
        if part:
            sha1.update(part)
    return sha1.hexdigest()


def make_cookie(name, load, seed, expire=0, domain="", path="", timestamp=""):
    """
    Create and return a cookie

    :param name: Cookie name
    :param load: Cookie load
    :param seed: A seed for the HMAC function
    :param expire: Number of minutes before this cookie goes stale
    :param domain: The domain of the cookie
    :param path: The path specification for the cookie
    :param timestamp: A time stamp
    :return: A tuple to be added to headers
    """
    cookie = SimpleCookie()
    if not timestamp:
        timestamp = str(int(time.time()))
    signature = cookie_signature(seed, load.encode("utf-8"),
                                 timestamp.encode("utf-8"))
    cookie[name] = "|".join([load, timestamp, signature])
    if path:
        cookie[name]["path"] = path
    if domain:
        cookie[name]["domain"] = domain
    if expire:
        cookie[name]["expires"] = _expiration(expire,
                                              "%a, %d-%b-%Y %H:%M:%S GMT")

    return tuple(cookie.output().split(": ", 1))


def parse_cookie(name, seed, kaka):
    """Parses and verifies a cookie value

    :param seed: A seed used for the HMAC signature
    :param kaka: The cookie
    :return: A tuple consisting of (payload, timestamp)
    """
    if not kaka:
        return None

    cookie_obj = SimpleCookie(kaka)
    morsel = cookie_obj.get(name)

    if morsel:
        parts = morsel.value.split("|")
        if len(parts) != 3:
            return None
        # verify the cookie signature
        sig = cookie_signature(seed, parts[0].encode("utf-8"),
                               parts[1].encode("utf-8"))
        if sig != parts[2]:
            raise InvalidCookieSign()

        try:
            return parts[0].strip(), parts[1]
        except KeyError:
            return None
    else:
        return None


def cookie_parts(name, kaka):
    cookie_obj = SimpleCookie(kaka)
    morsel = cookie_obj.get(name)
    if morsel:
        return morsel.value.split("|")
    else:
        return None


def get_post(environ):
    # the environment variable CONTENT_LENGTH may be empty or missing
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0

    # When the method is POST the query string will be sent
    # in the HTTP request body which is passed by the WSGI server
    # in the file like wsgi.input environment variable.
    text = environ['wsgi.input'].read(request_body_size)
    try:
        text = text.decode("utf-8")
    except AttributeError:
        pass
    return text


def get_or_post(environ):
    _method = environ["REQUEST_METHOD"]

    if _method == "GET":
        data = environ.get("QUERY_STRING", "")
    elif _method == "POST":
        data = get_post(environ)
    else:
        raise UnsupportedMethod(_method)

    return data


def extract_from_request(environ, kwargs=None):
    if kwargs is None:
        kwargs = {}

    request = None
    try:
        request = environ["QUERY_STRING"]
    except KeyError:
        pass
    if not request:
        try:
            request = as_unicode(get_post(environ))
        except KeyError:
            pass
    kwargs["request"] = request
    # authentication information
    try:
        kwargs["authn"] = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        pass
    try:
        kwargs["cookie"] = environ["HTTP_COOKIE"]
    except KeyError:
        pass

    # intended audience
    kwargs["requrl"] = geturl(environ)
    kwargs["url"] = geturl(environ, query=False)
    kwargs["baseurl"] = geturl(environ, query=False, path=False)
    kwargs["path"] = getpath(environ)
    return kwargs


def wsgi_wrapper(environ, start_response, func, **kwargs):
    kwargs = extract_from_request(environ, kwargs)
    args = func(**kwargs)

    try:
        resp, state = args
        return resp(environ, start_response)
    except TypeError:
        resp = args
        return resp(environ, start_response)
    except Exception as err:
        logger.error("%s" % err)
        raise


class CookieDealer(object):
    def getServer(self):
        return self._srv

    def setServer(self, server):
        self._srv = server

    srv = property(getServer, setServer)

    def __init__(self, srv, ttl=5):
        self.srv = None
        self.init_srv(srv)
        # minutes before the interaction should be completed
        self.cookie_ttl = ttl  # N minutes
        self.pad_chr = " "

    def init_srv(self, srv):
        if srv:
            self.srv = srv

            for param in ["seed", "iv"]:
                if not getattr(srv, param, None):
                    setattr(srv, param, rndstr().encode("utf-8"))

    def delete_cookie(self, cookie_name=None):
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        return self.create_cookie("", "", cookie_name=cookie_name, ttl=-1,
                                  kill=True)

    def create_cookie(self, value, typ, cookie_name=None, ttl=-1, kill=False):
        if kill:
            ttl = -1
        elif ttl < 0:
            ttl = self.cookie_ttl
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        timestamp = str(int(time.time()))
        _msg = "::".join([value, timestamp, typ])
        if self.srv.symkey:
            # Pad the message to be multiples of 16 bytes in length
            lm = len(_msg)
            _msg = _msg.ljust(lm + 16 - lm % 16, self.pad_chr)
            info = encrypt(self.srv.symkey, _msg, self.srv.iv).decode("utf-8")
        else:
            info = _msg
        cookie = make_cookie(cookie_name, info, self.srv.seed,
                             expire=ttl, domain="", path="",
                             timestamp=timestamp)
        return cookie

    def getCookieValue(self, cookie=None, cookie_name=None):
        return self.get_cookie_value(cookie, cookie_name)

    def get_cookie_value(self, cookie=None, cookie_name=None):
        """
        Return information stored in the Cookie

        :param cookie:
        :param cookie_name: The name of the cookie I'm looking for
        :return: tuple (value, timestamp, type)
        """
        if cookie is None or cookie_name is None:
            return None
        else:
            try:
                info, timestamp = parse_cookie(cookie_name,
                                               self.srv.seed, cookie)
            except (TypeError, AssertionError):
                return None
            else:
                if self.srv.symkey:
                    txt = decrypt(self.srv.symkey, info, self.srv.iv)
                    # strip spaces at the end
                    txt = txt.rstrip(self.pad_chr)
                else:
                    txt = info

                value, _ts, typ = txt.split("::")
                if timestamp == _ts:
                    return value, _ts, typ
        return None
