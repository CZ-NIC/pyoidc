import logging
import time
from urllib import urlencode
from urlparse import parse_qs
from urlparse import urlsplit
from oic.utils.aes_m2c import AES_encrypt
from oic.utils.aes_m2c import AES_decrypt
from oic.utils.http_util import Response
from oic.utils.http_util import parse_cookie
from oic.utils.http_util import make_cookie
from oic.utils.http_util import Redirect
from oic.utils.http_util import Unauthorized

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


class NoSuchAuthentication(Exception):
    pass


class TamperAllert(Exception):
    pass


class ToOld(Exception):
    pass


class UserAuthnMethod(object):
    def __init__(self, srv):
        self.srv = srv
        self.query_param = "upm_answer"
        # minutes before the authentication should be completed
        self.cookie_ttl = 5  # 5 minutes

    def __call__(self, *args, **kwargs):
        raise NotImplemented

    def create_cookie(self, value, cookie_name=None, typ="uam", ttl=-1):
        if ttl < 0:
            ttl = self.cookie_ttl
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        timestamp = str(int(time.mktime(time.gmtime())))
        info = AES_encrypt(self.srv.symkey,
                           "::".join([value, timestamp, typ]),
                           self.srv.iv)
        cookie = make_cookie(cookie_name, info, self.srv.seed,
                             expire=ttl, domain="", path="")
        return cookie

    def getCookieValue(self, cookie=None, cookie_name=None):
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
                value, _ts, typ = AES_decrypt(self.srv.symkey, info,
                                              self.srv.iv).split("::")
                if timestamp == _ts:
                    return value, _ts, typ
            except Exception:
                pass
        return None

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie is None:
            return None
        else:
            logger.debug("kwargs: %s" % kwargs)

            uid, _ts, typ = self.getCookieValue(cookie, self.srv.cookie_name)

            if typ == "uam":  # shortlived
                _now = int(time.mktime(time.gmtime()))
                if _now > (int(_ts) + int(self.cookie_ttl * 60)):
                    logger.debug("Authentication timed out")
                    raise ToOld("%d > (%d + %d)" % (_now, int(_ts),
                                                    int(self.cookie_ttl * 60)))
            else:
                if "max_age" in kwargs and kwargs["max_age"]:
                    _now = int(time.mktime(time.gmtime()))
                    if _now > (int(_ts) + int(kwargs["max_age"])):
                        logger.debug("Authentication too old")
                        raise ToOld("%d > (%d + %d)" % (
                            _now, int(_ts), int(kwargs["max_age"])))

            return {"uid": uid}

    def generateReturnUrl(self, return_to, uid):
        return create_return_url(return_to, uid, **{self.query_param: "true"})

    def verify(self, **kwargs):
        raise NotImplemented


def url_encode_params(params=None):
    if not isinstance(params, dict):
        raise Exception("You must pass in a dictionary!")
    params_list = []
    for k, v in params.items():
        if isinstance(v, list):
            params_list.extend([(k, x) for x in v])
        else:
            params_list.append((k, v))
    return urlencode(params_list)


def create_return_url(base, query, **kwargs):
    """
    Add a query string plus extra parameters to a base URL which may contain
    a query part already.

    :param base: redirect_uri may contain a query part, no fragment allowed.
    :param query: Old query part as a string
    :param kwargs: extra query parameters
    :return:
    """
    part = urlsplit(base)
    if part.fragment:
        raise ValueError("Base URL contained parts it shouldn't")

    for key, values in parse_qs(query).items():
        if key in kwargs:
            if isinstance(kwargs[key], basestring):
                kwargs[key] = [kwargs[key]]
            kwargs[key].extend(values)
        else:
            kwargs[key] = values

    if part.query:
        for key, values in parse_qs(part.query).items():
            if key in kwargs:
                if isinstance(kwargs[key], basestring):
                    kwargs[key] = [kwargs[key]]
                kwargs[key].extend(values)
            else:
                kwargs[key] = values

        _pre = base.split("?")[0]
    else:
        _pre = base

    logger.debug("kwargs: %s" % kwargs)

    return "%s?%s" % (_pre, url_encode_params(kwargs))


class UsernamePasswordMako(UserAuthnMethod):
    """Do user authentication using the normal username password form in a
    WSGI environment using Mako as template system"""

    def __init__(self, srv, mako_template, template_lookup, pwd, return_to):
        """
        :param srv: The server instance
        :param mako_template: Which Mako template to use
        :param pwd: Username/password dictionary like database
        :param return_to: Where to send the user after authentication
        :return:
        """
        UserAuthnMethod.__init__(self, srv)
        self.mako_template = mako_template
        self.template_lookup = template_lookup
        self.passwd = pwd
        self.return_to = return_to

    def __call__(self, cookie=None, policy_url=None, logo_url=None,
                 query="", **kwargs):
        """
        Put up the login form
        """
        if cookie:
            headers = [cookie]
        else:
            headers = []

        resp = Response(headers=headers)

        argv = {"login": "",
                "password": "",
                "action": "verify",
                "policy_url": policy_url,
                "logo_url": logo_url,
                "query": query}
        logger.info("do_authentication argv: %s" % argv)
        mte = self.template_lookup.get_template(self.mako_template)
        resp.message = mte.render(**argv)
        return resp

    def verify(self, request, **kwargs):
        """
        Verifies that the given username and password was correct
        :param request: Either the query part of a URL a urlencoded
            body of a HTTP message or a parse such.
        :param kwargs: Catch whatever else is sent.
        :return: redirect back to where ever the base applications
            wants the user after authentication.
        """

        logger.debug("verify(%s)" % request)
        if isinstance(request, basestring):
            _dict = parse_qs(request)
        elif isinstance(request, dict):
            _dict = request
        else:
            raise ValueError("Wrong type of input")

        logger.debug("dict: %s" % _dict)
        logger.debug("passwd: %s" % self.passwd)
        # verify username and password
        try:
            assert _dict["password"][0] == self.passwd[_dict["login"][0]]
            cookie = self.create_cookie(_dict["login"][0])
            return_to = self.generateReturnUrl(self.return_to, _dict["query"][0])
            resp = Redirect(return_to, headers=[cookie])
        except (AssertionError, KeyError):
            resp = Unauthorized("Unknown user or wrong password")

        return resp

    def done(self, areq):
        try:
            _ = areq[self.query_param]
            return False
        except KeyError:
            return True


class AuthnMethodChooser(object):
    def __init__(self, methods=None):
        self.methods = methods

    def __call__(self, **kwargs):
        if not self.methods:
            raise Exception("No authentication methods defined")
        elif len(self.methods) == 1:
            return self.methods[0]
        else:
            pass  # TODO

