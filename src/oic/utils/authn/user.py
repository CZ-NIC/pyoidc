# coding=utf-8
import base64
import logging
import time

import six
from six.moves.urllib.parse import parse_qs, urlunsplit, urlsplit, urlencode, unquote
from oic.exception import PyoidcError

from oic.utils import aes
from oic.utils.http_util import Response
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import InvalidCookieSign
from oic.utils.http_util import Redirect
from oic.utils.http_util import Unauthorized

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


LOC = {
    "en": {
        "title": "User log in",
        "login_title": "Username",
        "passwd_title": "Password",
        "submit_text": "Submit",
        "client_policy_title": "Client Policy"},
    "se": {
        "title": "Logga in",
        "login_title": u"Användarnamn",
        "passwd_title": u"Lösenord",
        "submit_text": u"Sänd",
        "client_policy_title": "Klientens sekretesspolicy"
    }
}


class NoSuchAuthentication(PyoidcError):
    pass


class TamperAllert(PyoidcError):
    pass


class ToOld(PyoidcError):
    pass


class FailedAuthentication(PyoidcError):
    pass


class InstantiationError(PyoidcError):
    pass


class UserAuthnMethod(CookieDealer):
    MULTI_AUTH_COOKIE = "rp_query_cookie"

    def __init__(self, srv, ttl=5):
        CookieDealer.__init__(self, srv, ttl)
        self.query_param = "upm_answer"

    def __call__(self, *args, **kwargs):
        raise NotImplemented

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie is None:
            return None, 0
        else:
            logger.debug("kwargs: %s" % kwargs)

            try:
                val = self.getCookieValue(cookie, self.srv.cookie_name)
            except (InvalidCookieSign, AssertionError):
                val = None

            if val is None:
                return None, 0
            else:
                uid, _ts, typ = val

            if typ == "uam":  # shortlived
                _now = int(time.time())
                if _now > (int(_ts) + int(self.cookie_ttl * 60)):
                    logger.debug("Authentication timed out")
                    raise ToOld("%d > (%d + %d)" % (_now, int(_ts),
                                                    int(self.cookie_ttl * 60)))
            else:
                if "max_age" in kwargs and kwargs["max_age"]:
                    _now = int(time.time())
                    if _now > (int(_ts) + int(kwargs["max_age"])):
                        logger.debug("Authentication too old")
                        raise ToOld("%d > (%d + %d)" % (
                            _now, int(_ts), int(kwargs["max_age"])))

            return {"uid": uid}, _ts

    def generate_return_url(self, return_to, uid, path=""):
        """
        :param return_to: If it starts with '/' it's an absolute path otherwise
        a relative path.
        :param uid:
        :param path: The verify path
        """
        if return_to.startswith("http"):
            up = urlsplit(return_to)
            _path = up.path
        else:
            up = None
            _path = return_to

        if not _path.startswith("/"):
            p = path.split("/")
            p[-1] = _path
            _path = "/".join(p)

        if up:
            _path = urlunsplit([up[0], up[1], _path, up[3], up[4]])

        return create_return_url(_path, uid, **{self.query_param: "true"})

    def verify(self, **kwargs):
        raise NotImplemented

    def get_multi_auth_cookie(self, cookie):
        rp_query_cookie = self.getCookieValue(cookie,
                                              UserAuthnMethod.MULTI_AUTH_COOKIE)

        if rp_query_cookie:
            return rp_query_cookie[0]
        return ""


def url_encode_params(params=None):
    if not isinstance(params, dict):
        raise InstantiationError("You must pass in a dictionary!")
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
            if isinstance(kwargs[key], six.string_types):
                kwargs[key] = [kwargs[key]]
            kwargs[key].extend(values)
        else:
            kwargs[key] = values

    if part.query:
        for key, values in parse_qs(part.query).items():
            if key in kwargs:
                if isinstance(kwargs[key], six.string_types):
                    kwargs[key] = [kwargs[key]]
                kwargs[key].extend(values)
            else:
                kwargs[key] = values

        _pre = base.split("?")[0]
    else:
        _pre = base

    logger.debug("kwargs: %s" % kwargs)
    if kwargs:
        return "%s?%s" % (_pre, url_encode_params(kwargs))
    else:
        return _pre


class UsernamePasswordMako(UserAuthnMethod):
    """Do user authentication using the normal username password form in a
    WSGI environment using Mako as template system"""

    param_map = {"as_user": "login", "acr_values": "acr",
                 "policy_uri": "policy_uri", "logo_uri": "logo_uri",
                 "tos_uri": "tos_uri", "query": "query"}

    def __init__(self, srv, mako_template, template_lookup, pwd, return_to="",
                 templ_arg_func=None, verification_endpoints=None):
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
        self.verification_endpoints = verification_endpoints or ["verify"]
        if templ_arg_func:
            self.templ_arg_func = templ_arg_func
        else:
            self.templ_arg_func = self.template_args

    def template_args(self, end_point_index=0, **kwargs):
        """
        Method to override if necessary, dependent on the page layout
        and context

        :param kwargs:
        :return: dictionary of parameters used to build the Authn page
        """

        try:
            action = kwargs["action"]
        except KeyError:
            action = self.verification_endpoints[end_point_index]

        argv = {"password": "", "action": action}

        for fro, to in self.param_map.items():
            try:
                argv[to] = kwargs[fro]
            except KeyError:
                argv[to] = ""

        if "extra" in kwargs:
            for param in kwargs["extra"]:
                try:
                    argv[param] = kwargs[param]
                except KeyError:
                    argv[param] = ""

        try:
            _locs = kwargs["ui_locales"]
        except KeyError:
            argv.update(LOC["en"])
        else:
            for loc in _locs:
                try:
                    argv.update(LOC[loc])
                except KeyError:
                    pass
                else:
                    break

        return argv

    def __call__(self, cookie=None, end_point_index=0, **kwargs):
        """
        Put up the login form
        """
        # if cookie:
        #     headers = [cookie]
        # else:
        #     headers = []

        resp = Response()

        argv = self.templ_arg_func(end_point_index, **kwargs)
        logger.info("do_authentication argv: %s" % argv)
        mte = self.template_lookup.get_template(self.mako_template)
        resp.message = mte.render(**argv).decode("utf-8")
        return resp

    def _verify(self, pwd, user):
        assert pwd == self.passwd[user]

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
        if isinstance(request, six.string_types):
            _dict = parse_qs(request)
        elif isinstance(request, dict):
            _dict = request
        else:
            raise ValueError("Wrong type of input")

        logger.debug("dict: %s" % _dict)
        logger.debug("passwd: %s" % self.passwd)
        # verify username and password
        try:
            self._verify(_dict["password"][0], _dict["login"][0])
        except (AssertionError, KeyError):
            resp = Unauthorized("Unknown user or wrong password")
            return resp, False
        else:
            # if "cookie" not in kwargs or self.srv.cookie_name not in kwargs["cookie"]:
            headers = [self.create_cookie(_dict["login"][0], "upm")]
            try:
                _qp = _dict["query"][0]
            except KeyError:
                _qp = self.get_multi_auth_cookie(kwargs['cookie'])
            try:
                return_to = self.generate_return_url(kwargs["return_to"], _qp)
            except KeyError:
                try:
                    return_to = self.generate_return_url(self.return_to, _qp,
                                                         kwargs["path"])
                except KeyError:
                    return_to = self.generate_return_url(self.return_to, _qp)

            return Redirect(return_to, headers=headers), True

    def done(self, areq):
        try:
            _ = areq[self.query_param]
            return False
        except KeyError:
            return True


class BasicAuthn(UserAuthnMethod):

    def __init__(self, srv, pwd, ttl=5):
        UserAuthnMethod.__init__(self, srv, ttl)
        self.passwd = pwd

    def verify_password(self, user, password):
        try:
            assert password == self.passwd[user]
        except (AssertionError, KeyError):
            raise FailedAuthentication("Wrong password")

    def authenticated_as(self, cookie=None, authorization="", **kwargs):
        """

        :param cookie: A HTTP Cookie
        :param authorization: The HTTP Authorization header
        :param args: extra args
        :param kwargs: extra key word arguments
        :return:
        """
        if authorization.startswith("Basic"):
            authorization = authorization[6:]

        (user, pwd) = base64.b64decode(authorization).split(":")
        user = unquote(user)
        self.verify_password(user, pwd)
        return {"uid": user}, time.time()


class SymKeyAuthn(UserAuthnMethod):

    def __init__(self, srv, ttl, symkey):
        UserAuthnMethod.__init__(self, srv, ttl)
        self.symkey = symkey

    def authenticated_as(self, cookie=None, authorization="", **kwargs):
        """

        :param cookie: A HTTP Cookie
        :param authorization: The HTTP Authorization header
        :param args: extra args
        :param kwargs: extra key word arguments
        :return:
        """
        (encmsg, iv) = base64.b64decode(authorization).split(":")
        try:
            user = aes.decrypt(self.symkey, encmsg, iv)
        except (AssertionError, KeyError):
            raise FailedAuthentication("Decryption failed")

        return {"uid": user}, time.time()


class NoAuthn(UserAuthnMethod):
    # Just for testing allows anyone it without authentication

    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, authorization="", **kwargs):
        """

        :param cookie: A HTTP Cookie
        :param authorization: The HTTP Authorization header
        :param args: extra args
        :param kwargs: extra key word arguments
        :return:
        """

        return {"uid": self.user}, time.time()
