import base64
import logging
import time
from urllib import urlencode
import urllib
from urlparse import parse_qs
from urlparse import urlsplit
import urlparse
import ldap
from oic.utils.aes_m2c import AES_decrypt
from oic.utils.http_util import Response, CookieDealer, InvalidCookieSign
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


class FailedAuthentication(Exception):
    pass


class UserAuthnMethod(CookieDealer):
    def __init__(self, srv, ttl=5):
        CookieDealer.__init__(self, srv, ttl)
        self.query_param = "upm_answer"

    def __call__(self, *args, **kwargs):
        raise NotImplemented

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie is None:
            return None
        else:
            logger.debug("kwargs: %s" % kwargs)

            try:
                val = self.getCookieValue(cookie, self.srv.cookie_name)
            except InvalidCookieSign:
                val = None

            if val is None:
                return None
            else:
                uid, _ts, typ = val

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
    if kwargs:
        return "%s?%s" % (_pre, url_encode_params(kwargs))
    else:
        return _pre


class UsernamePasswordMako(UserAuthnMethod):
    """Do user authentication using the normal username password form in a
    WSGI environment using Mako as template system"""

    def __init__(self, srv, mako_template, template_lookup, pwd, return_to="",
                 templ_arg_func=None):
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
        if templ_arg_func:
            self.templ_arg_func = templ_arg_func
        else:
            self.templ_arg_func = self.template_args

    @staticmethod
    def template_args(**kwargs):
        """
        Method to override if necessary, dependent on the page layout
        and context

        :param kwargs:
        :return:
        """
        acr = None
        try:
            req = urlparse.parse_qs(kwargs["query"])
            acr = req["acr_values"][0]
        except:
            pass

        argv = {"password": "",
                "action": "verify",
                "acr": acr}

        try:
            argv["login"] = kwargs["as_user"]
        except KeyError:
            argv["login"] = ""

        for param in ["policy_url", "logo_url", "query"]:
            try:
                argv[param] = kwargs[param]
            except KeyError:
                argv[param] = ""

        return argv

    def __call__(self, cookie=None, **kwargs):
        """
        Put up the login form
        """
        if cookie:
            headers = [cookie]
        else:
            headers = []

        resp = Response(headers=headers)

        argv = self.templ_arg_func(**kwargs)
        logger.info("do_authentication argv: %s" % argv)
        mte = self.template_lookup.get_template(self.mako_template)
        resp.message = mte.render(**argv)
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
            assert self._verify(_dict["password"][0], _dict["login"][0])
        except (AssertionError, KeyError):
            resp = Unauthorized("Unknown user or wrong password")
        else:
            cookie = self.create_cookie(_dict["login"][0], "upm")
            try:
                _qp = _dict["query"][0]
            except KeyError:
                _qp = ""
            return_to = self.generateReturnUrl(self.return_to, _qp)
            resp = Redirect(return_to, headers=[cookie])

        return resp

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
            raise FailedAuthentication()

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
        user = urllib.unquote(user)
        self.verify_password(user, pwd)
        return {"uid": user}


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
            user = AES_decrypt(self.symkey, encmsg, iv)
        except (AssertionError, KeyError):
            raise FailedAuthentication()

        return {"uid": user}


class LDAPAuthn(UsernamePasswordMako):
    def __init__(self, srv, ldapsrv, return_to,
                 dn_pattern, mako_template, template_lookup):
        """
        :param srv: The server instance
        :param ldapsrv: Which LDAP server to us
        :param return_to: Where to send the user after authentication
        :return:
        """
        UsernamePasswordMako.__init__(self, srv, mako_template, template_lookup,
                                      None, return_to)

        self.ldap = ldap.initialize(ldapsrv)
        self.ldap.protocol_version = 3
        self.ldap.set_option(ldap.OPT_REFERRALS, 0)
        self.dn_pattern = dn_pattern

    def _verify(self, pwd, user):
        """
        Verifies the username and password agains a LDAP server
        :param pwd: The password
        :param user: The username
        :return: AssertionError if the LDAP verification failed.
        """
        _dn = self.dn_pattern % user
        try:
            self.ldap.simple_bind_s(_dn, pwd)
        except Exception:
            raise AssertionError()
