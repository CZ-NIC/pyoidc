import copy
import logging

import requests
import six.moves.http_cookiejar as cookielib
from six.moves.http_cookies import CookieError
from six.moves.http_cookies import SimpleCookie

from oic.oauth2.exception import NonFatalException
from oic.oauth2.util import set_cookie
from oic.utils.keyio import KeyJar
from oic.utils.sanitize import sanitize

__author__ = 'roland'

logger = logging.getLogger(__name__)


class PBase(object):
    def __init__(self, verify_ssl=True, keyjar=None, client_cert=None, timeout=5):
        """
        A base class for OAuth2 clients and servers

        :param verify_ssl: Control TLS server certificate validation. If set to
            True the certificate is validated against the global settings,
            if set to False, no validation is performed. If set to a filename
            this is used as a certificate bundle in openssl format. If set
            to a directory name this is used as a CA directory in
            the openssl format.
        :param keyjar: A place to keep keys for signing/encrypting messages
                       Creates a default keyjar if not set.
        :param client_cert: local cert to use as client side certificate, as a
            single file (containing the private key and the certificate) or as
            a tuple of both file's path
        :param timeout: Timeout for requests library. Can be specified either as
            a single integer or as a tuple of integers. For more details, refer to
            ``requests`` documentation.
        """

        self.keyjar = keyjar or KeyJar(verify_ssl=verify_ssl)

        self.cookiejar = cookielib.FileCookieJar()

        # Additional args for the requests library calls
        self.request_args = {
            "allow_redirects": False,
            "cert": client_cert,
            "verify": verify_ssl,
            "timeout": timeout,
        }

        # Event collector, for tracing
        self.events = None
        self.req_callback = None

    def _cookies(self):
        """Turn cookiejar into a dict"""
        cookie_dict = {}

        for _, a in list(self.cookiejar._cookies.items()):
            for _, b in list(a.items()):
                for cookie in list(b.values()):
                    cookie_dict[cookie.name] = cookie.value

        return cookie_dict

    def http_request(self, url, method="GET", **kwargs):
        """
        Run a HTTP request to fetch the given url

        This wraps the requests library, so you can pass
        most requests kwargs to this method to override
        defaults.

        :param url: The URL to fetch
        :param method: The HTTP method to use.
        :param kwargs: Additional keyword arguments to pass through.

        """
        _kwargs = copy.copy(self.request_args)
        if kwargs:
            _kwargs.update(kwargs)

        if self.cookiejar:
            _kwargs["cookies"] = self._cookies()
            logger.debug("SENT {} COOKIES".format(len(_kwargs["cookies"])))

        if self.req_callback is not None:
            _kwargs = self.req_callback(method, url, **_kwargs)

        try:
            r = requests.request(method, url, **_kwargs)
        except Exception as err:
            logger.error(
                "http_request failed: %s, url: %s, htargs: %s, method: %s" % (
                    err, url, sanitize(_kwargs), method))
            raise

        if self.events is not None:
            self.events.store('HTTP response', r, ref=url)

        try:
            _cookie = r.headers["set-cookie"]
            logger.debug("RECEIVED COOKIE")
            try:
                set_cookie(self.cookiejar, SimpleCookie(_cookie))
            except CookieError as err:
                logger.error(err)
                raise NonFatalException(r, "{}".format(err))
        except (AttributeError, KeyError):
            pass

        return r

    def send(self, url, method="GET", **kwargs):
        return self.http_request(url, method, **kwargs)

    def load_cookies_from_file(self, filename, ignore_discard=False,
                               ignore_expires=False):
        self.cookiejar.load(filename, ignore_discard, ignore_expires)

    def save_cookies_to_file(self, filename, ignore_discard=False,
                             ignore_expires=False):

        self.cookiejar.save(filename, ignore_discard, ignore_expires)
