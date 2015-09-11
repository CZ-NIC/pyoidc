from six.moves.urllib.parse import parse_qs
import six
from oic.utils.authn.user import logger, UsernamePasswordMako
from oic.utils.http_util import Unauthorized, Redirect


__author__ = 'danielevertsson'


class JavascriptFormMako(UsernamePasswordMako):
    """Do user authentication using the normal username password form in a
    WSGI environment using Mako as template system"""

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
            assert _dict['login_parameter'][0] == 'logged_in'
        except (AssertionError, KeyError):
            resp = Unauthorized("You are not authorized. Javascript not executed")
            return resp, False
        else:
            cookie = self.create_cookie("diana", "upm")
            try:
                _qp = _dict["query"][0]
            except KeyError:
                _qp = self.get_multi_auth_cookie(kwargs['cookie'])
            try:
                return_to = self.generate_return_url(kwargs["return_to"], _qp)
            except KeyError:
                return_to = self.generate_return_url(self.return_to, _qp)
            resp = Redirect(return_to, headers=[cookie])

        return resp, True