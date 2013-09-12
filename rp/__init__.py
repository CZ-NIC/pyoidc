__author__ = 'haho0032'

#

from saml2 import samlp

import logging
from saml2.httputil import Response
import traceback
import sys

logger = logging.getLogger(__name__)


class Social(object):
    def __init__(self, client_id, client_secret, opKey,
                 attribute_map=None, authenticating_authority=None,
                 name="", **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret
        self.attribute_map = attribute_map
        self.opKey = opKey
        self.authenticating_authority = authenticating_authority
        self.name = name
        self.extra = kwargs

    def begin(self, environ, server_env, start_response, session):
        raise NotImplementedError()

    def phaseN(self, environ, query, server_env, sid):
        raise NotImplementedError()


    def result(self, environ, start_response, server_env, result):
        resp = Response(mako_template="opresult.mako",
        template_lookup=server_env["template_lookup"],
        headers=[])
        argv = {
            "result" : result
        }
        return resp(environ, start_response, **argv)

    #noinspection PyUnusedLocal
    def callback(self, environ, server_env, start_response, query, session):
        """

        :param environ:
        :param server_env:
        :param start_response:
        :param info:
        :param session:
        :return:
        """
        _service = self.__class__.__name__

        logger.debug("[do_%s] environ: %s" % (_service, environ))
        logger.debug("[do_%s] query: %s" % (_service, query))

        try:
            result = self.phaseN(environ, query, server_env, session)
            logger.debug("[do_%s] response: %s" % (_service, result))

        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            result = (False, "An unknown exception has occurred.")

        return self.result(environ, start_response, server_env, result)

