from jwkest.jws import alg2keytype
from oic.oauth2.exception import FailedAuthentication
from oic.oic import OpenIDSchema
from oic.utils.http_util import Response

__author__ = 'haho0032'
import logging

from oic.oic.provider import Provider

logger = logging.getLogger(__name__)

class XpressConnectProvider(Provider):


    #noinspection PyUnusedLocal
    def userinfo_endpoint(self, request="", **kwargs):
        """
        :param request: The request in a string format
        """
        try:
            _log_debug = kwargs["logger"].debug
            _log_info = kwargs["logger"].info
        except KeyError:
            _log_debug = logger.debug
            _log_info = logger.info

        _sdb = self.sdb

        if not request or "access_token" not in request:
            _token = kwargs["authn"]
            assert _token.startswith("Bearer ")
            _token = _token[len("Bearer "):]
            logger.debug("Bearer token: '%s'" % _token)
        else:
            uireq = self.server.parse_user_info_request(data=request)
            logger.debug("user_info_request: %s" % uireq)
            _token = uireq["access_token"]

        # should be an access token
        typ, key = _sdb.token.type_and_key(_token)
        _log_debug("access_token type: '%s'" % (typ,))

        try:
            assert typ == "T"
        except AssertionError:
            raise FailedAuthentication("Wrong type of token")

        #_log_info("keys: %s" % self.sdb.keys())
        if _sdb.is_revoked(key):
            return self._error(error="access_denied", descr="Token is revoked")
        session = _sdb[key]

        # Scope can translate to userinfo_claims

        info = OpenIDSchema(**self._collect_user_info(session))

        # Should I return a JSON or a JWT ?
        """_cinfo = self.cdb[session["client_id"]]
        if "userinfo_signed_response_alg" in _cinfo:
            algo = _cinfo["userinfo_signed_response_alg"]
            # Use my key for signing
            key = self.keyjar.get_signing_key(alg2keytype(algo), "")
            jinfo = info.to_jwt(key, algo)
            content_type = "application/jwt"
            if "userinfo_encrypted_response_alg" in _cinfo:
                # encrypt with clients public key
                jinfo = self.encrypt(jinfo, _cinfo, session["client_id"],
                                     "userinfo")
        elif "userinfo_encrypted_response_alg" in _cinfo:
            jinfo = self.encrypt(info.to_json(), _cinfo, session["client_id"],
                                 "userinfo")
            content_type = "application/jwt"
        else:
            jinfo = info.to_json()
            content_type = "application/json"
"""
        content_type = 'text/xml'
        id = info['sub']
        xpressConnectResp = "<identity id='" + id + "' name='" + id + "' group_id='' group_name=''/>"

        return Response(xpressConnectResp, content=content_type)
