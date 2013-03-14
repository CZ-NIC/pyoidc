__author__ = 'rohe0002'

import logging
from oic.oauth2 import rndstr

from oic.oic.message import OpenIDSchema
from oic.oic.message import Claims
from oic.oic.message import TokenErrorResponse
from oic.oic.message import UserInfoClaim

from oic.oic import Server as OicServer
from oic.oic import Client
from oic.oic import REQUEST2ENDPOINT
from oic.oic import RESPONSE2ERROR

from oic.oic.provider import Provider
from oic.oic.provider import Endpoint

from oic.oauth2.message import Message
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS

from oic.utils.http_util import Response, Unauthorized, get_or_post

# Used in claims.py
#from oic.oic.message import RegistrationRequest
#from oic.oic.message import RegistrationResponse

logger = logging.getLogger(__name__)


class UserClaimsRequest(Message):
    c_param = {"sub": SINGLE_REQUIRED_STRING,
               "client_id": SINGLE_REQUIRED_STRING,
               "client_secret": SINGLE_REQUIRED_STRING,
               "claims_names": REQUIRED_LIST_OF_STRINGS}


class UserClaimsResponse(Message):
    c_param = {"claims_names": REQUIRED_LIST_OF_STRINGS,
               "jwt": SINGLE_OPTIONAL_STRING,
               "endpoint": SINGLE_OPTIONAL_STRING,
               "access_token": SINGLE_OPTIONAL_STRING}

#    def verify(self, **kwargs):
#        if "jwt" in self:
#            # Try to decode the JWT, checks the signature
#            args = dict([(claim, kwargs[claim]) for claim in ["key","keyjar"] \
#                            if claim in kwargs])
#            try:
#                item = OpenIDSchema().from_jwt(str(self["jwt"]), **args)
#            except Exception, _err:
#                raise
#
#            if not item.verify(**kwargs):
#                return False
#
#        return super(self.__class__, self).verify(**kwargs)


class UserInfoClaimsRequest(Message):
    c_param = {"access_token": SINGLE_REQUIRED_STRING}


class OICCServer(OicServer):

    def parse_user_claims_request(self, info, format="urlencoded"):
        return self._parse_request(UserClaimsRequest, info, format)

    def parse_userinfo_claims_request(self, info, format="urlencoded"):
        return self._parse_request(UserInfoClaimsRequest, info, format)


class ClaimsServer(Provider):

    def __init__(self, name, sdb, cdb, function, userdb, urlmap=None,
                 debug=0, ca_certs="", jwt_keys=None):
        Provider.__init__(self, name, sdb, cdb, function, userdb, urlmap,
                          ca_certs, jwt_keys)

        if jwt_keys is None:
            jwt_keys = []

        for cid, _dic in cdb.items():
            try:
                jwt_keys.append([_dic["client_secret"], "hmac", "sig", cid])
                jwt_keys.append([_dic["client_secret"], "hmac", "ver", cid])
            except KeyError:
                pass

        self.srvmethod = OICCServer(jwt_keys=jwt_keys)
        self.keyjar = self.srvmethod.keyjar
        self.claims_mode = "aggregate"
        self.info_store = {}
        self.claims_userinfo_endpoint = ""

    def _aggregation(self, info):

        jwt_key = self.keyjar.get_signing_key()
        cresp = UserClaimsResponse(jwt=info.to_jwt(key=jwt_key,
                                                   algorithm="RS256"),
                                   claims_names=info.keys())

        logger.info("RESPONSE: %s" % (cresp.to_dict(),))
        return cresp

    #noinspection PyUnusedLocal
    def _distributed(self, info):
        # store the user info so it can be accessed later
        access_token = rndstr()
        self.info_store[access_token] = info
        return UserClaimsResponse(endpoint=self.claims_userinfo_endpoint,
                                  access_token=access_token,
                                  claims_names=info.keys())

    #noinspection PyUnusedLocal
    def do_aggregation(self, info, uid):
        try:
            return self.function["claims_mode"](info, uid)
        except KeyError:
            if self.claims_mode == "aggregate":
                return True
            else:
                return False

    #noinspection PyUnusedLocal
    def claims_endpoint(self, environ, start_response, *args):
        _log_info = logger.info

        query = get_or_post(environ)
        ucreq = self.srvmethod.parse_user_claims_request(query)

        _log_info("request: %s" % ucreq)

        if not self.function["verify_client"](environ, ucreq, self.cdb):
            _log_info("could not verify client")
            err = TokenErrorResponse(error="unathorized_client")
            resp = Unauthorized(err.to_json(), content="application/json")
            return resp(environ, start_response)

        if "claims_names" in ucreq:
            args = dict([(n, {"optional": True}) for n in ucreq["claims_names"]])
            uic = UserInfoClaim(claims=Claims(**args))
        else:
            uic = None

        _log_info("User info claims: %s" % uic)

        #oicsrv, userdb, subject, client_id="", user_info_claims=None
        info = self.function["userinfo"](self, self.userdb, ucreq["sub"],
                                         ucreq["client_id"],
                                         user_info_claims=uic)

        _log_info("User info: %s" % info.to_dict())

        if self.do_aggregation(info, ucreq["sub"]):
            cresp = self._aggregation(info)
        else:
            cresp = self._distributed(info)

        _log_info("response: %s" % cresp.to_dict())

        resp = Response(cresp.to_json(), content="application/json")
        return resp(environ, start_response)

    def claims_info_endpoint(self, environ, start_response, *args):
        _log_info = logger.info

        query = get_or_post(environ)
        _log_info("Claims_info_endpoint query: '%s'" % query)
        _log_info("environ: %s" % environ)

        #ucreq = self.srvmethod.parse_userinfo_claims_request(query)
        #_log_info("request: %s" % ucreq)

        # Supposed to be "Bearer <access_token>
        access_token = self._bearer_auth(environ)
        uiresp = OpenIDSchema(**self.info_store[access_token])

        _log_info("returning: %s" % uiresp.to_dict())
        resp = Response(uiresp.to_json(), content="application/json")
        return resp(environ, start_response)

class ClaimsClient(Client):

    def __init__(self, client_id=None, ca_certs="",
                 client_timeout=0, jwt_keys=None):

        Client.__init__(self, client_id, ca_certs, jwt_keys=jwt_keys,
                        client_timeout=client_timeout)

        self.request2endpoint = REQUEST2ENDPOINT.copy()
        self.request2endpoint["UserClaimsRequest"] = "userclaims_endpoint"
        self.response2error = RESPONSE2ERROR.copy()
        self.response2error["UserClaimsResponse"] = ["ErrorResponse"]

    #noinspection PyUnusedLocal
    def construct_UserClaimsRequest(self, request=UserClaimsRequest,
                                    request_args=None, extra_args=None,
                                    **kwargs):

        return self.construct_request(request, request_args, extra_args)


    def do_claims_request(self, request=UserClaimsRequest,
                          request_resp=UserClaimsResponse,
                          body_type="json",
                          method="POST", request_args=None, extra_args=None,
                          http_args=None):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

#        http_args = self.init_authentication_method(csi, "bearer_header",
#                                                    request_args)

        return self.request_and_return(url, request_resp, method, body,
                                       body_type, extended=False,
                                       http_args=http_args,
                                       key=self.keyjar.verify_keys(
                                           self.keyjar.match_owner(url)))

class UserClaimsEndpoint(Endpoint) :
    type = "userclaims"

class UserClaimsInfoEndpoint(Endpoint) :
    type = "userclaimsinfo"
