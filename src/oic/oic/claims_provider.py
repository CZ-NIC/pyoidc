import logging

from oic import rndstr
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import Message
from oic.oic import Server as OicServer
from oic.oic import REQUEST2ENDPOINT
from oic.oic import RESPONSE2ERROR
from oic.oic import Client
from oic.oic.message import Claims
from oic.oic.message import OpenIDSchema
from oic.oic.provider import Endpoint
from oic.oic.provider import Provider
from oic.utils.authn.client import bearer_auth
from oic.utils.http_util import Response
from oic.utils.keyio import KeyJar
from oic.utils.sanitize import sanitize

__author__ = 'rohe0002'

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
    def parse_user_claims_request(self, info, sformat="urlencoded"):
        return self._parse_request(UserClaimsRequest, info, sformat)

    def parse_userinfo_claims_request(self, info, sformat="urlencoded"):
        return self._parse_request(UserInfoClaimsRequest, info, sformat)


class ClaimsServer(Provider):
    def __init__(self, name, sdb, cdb, userinfo, client_authn, urlmap=None,
                 ca_certs="", keyjar=None, hostname="", dist_claims_mode=None):
        Provider.__init__(self, name, sdb, cdb, None, userinfo, None,
                          client_authn, "", urlmap, ca_certs, keyjar,
                          hostname)

        if keyjar is None:
            keyjar = KeyJar(ca_certs)

        for cid, _dic in cdb.items():
            try:
                keyjar.add_symmetric(cid, _dic["client_secret"], ["sig", "ver"])
            except KeyError:
                pass

        self.srvmethod = OICCServer(keyjar=keyjar)
        self.dist_claims_mode = dist_claims_mode
        self.info_store = {}
        self.claims_userinfo_endpoint = ""

    def _aggregation(self, info):

        jwt_key = self.keyjar.get_signing_key()
        cresp = UserClaimsResponse(jwt=info.to_jwt(key=jwt_key,
                                                   algorithm="RS256"),
                                   claims_names=list(info.keys()))

        logger.info("RESPONSE: %s" % (sanitize(cresp.to_dict()),))
        return cresp

    def _distributed(self, info):
        # store the user info so it can be accessed later
        access_token = rndstr()
        self.info_store[access_token] = info
        return UserClaimsResponse(endpoint=self.claims_userinfo_endpoint,
                                  access_token=access_token,
                                  claims_names=info.keys())

    def do_aggregation(self, info, uid):
        return self.dist_claims_mode.aggregate(uid, info)

    def claims_endpoint(self, request, http_authz, *args):
        _log_info = logger.info

        ucreq = self.srvmethod.parse_user_claims_request(request)

        _log_info("request: %s" % sanitize(ucreq))

        try:
            self.client_authn(self, ucreq, http_authz)
        except Exception as err:
            _log_info("Failed to verify client due to: %s" % err)

        if "claims_names" in ucreq:
            args = dict([(n, {"optional": True}) for n in
                         ucreq["claims_names"]])
            uic = Claims(**args)
        else:
            uic = None

        _log_info("User info claims: %s" % sanitize(uic))

        # oicsrv, userdb, subject, client_id="", user_info_claims=None
        info = self.userinfo(ucreq["sub"], user_info_claims=uic,
                             client_id=ucreq["client_id"])

        _log_info("User info: %s" % sanitize(info))

        # Convert to message format
        info = OpenIDSchema(**info)

        if self.do_aggregation(info, ucreq["sub"]):
            cresp = self._aggregation(info)
        else:
            cresp = self._distributed(info)

        _log_info("response: %s" % sanitize(cresp.to_dict()))

        return Response(cresp.to_json(), content="application/json")

    def claims_info_endpoint(self, request, authn):
        _log_info = logger.info

        _log_info("Claims_info_endpoint query: '%s'" % sanitize(request))

        ucreq = self.srvmethod.parse_userinfo_claims_request(request)
        # _log_info("request: %s" % sanitize(ucreq))

        # Bearer header or body
        access_token = bearer_auth(ucreq, authn)
        uiresp = OpenIDSchema(**self.info_store[access_token])

        _log_info("returning: %s" % sanitize(uiresp.to_dict()))
        return Response(uiresp.to_json(), content="application/json")


class ClaimsClient(Client):
    def __init__(self, client_id=None, ca_certs=""):

        Client.__init__(self, client_id, ca_certs)

        self.request2endpoint = REQUEST2ENDPOINT.copy()
        self.request2endpoint["UserClaimsRequest"] = "userclaims_endpoint"
        self.response2error = RESPONSE2ERROR.copy()
        self.response2error["UserClaimsResponse"] = ["ErrorResponse"]

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

        # http_args = self.init_authentication_method(csi, "bearer_header",
        #                                                    request_args)

        return self.request_and_return(url, request_resp, method, body,
                                       body_type, extended=False,
                                       http_args=http_args,
                                       key=self.keyjar.verify_keys(
                                           self.keyjar.match_owner(url)))


class UserClaimsEndpoint(Endpoint):
    etype = "userclaims"


class UserClaimsInfoEndpoint(Endpoint):
    etype = "userclaimsinfo"
