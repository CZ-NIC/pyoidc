__author__ = 'rohe0002'

from oic import oauth2
from oic.oic import Server as OicServer
from oic.oic import Client
from oic.oic.server import Server, get_or_post
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oauth2.message import ErrorResponse

from oic.utils.http_util import Response
from oic.oic import REQUEST2ENDPOINT
from oic.oic import RESPONSE2ERROR

#from oic.oic.message import IdToken, OpenIDSchema
from oic.oic.message import Claims
from oic.oic.message import OpenIDSchema
from oic.oic.message import UserInfoClaim

class UserClaimsRequest(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["user_id"] = SINGLE_REQUIRED_STRING
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["client_secret"] = SINGLE_REQUIRED_STRING
    c_attributes["claims_names"] = REQUIRED_LIST_OF_STRINGS

    def __init__(self,
                 user_id=None,
                 client_id=None,
                 client_secret=None,
                 claims_names=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.user_id = user_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.claims_names = claims_names

class UserClaimsResponse(oauth2.Base):
    c_attributes = oauth2.Base.c_attributes.copy()
    c_attributes["claims_names"] = REQUIRED_LIST_OF_STRINGS
    c_attributes["jwt"] = SINGLE_OPTIONAL_STRING
    c_attributes["endpoint"] = SINGLE_OPTIONAL_STRING
    c_attributes["access_token"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 jwt=None,
                 claims_names=None,
                 endpoint=None,
                 access_token=None,
                 **kwargs):
        oauth2.Base.__init__(self, **kwargs)
        self.jwt = jwt
        self.claims_names = claims_names
        self.endpoint = endpoint
        self.access_token = access_token

    def verify(self, **kwargs):
        if self.jwt:
            # Try to decode the JWT, checks the signature
            try:
                item = OpenIDSchema.set_jwt(str(self.jwt), kwargs["key"])
            except Exception, _err:
                raise Exception(_err.__class__.__name__)

            if not item.verify(**kwargs):
                return False

        return oauth2.Base.verify(self, **kwargs)

class OICCServer(OicServer):

    def parse_user_claims_request(self, info, format="urlencoded",
                                  extended=True):
        return self._parse_request(UserClaimsRequest, info, format, extended)

class ClaimsServer(Server):

    def __init__(self, name, sdb, cdb, function, keys, userdb, urlmap=None,
                 debug=0, cache=None, timeout=None, proxy_info=None,
                 follow_redirects=True, ca_certs="", jwt_keys=None):
        Server.__init__(self, name, sdb, cdb, function, keys, userdb, urlmap,
                        debug, cache, timeout, proxy_info,
                        follow_redirects, ca_certs, jwt_keys)

        self.srvmethod = OICCServer(jwt_keys)

    #noinspection PyUnusedLocal
    def claims_endpoint(self, environ, start_response, logger, *args):
        _log_info = logger.info

        query = get_or_post(environ)
        ucreq = self.srvmethod.parse_user_claims_request(query)

        _log_info("request: %s" % ucreq)

        if ucreq.claims_names:
            args = dict([(n, None) for n in ucreq.claims_names])
            uic = UserInfoClaim(claims=[Claims(**args)])
        else:
            uic = None

        _log_info("User info claims: %s" % uic)

        info = self.function["userinfo"](self.userdb, ucreq.user_id,
                                         user_info_claims=uic)

        _log_info("User info: %s" % info.dictionary())

        jwt_key = {"hmac":self.cdb[ucreq.client_id]["client_secret"]}
        cresp = UserClaimsResponse(jwt=info.get_jwt(key=jwt_key),
                                   claims_names=info.keys())

        _log_info("RESPONSE: %s" % (cresp.dictionary(),))
        resp = Response(cresp.get_json(), content="application/json")
        return resp(environ, start_response)

class ClaimsClient(Client):

    def __init__(self, client_id=None, cache=None, timeout=None,
                 proxy_info=None, follow_redirects=True,
                 disable_ssl_certificate_validation=False, ca_certs="",
                 client_timeout=0, expire_in=0, grant_expire_in=0,
                 httpclass=None):

        Client.__init__(self, client_id, cache, timeout,
                        proxy_info, follow_redirects,
                        disable_ssl_certificate_validation,
                        ca_certs, client_timeout, expire_in, grant_expire_in,
                        httpclass)

        self.request2endpoint = REQUEST2ENDPOINT.copy()
        self.request2endpoint["UserClaimsRequest"] = "userclaims_endpoint"
        self.response2error = RESPONSE2ERROR.copy()
        self.response2error[UserClaimsResponse] = [ErrorResponse]

    #noinspection PyUnusedLocal
    def construct_UserClaimsRequest(self, cls=UserClaimsRequest,
                                         request_args=None, extra_args=None,
                                         **kwargs):

        return self.construct_request(cls, request_args, extra_args)


    def do_claims_request(self, cls=UserClaimsRequest,
                          resp_cls=UserClaimsResponse, body_type="json",
                          method="POST", request_args=None, extra_args=None,
                          http_args=None):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       body_type, extended=False,
                                       http_args=http_args,
                                       key=self.verify_key)

