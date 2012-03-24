
__author__ = 'rohe0002'

from oic.oic import Server as OicServer
from oic.oic import Client
from oic.oic import REQUEST2ENDPOINT
from oic.oic import RESPONSE2ERROR

from oic.oic.message import message
#from oic.oic.message import SCHEMA

from oic.oic.provider import Provider, get_or_post, Endpoint

from oic.oauth2.message import SINGLE_REQUIRED_STRING, Message
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS

from oic.utils.http_util import Response, Unauthorized

# Used in claims.py
#from oic.oic.message import RegistrationRequest
#from oic.oic.message import RegistrationResponse

def verify(self, **kwargs):
    if self.jwt:
        # Try to decode the JWT, checks the signature
        try:
            item = message("OpenIDSchema").set_jwt(str(self.jwt),
                                                   kwargs["key"])
        except Exception, _err:
            raise Exception(_err.__class__.__name__)

        if not item.verify(**kwargs):
            return False

    return super(self.__class__, self).verify(**kwargs)

SCHEMA = {
    "": {"param": {}},
    "UserClaimsRequest": {
        "name": "UserClaimsRequest",
        "param": {
            "user_id": SINGLE_REQUIRED_STRING,
            "client_id": SINGLE_REQUIRED_STRING,
            "client_secret": SINGLE_REQUIRED_STRING,
            "claims_names": REQUIRED_LIST_OF_STRINGS
        },
    },
    "UserClaimsResponse": {
        "name": "UserClaimsResponse",
        "param": {
            "claims_names": REQUIRED_LIST_OF_STRINGS,
            "jwt": SINGLE_OPTIONAL_STRING,
            "endpoint": SINGLE_OPTIONAL_STRING,
            "access_token": SINGLE_OPTIONAL_STRING
        },
        "verify": verify,
    },
}

class OICCServer(OicServer):

    def parse_user_claims_request(self, info, format="urlencoded"):
        return self._parse_request(SCHEMA["UserClaimsRequest"], info, format)

class ClaimsServer(Provider):

    def __init__(self, name, sdb, cdb, function, userdb, urlmap=None,
                 debug=0, ca_certs="", jwt_keys=None):
        Provider.__init__(self, name, sdb, cdb, function, userdb, urlmap,
                          debug, ca_certs, jwt_keys)

        if jwt_keys is None:
            jwt_keys = []

        for cid, _dic in cdb.items():
            jwt_keys.append([_dic["client_secret"], "hmac", "sign", cid])
            jwt_keys.append([_dic["client_secret"], "hmac", "verify", cid])

        self.srvmethod = OICCServer(jwt_keys=jwt_keys)
        self.keystore = self.srvmethod.keystore
        self.claims_mode = "aggregate"

    def _aggregation(self, info, logger):

        jwt_key = self.keystore.get_sign_key()
        cresp = Message("UserClaimsResponse", SCHEMA["UserClaimsResponse"],
                        jwt=info.to_jwt(key=jwt_key, algorithm="RS256"),
                        claims_names=info.keys())

        logger.info("RESPONSE: %s" % (cresp.to_dict(),))
        return cresp

    #noinspection PyUnusedLocal
    def _distributed(self, ucreq, logger):
        return Message("UserClaimsResponse", SCHEMA["UserClaimsResponse"])

    #noinspection PyUnusedLocal
    def do_aggregation(self, info, uid):
        if self.claims_mode == "aggregate":
            return True
        else:
            return False

    #noinspection PyUnusedLocal
    def claims_endpoint(self, environ, start_response, logger, *args):
        _log_info = logger.info

        query = get_or_post(environ)
        ucreq = self.srvmethod.parse_user_claims_request(query)

        _log_info("request: %s" % ucreq)

        if not self.function["verify_client"](environ, ucreq, self.cdb):
            _log_info("could not verify client")
            err = message("TokenErrorResponse", error="unathorized_client")
            resp = Unauthorized(err.to_json(), content="application/json")
            return resp(environ, start_response)

        if "claims_names" in ucreq:
            args = dict([(n, {"optional": True}) for n in ucreq["claims_names"]])
            uic = message("UserInfoClaim", claims=message("Claims", **args))
        else:
            uic = None

        _log_info("User info claims: %s" % uic)

        info = self.function["userinfo"](self, self.userdb, ucreq["user_id"],
                                         user_info_claims=uic)

        _log_info("User info: %s" % info.to_dict())

        if self.do_aggregation(info, ucreq["user_id"]):
            cresp = self._aggregation(info, logger)
        else:
            cresp = self._distributed(info, logger)

        resp = Response(cresp.to_json(), content="application/json")
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
    def construct_UserClaimsRequest(self, schema=SCHEMA["UserClaimsRequest"],
                                    request_args=None, extra_args=None,
                                    **kwargs):

        return self.construct_request(schema, request_args, extra_args)


    def do_claims_request(self, schema=SCHEMA["UserClaimsRequest"],
                          resp_schema=SCHEMA["UserClaimsResponse"],
                          body_type="json",
                          method="POST", request_args=None, extra_args=None,
                          http_args=None):

        url, body, ht_args, csi = self.request_info(schema, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_schema, method, body,
                                       body_type, extended=False,
                                       http_args=http_args,
                                       key=self.keystore.pairkeys(
                                           self.keystore.match_owner(url)))

class UserClaimsEndpoint(Endpoint) :
    type = "userclaims"
