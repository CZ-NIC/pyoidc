import requests

__author__ = 'haho0032'
import traceback
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from rp1 import Social
from oic import oic
#from oic.oic import consumer
from oic.oauth2 import rndstr
from oic.oauth2.message import ErrorResponse

from oic.oic.message import AuthorizationResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AccessTokenResponse

import logging
import sys

logger = logging.getLogger(__name__)


def token_secret_key(sid):
    return "token_secret_%s" % sid

SERVICE_NAME = "OIC"
#CLIENT_REDIRECT_URIS = ["http://lingon.catalogix.se:8091/oic"]
FLOW_TYPE = "code" # or "token"

CLIENT_CONFIG = {}

ME = {
    "application_type": "web",
    "application_name": "idpproxy",
    "contacts": ["ops@example.com"],
}


class OpenIDConnect(Social):
    def __init__(self, client_id, client_secret, **kwargs):
        Social.__init__(self, client_id, client_secret, **kwargs)
        try:
            self.srv_discovery_url = kwargs["srv_discovery_url"]
        except KeyError:
            self.srv_discovery_url = None
        self.flow_type = FLOW_TYPE
        self.access_token_response = AccessTokenResponse
        self.client_cls = oic.Client
        self.authn_method = None

    def dynamic(self, server_env, callback, logoutCallback, session):
        try:
            client = server_env["OIC_CLIENT"][self.opKey]
        except KeyError:
            client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD)
            client.redirect_uris = [callback]
            client.post_logout_redirect_uris = [logoutCallback]
            _me = ME.copy()
            _me["redirect_uris"] = [callback]

            provider_conf = client.provider_config(self.srv_discovery_url)
            logger.debug("Got provider config: %s" % provider_conf)
            logger.debug("Registering RP")
            reg_info = client.register(provider_conf["registration_endpoint"],
                                       **_me)
            logger.debug("Registration response: %s" % reg_info)
            for prop in ["client_id", "client_secret"]:
                try:
                    setattr(client, prop, reg_info[prop])
                except KeyError:
                    pass
            try:
                server_env["OIC_CLIENT"][self.opKey] = client
            except KeyError:
                server_env["OIC_CLIENT"] = {self.opKey: client}

        return client

    def static(self, server_env, callback, logoutCallback):
        try:
            client = server_env["OIC_CLIENT"][self.opKey]
            logger.debug("Static client: %s" % server_env["OIC_CLIENT"])
        except KeyError:
            client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD)
            client.redirect_uris = [callback]
            client.post_logout_redirect_uris = [logoutCallback]
            for typ in ["authorization", "token", "userinfo"]:
                endpoint = "%s_endpoint" % typ
                setattr(client, endpoint, self.extra[endpoint])

            client.client_id = self.client_id
            client.client_secret = self.client_secret

            if "keys" in self.extra:
                client.keyjar.add(self.extra["keys"][0],self.extra["keys"][1])

            try:
                server_env["OIC_CLIENT"][self.opKey] = client
            except KeyError:
                server_env["OIC_CLIENT"] = {self.opKey: client}
        return client

    #noinspection PyUnusedLocal
    def begin(self, environ, server_env, start_response, session):
        """Step 1: Get a access grant.

        :param environ:
        :param server_env:
        :param start_response:
        :param session:
        """
        try:
            logger.debug("FLOW type: %s" % self.flow_type)
            logger.debug("begin environ: %s" % server_env)
            client = session.getClient()
            if client is not None and self.srv_discovery_url:
                data = {"client_id": client.client_id}
                resp = requests.get(self.srv_discovery_url + "verifyClientId",
                            params=data, verify=False)
                if not resp.ok and resp.status_code == 400:
                    client = None
                    server_env["OIC_CLIENT"].pop(self.opKey, None)
            if client is None:
                callback = server_env["base_url"] + self.opKey
                logoutCallback = server_env["base_url"]

                if self.srv_discovery_url:
                    client = self.dynamic(server_env, callback, logoutCallback, session)
                else:
                    client = self.static(server_env, callback, logoutCallback)
                client.state = session.getState()
                session.setClient(client)
                session.setService(self.opKey)
            acr_value = session.getAcrValue(client.authorization_endpoint)
            try:
                acr_values = client.provider_info[self.srv_discovery_url]["acr_values"].split()
                session.setAcrvalues(acr_values)
            except:
                pass

            if acr_value is None and acr_values is not None and len(acr_values) > 1:
                resp_headers = [("Location", str("/rpAcr?key="+self.opKey))]
                start_response("302 Found", resp_headers)
                return []
            elif acr_value is None and acr_values is not None and len(acr_values) == 1:
                    acr_value = acr_values[0]
            return self.create_authnrequest(environ, server_env, start_response, session, acr_value)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(
                environ, start_response, server_env,
                (False, "Cannot find the OP! Please view your configuration."))

    #noinspection PyUnusedLocal
    def create_authnrequest(self, environ, server_env, start_response, session, acr_value):
        try:
            client = session.getClient()
            session.setAcrValue(client.authorization_endpoint, acr_value)
            request_args = {
                "response_type": self.flow_type,
                "scope": self.extra["scope"],
                "state":  client.state,
            }

            if acr_value is not None:
                request_args["acr_values"] = acr_value

            if self.flow_type == "token":
                request_args["nonce"] = rndstr(16)
                session.setNonce(request_args["nonce"])
            else:
                use_nonce = getattr(self, "use_nonce", None)
                if use_nonce:
                    request_args["nonce"] = rndstr(16)
                    session.setNonce(request_args["nonce"])


            logger.info("client args: %s" % client.__dict__.items(),)
            logger.info("request_args: %s" % (request_args,))
            # User info claims
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(environ, start_response, server_env,(False, "Cannot find the OP! Please view your configuration of pyoidc RP."))


        try:
            cis = client.construct_AuthorizationRequest(
                request_args=request_args)
            logger.debug("request: %s" % cis)

            url, body, ht_args, cis = client.uri_and_body(
                AuthorizationRequest, cis, method="GET",
                request_args=request_args)
            logger.debug("body: %s" % body)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(environ, start_response, server_env,(False, "Authorization request can not be performed!"))

        logger.info("URL: %s" % url)
        logger.debug("ht_args: %s" % ht_args)

        #session.setAuthn_auth(client.authorization_endpoint)
        #session.setAuthentication("VERIFY")

        #server_env["CACHE"][sid] = session
        session.setClient(client)
        resp_headers = [("Location", str(url))]
        if ht_args:
            resp_headers.extend([(a, b) for a, b in ht_args.items()])
        logger.debug("resp_headers: %s" % resp_headers)
        start_response("302 Found", resp_headers)
        return []

    def get_accesstoken(self, client, authresp):
        if self.srv_discovery_url:
            issuer = client.provider_info.keys()[0]
            #logger.debug("state: %s (%s)" % (client.state, msg["state"]))
            key = client.keyjar.get_verify_key(owner=issuer)
            kwargs = {"key": key}
            logger.debug("key: %s" % key)
        else:
            kwargs = {"keyjar": client.keyjar}

        if self.authn_method:
            kwargs["authn_method"] = self.authn_method

        # get the access token
        return client.do_access_token_request(
            state=authresp["state"], response_cls=self.access_token_response,
            **kwargs)

    #noinspection PyUnusedLocal
    def verify_token(self, client, access_token):
        return {}

    def get_userinfo(self, client, authresp, access_token, **kwargs):
        # use the access token to get some userinfo
        return client.do_user_info_request(state=authresp["state"],
                                           schema="openid",
                                           access_token=access_token,
                                           **kwargs)

    #noinspection PyUnusedLocal
    def phaseN(self, environ, query, server_env, session):
        """Step 2: Once the consumer has redirected the user back to the
        callback URL you can request the access token the user has
        approved."""

        client = session.getClient()
        logger.debug("info: %s" % query)
        logger.debug("keyjar: %s" % client.keyjar)

        authresp = client.parse_response(AuthorizationResponse, query,
                                         sformat="dict")

        if isinstance(authresp, ErrorResponse):
            return False, "Access denied"

        #session.session_id = msg["state"]

        logger.debug("callback environ: %s" % environ)

        if self.flow_type == "code":
            # get the access token
            try:
                tokenresp = self.get_accesstoken(client, authresp)
            except Exception, err:
                logger.error("%s" % err)
                raise

            if isinstance(tokenresp, ErrorResponse):
                return (False, "Invalid response %s." % tokenresp["error"])

            access_token = tokenresp["access_token"]
        else:
            access_token = authresp["access_token"]

        userinfo = self.verify_token(client, access_token)

        inforesp = self.get_userinfo(client, authresp, access_token)

        if isinstance(inforesp, ErrorResponse):
            return False, "Invalid response %s." % inforesp["error"], session

        tot_info = userinfo.update(inforesp.to_dict())

        logger.debug("UserInfo: %s" % inforesp)

        return True, userinfo, access_token, client



