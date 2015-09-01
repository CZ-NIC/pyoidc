from oic.utils.http_util import Redirect
from oic.exception import MissingAttribute
from oic import oic
from oic.oauth2 import rndstr, ErrorResponse
from oic.oic import ProviderConfigurationResponse, AuthorizationResponse
from oic.oic import RegistrationResponse
from oic.oic import AuthorizationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

__author__ = 'roland'

import logging

logger = logging.getLogger(__name__)


class OIDCError(Exception):
    pass


class Client(oic.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        oic.Client.__init__(self, client_id, ca_certs, client_prefs,
                            client_authn_method, keyjar, verify_ssl)
        if behaviour:
            self.behaviour = behaviour

    def create_authn_request(self, session, acr_value=None, **kwargs):
        session["state"] = rndstr()
        session["nonce"] = rndstr()
        request_args = {
            "response_type": self.behaviour["response_type"],
            "scope": self.behaviour["scope"],
            "state": session["state"],
            "nonce": session["nonce"],
            "redirect_uri": self.registration_response["redirect_uris"][0]
        }

        if acr_value is not None:
            request_args["acr_values"] = acr_value

        request_args.update(kwargs)
        cis = self.construct_AuthorizationRequest(request_args=request_args)
        logger.debug("request: %s" % cis)

        url, body, ht_args, cis = self.uri_and_body(AuthorizationRequest, cis,
                                                    method="GET",
                                                    request_args=request_args)

        logger.debug("body: %s" % body)
        logger.info("URL: %s" % url)
        logger.debug("ht_args: %s" % ht_args)

        resp = Redirect(str(url))
        if ht_args:
            resp.headers.extend([(a, b) for a, b in ht_args.items()])
        logger.debug("resp_headers: %s" % resp.headers)
        return resp

    def callback(self, response, session):
        """
        This is the method that should be called when an AuthN response has been
        received from the OP.

        :param response: The URL returned by the OP
        :return:
        """
        authresp = self.parse_response(AuthorizationResponse, response,
                                       sformat="dict", keyjar=self.keyjar)

        if isinstance(authresp, ErrorResponse):
            if authresp["error"] == "login_required":
                return self.create_authn_request(session)
            else:
                return OIDCError("Access denied")

        if session["state"] != authresp["state"]:
            return OIDCError("Received state not the same as expected.")

        try:
            if authresp["id_token"] != session["nonce"]:
                return OIDCError("Received nonce not the same as expected.")
            self.id_token[authresp["state"]] = authresp["id_token"]
        except KeyError:
            pass

        if self.behaviour["response_type"] == "code":
            # get the access token
            try:
                args = {
                    "code": authresp["code"],
                    "redirect_uri": self.registration_response[
                        "redirect_uris"][0],
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }

                atresp = self.do_access_token_request(
                    scope="openid", state=authresp["state"], request_args=args,
                    authn_method=self.registration_response["token_endpoint_auth_method"])
            except Exception as err:
                logger.error("%s" % err)
                raise

            if isinstance(atresp, ErrorResponse):
                raise OIDCError("Invalid response %s." % atresp["error"])

        try:
            kwargs = {"method": self.userinfo_request_method}
        except AttributeError:
            kwargs = {}

        inforesp = self.do_user_info_request(state=authresp["state"], **kwargs)

        if isinstance(inforesp, ErrorResponse):
            raise OIDCError("Invalid response %s." % inforesp["error"])

        userinfo = inforesp.to_dict()

        logger.debug("UserInfo: %s" % inforesp)

        return userinfo


class OIDCClients(object):
    def __init__(self, config):
        """

        :param config: Imported configuration module
        :return:
        """
        self.client = {}
        self.client_cls = Client
        self.config = config

        for key, val in config.CLIENTS.items():
            if key == "":
                continue
            else:
                self.client[key] = self.create_client(**val)

    def create_client(self, userid="", **kwargs):
        """
        Do an instantiation of a client instance

        :param userid: An identifier of the user
        :param: Keyword arguments
            Keys are ["srv_discovery_url", "client_info", "client_registration",
            "provider_info"]
        :return: client instance
        """

        _key_set = set(list(kwargs.keys()))
        args = {}
        for param in ["verify_ssl"]:
            try:
                args[param] = kwargs[param]
            except KeyError:
                pass
            else:
                _key_set.discard(param)

        client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 behaviour=kwargs["behaviour"], verify_ssl=self.config.VERIFY_SSL, **args)

        try:
            client.userinfo_request_method = kwargs["userinfo_request_method"]
        except KeyError:
            pass
        else:
            _key_set.discard("userinfo_request_method")

        # The behaviour parameter is not significant for the election process
        _key_set.discard("behaviour")
        for param in ["allow"]:
            try:
                setattr(client, param, kwargs[param])
            except KeyError:
                pass
            else:
                _key_set.discard(param)

        if _key_set == set(["client_info"]):  # Everything dynamic
            # There has to be a userid
            if not userid:
                raise MissingAttribute("Missing userid specification")

            # Find the service that provides information about the OP
            issuer = client.wf.discovery_query(userid)
            # Gather OP information
            _ = client.provider_config(issuer)
            # register the client
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == set(["client_info", "srv_discovery_url"]):
            # Ship the webfinger part
            # Gather OP information
            _ = client.provider_config(kwargs["srv_discovery_url"])
            # register the client
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == set(["provider_info", "client_info"]):
            client.handle_provider_config(
                ProviderConfigurationResponse(**kwargs["provider_info"]),
                kwargs["provider_info"]["issuer"])
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == set(["provider_info", "client_registration"]):
            client.handle_provider_config(
                ProviderConfigurationResponse(**kwargs["provider_info"]),
                kwargs["provider_info"]["issuer"])
            client.store_registration_info(RegistrationResponse(
                **kwargs["client_registration"]))
        elif _key_set == set(["srv_discovery_url", "client_registration"]):
            _ = client.provider_config(kwargs["srv_discovery_url"])
            client.store_registration_info(RegistrationResponse(
                **kwargs["client_registration"]))
        else:
            raise Exception("Configuration error ?")

        return client

    def dynamic_client(self, userid):
        client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 verify_ssl=self.config.VERIFY_SSL)

        issuer = client.wf.discovery_query(userid)
        if issuer in self.client:
            return self.client[issuer]
        else:
            # Gather OP information
            _pcr = client.provider_config(issuer)
            # register the client
            _ = client.register(_pcr["registration_endpoint"],
                                **self.config.CLIENTS[""]["client_info"])
            try:
                client.behaviour.update(**self.config.CLIENTS[""]["behaviour"])
            except KeyError:
                pass

            self.client[issuer] = client
            return client

    def __getitem__(self, item):
        """
        Given a service or user identifier return a suitable client
        :param item:
        :return:
        """
        try:
            return self.client[item]
        except KeyError:
            return self.dynamic_client(item)

    def keys(self):
        return list(self.client.keys())
