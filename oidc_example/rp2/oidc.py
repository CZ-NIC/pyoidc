import logging
import sys
import traceback

import requests

from oic import oic
from oic import rndstr
from oic.oauth2 import PBase
from oic.oauth2.message import ErrorResponse
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import Response
from oic.utils.webfinger import WebFinger

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "OIC"
FLOW_TYPE = "code"

CLIENT_CONFIG = {}


class OpenIDConnect(object):
    def __init__(self, attribute_map=None, authenticating_authority=None,
                 name="", registration_info=None, **kwargs):
        self.attribute_map = attribute_map
        self.authenticating_authority = authenticating_authority
        self.name = name
        self.client_id = ""
        self.client_secret = ""

        for param in ["client_id", "client_secret"]:
            try:
                setattr(self, param, kwargs[param])
                del kwargs[param]
            except KeyError:
                pass

        self.extra = kwargs
        try:
            self.srv_discovery_url = kwargs["srv_discovery_url"]
        except KeyError:
            self.srv_discovery_url = None
        self.flow_type = FLOW_TYPE
        self.access_token_response = AccessTokenResponse
        self.client_cls = oic.Client
        self.authn_method = None
        self.registration_info = registration_info

    def dynamic(self, server_env, callback, logout_callback, session, key):
        try:
            client = server_env["OIC_CLIENT"][key]
        except KeyError:
            client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD)
            client.redirect_uris = [callback]
            client.post_logout_redirect_uris = [logout_callback]

            _me = self.registration_info.copy()
            _me["redirect_uris"] = [callback]

            provider_conf = client.provider_config(self.srv_discovery_url)
            logger.debug("Got provider config: %s", provider_conf)
            session['provider'] = provider_conf["issuer"]
            logger.debug("Registering RP")
            reg_info = client.register(provider_conf["registration_endpoint"],
                                       **_me)
            logger.debug("Registration response: %s", reg_info)
            for prop in ["client_id", "client_secret"]:
                try:
                    setattr(client, prop, reg_info[prop])
                except KeyError:
                    pass
            try:
                server_env["OIC_CLIENT"][key] = client
            except KeyError:
                server_env["OIC_CLIENT"] = {key: client}
        return client

    def static(self, server_env, callback, logout_callback, key):
        try:
            client = server_env["OIC_CLIENT"][key]
            logger.debug("Static client: %s", server_env["OIC_CLIENT"])
        except KeyError:
            client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD)
            client.redirect_uris = [callback]
            client.post_logout_redirect_uris = [logout_callback]
            for typ in ["authorization", "token", "userinfo"]:
                endpoint = "%s_endpoint" % typ
                setattr(client, endpoint, self.extra[endpoint])

            client.client_id = self.client_id
            client.client_secret = self.client_secret

            if "keys" in self.extra:
                client.keyjar.add(self.extra["keys"][0], self.extra["keys"][1])

            try:
                server_env["OIC_CLIENT"][key] = client
            except KeyError:
                server_env["OIC_CLIENT"] = {key: client}
        return client

    # noinspection PyUnusedLocal
    def begin(self, environ, server_env, start_response, session, key):
        """Step 1: Get a access grant.

        :param environ:
        :param start_response:
        :param server_env:
        :param session:
        """
        try:
            logger.debug("FLOW type: %s", self.flow_type)
            logger.debug("begin environ: %s", server_env)
            client = session['client']
            if client is not None and self.srv_discovery_url:
                data = {"client_id": client.client_id}
                resp = requests.get(self.srv_discovery_url + "verifyClientId",
                                    params=data, verify=False)
                if not resp.ok and resp.status_code == 400:
                    client = None
                    server_env["OIC_CLIENT"].pop(key, None)

            _state = ""
            if client is None:
                callback = server_env["base_url"] + key
                logout_callback = server_env["base_url"]
                if self.srv_discovery_url:
                    client = self.dynamic(server_env, callback, logout_callback,
                                          session, key)
                else:
                    client = self.static(server_env, callback, logout_callback,
                                         key)
                _state = session['state']
                session['client'] = client

            acr_value = session.get_acr_value(client.authorization_endpoint)
            try:
                acr_values = client.provider_info["acr_values_supported"]
                session['acr_values'] = acr_values
            except KeyError:
                acr_values = None

            if acr_value is None and acr_values is not None and \
                            len(acr_values) > 1:
                resp_headers = [("Location", str("/rpAcr"))]
                start_response("302 Found", resp_headers)
                return []
            elif acr_values is not None and len(acr_values) == 1:
                acr_value = acr_values[0]
            return self.create_authnrequest(environ, server_env, start_response,
                                            session, acr_value, _state)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(
                environ, start_response, server_env,
                (False, "Cannot find the OP! Please view your configuration."))

    # noinspection PyUnusedLocal
    def create_authnrequest(self, environ, server_env, start_response, session,
                            acr_value, state):
        try:
            client = session['client']
            session.set_acr_value(client.authorization_endpoint, acr_value)
            request_args = {
                "response_type": self.flow_type,
                "scope": server_env["SCOPE"],
                "state": state,
            }

            if acr_value is not None:
                request_args["acr_values"] = acr_value

            if self.flow_type == "token":
                request_args["nonce"] = rndstr(16)
                session['nonce'] = request_args["nonce"]
            else:
                use_nonce = getattr(self, "use_nonce", None)
                if use_nonce:
                    request_args["nonce"] = rndstr(16)
                    session['nonce'] = request_args["nonce"]

            logger.info("client args: %s", list(client.__dict__.items()))
            logger.info("request_args: %s", request_args)
            # User info claims
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(
                environ, start_response, server_env,
                (False, "Cannot find the OP! Please view your configuration."))

        try:
            cis = client.construct_AuthorizationRequest(
                request_args=request_args)
            logger.debug("request: %s", cis)

            url, body, ht_args, cis = client.uri_and_body(
                AuthorizationRequest, cis, method="GET",
                request_args=request_args)
            logger.debug("body: %s", body)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(environ, start_response, server_env, (
                False, "Authorization request can not be performed!"))

        logger.info("URL: %s", url)
        logger.debug("ht_args: %s", ht_args)

        session['client'] = client
        resp_headers = [("Location", str(url))]
        if ht_args:
            resp_headers.extend([(a, b) for a, b in ht_args.items()])
        logger.debug("resp_headers: %s", resp_headers)
        start_response("302 Found", resp_headers)
        return []

    def get_accesstoken(self, client, authresp):
        if self.srv_discovery_url:
            issuer = list(client.provider_info.keys())[0]
            # logger.debug("state: %s (%s)" % (client.state, msg["state"]))
            key = client.keyjar.get_verify_key(owner=issuer)
            kwargs = {"key": key}
            logger.debug("key: %s", key)
        else:
            kwargs = {"keyjar": client.keyjar}

        if self.authn_method:
            kwargs["authn_method"] = self.authn_method

        # get the access token
        return client.do_access_token_request(
            state=authresp["state"], response_cls=self.access_token_response,
            **kwargs)

    # noinspection PyUnusedLocal
    def verify_token(self, client, access_token):
        return {}

    def get_userinfo(self, client, authresp, access_token, **kwargs):
        # use the access token to get some userinfo
        return client.do_user_info_request(state=authresp["state"],
                                           schema="openid",
                                           access_token=access_token,
                                           **kwargs)

    # noinspection PyUnusedLocal
    def phaseN(self, environ, query, server_env, session):
        """Step 2: Once the consumer has redirected the user back to the
        callback URL you can request the access token the user has
        approved."""

        client = session['client']
        logger.debug("info: %s", query)
        logger.debug("keyjar: %s", client.keyjar)

        authresp = client.parse_response(AuthorizationResponse, query,
                                         sformat="dict", keyjar=client.keyjar)

        if isinstance(authresp, ErrorResponse):
            return False, "Access denied"
        try:
            client.id_token = authresp["id_token"]
        except:
            pass
        # session.session_id = msg["state"]

        logger.debug("callback environ: %s", environ)

        if self.flow_type == "code":
            # get the access token
            try:
                tokenresp = self.get_accesstoken(client, authresp)
            except Exception as err:
                logger.error("%s", err)
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

        logger.debug("UserInfo: %s", inforesp)

        return True, userinfo, access_token, client

    # noinspection PyUnusedLocal
    def callback(self, environ, server_env, start_response, query, session):
        """
        This is where we come back after the OP has done the
        Authorization Request.

        :param environ:
        :param server_env:
        :param start_response:
        :param query:
        :param session:
        :return:
        """
        _service = self.__class__.__name__

        logger.debug("[do_%s] environ: %s", _service, environ)
        logger.debug("[do_%s] query: %s", _service, query)

        try:
            result = self.phaseN(environ, query, server_env, session)
            session['login'] = True
            logger.debug("[do_%s] response: %s", _service, result)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            result = (False, "An unknown exception has occurred.")

        return self.result(environ, start_response, server_env, result)

    def result(self, environ, start_response, server_env, result):
        resp = Response(mako_template="opresult.mako",
                        template_lookup=server_env["template_lookup"],
                        headers=[])
        argv = {
            "result": result
        }
        return resp(environ, start_response, **argv)

    def find_srv_discovery_url(self, resource):
        """
        Use Webfinger to find the OP, The input is a unique identifier
        of the user. Allowed forms are the acct, mail, http and https
        urls. If no protocol specification is given like if only an
        email like identifier is given. It will be translated if possible to
        one of the allowed formats.

        :param resource: unique identifier of the user.
        :return:
        """

        wf = WebFinger(httpd=PBase(verify_ssl=self.extra["ca_bundle"]))
        return wf.discovery_query(resource)
