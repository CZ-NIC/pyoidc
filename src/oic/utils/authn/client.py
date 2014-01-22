import logging
from jwkest import Invalid
from jwkest import MissingKey
from jwkest.jws import alg2keytype
from oic.oauth2.exception import UnknownAssertionType
from oic.oauth2.exception import NotForMe
from oic.oauth2 import rndstr, VREQUIRED
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oic import REQUEST2ENDPOINT
from oic.oic import DEF_SIGN_ALG
from oic.oic import AuthnToken
from oic.oic import JWT_BEARER
from oic.utils.time_util import utc_now


logger = logging.getLogger(__name__)

__author__ = 'rolandh'


class AuthnFailure(Exception):
    pass


# ========================================================================
def assertion_jwt(cli, keys, audience, algorithm):
    _now = utc_now()

    at = AuthnToken(iss=cli.client_id, sub=cli.client_id,
                    aud=audience, jti=rndstr(8),
                    exp=_now + 600, iat=_now)
    return at.to_jwt(key=keys, algorithm=algorithm)


class ClientAuthnMethod(object):
    def __init__(self, cli=None):
        """
        :param cli: Client instance
        """
        self.cli = cli

    def construct(self, **kwargs):
        """ Add authentication information to a request
        :return:
        """
        raise NotImplementedError

    def verify(self, **kwargs):
        """
        Verify authentication information in a request
        :param kwargs:
        :return:
        """
        raise NotImplementedError


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.
    """
    def construct(self, cis, request_args=None, http_args=None, **kwargs):
        # Basic HTTP Authentication
        if http_args is None:
            http_args = {}

        try:
            passwd = kwargs["password"]
        except KeyError:
            try:
                passwd = http_args["password"]
            except KeyError:
                try:
                    passwd = cis["client_secret"]
                except KeyError:
                    passwd = self.cli.client_secret

        try:
            user = kwargs["user"]
        except KeyError:
            user = self.cli.client_id

        http_args["auth"] = (user, passwd)

        try:
            del cis["client_secret"]
        except KeyError:
            pass

        if not cis.c_param["client_id"][VREQUIRED]:
            del cis["client_id"]

        return http_args

    def verify(self, areq, client_id, **kwargs):
        if self.cli.cdb[client_id]["client_secret"] == areq["client_secret"]:
            return client_id
        else:
            raise AuthnFailure()


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.
    """
    def construct(self, cis, request_args=None, http_args=None, **kwargs):
        if "client_secret" not in cis:
            try:
                cis["client_secret"] = http_args["client_secret"]
                del http_args["client_secret"]
            except (KeyError, TypeError):
                if self.cli.client_secret:
                    cis["client_secret"] = self.cli.client_secret
                else:
                    raise AuthnFailure("Missing client secret")

        cis["client_id"] = self.cli.client_id

        return http_args


class BearerHeader(ClientAuthnMethod):
    def construct(self, cis=None, request_args=None, http_args=None,
                  **kwargs):
        """
        More complicated logic then I would have liked it to be

        :param cli: Client instance
        :param cis: Request class instance
        :param request_args: request arguments
        :param http_args: HTTP header arguments
        :param kwargs:
        :return:
        """

        if cis:
            if "access_token" in cis:
                _acc_token = cis["access_token"]
                del cis["access_token"]
                # Required under certain circumstances :-) not under other
                cis.c_param["access_token"] = SINGLE_OPTIONAL_STRING
            else:
                try:
                    _acc_token = request_args["access_token"]
                    del request_args["access_token"]
                except (KeyError, TypeError):
                    try:
                        _acc_token = kwargs["access_token"]
                    except KeyError:
                        try:
                            _ = kwargs["state"]
                        except KeyError:
                            if not self.cli.state:
                                raise Exception("Missing state specification")
                            kwargs["state"] = self.cli.state

                        _acc_token = self.cli.get_token(**kwargs).access_token
        else:
            try:
                _acc_token = kwargs["access_token"]
            except KeyError:
                _acc_token = request_args["access_token"]

        # Do I need to base64 encode the access token ? Probably !
        #_bearer = "Bearer %s" % base64.b64encode(_acc_token)
        _bearer = "Bearer %s" % _acc_token
        if http_args is None:
            http_args = {"headers": {}}
            http_args["headers"]["Authorization"] = _bearer
        else:
            try:
                http_args["headers"]["Authorization"] = _bearer
            except KeyError:
                http_args["headers"] = {"Authorization": _bearer}

        return http_args


class BearerBody(ClientAuthnMethod):
    def construct(self, cis, request_args=None, http_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        if "access_token" in cis:
            pass
        else:
            try:
                cis["access_token"] = request_args["access_token"]
            except KeyError:
                try:
                    _ = kwargs["state"]
                except KeyError:
                    if not self.cli.state:
                        raise Exception("Missing state specification")
                    kwargs["state"] = self.cli.state

                cis["access_token"] = self.cli.get_token(**kwargs).access_token

        return http_args


def bearer_auth(req, authn):
    """
    Pick out the access token, either in HTTP_Authorization header or
    in request body.

    :param req:
    :param authn:
    :return:
    """

    try:
        return req["access_token"]
    except KeyError:
        assert authn.startswith("Bearer ")
        return authn[7:]


class JWSAuthnMethod(ClientAuthnMethod):

    def choose_algorithm(self, entity, **kwargs):
        try:
            algorithm = kwargs["algorithm"]
        except KeyError:
            algorithm = DEF_SIGN_ALG[entity]
        if not algorithm:
            raise Exception("Missing algorithm specification")
        return algorithm

    def get_signing_key(self, algorithm):
        return self.cli.keyjar.get_signing_key(alg2keytype(algorithm))

    def construct(self, cis, request_args=None, http_args=None, **kwargs):
        """
        Constructs a client assertion and signs it with a key.
        The request is modified as a side effect.

        :param cis: The request
        :param request_args: request arguments
        :param http_args: HTTP arguments
        :param kwargs: Extra arguments
        :return: Constructed HTTP arguments, in this case none
        """

        # audience is the OP endpoint
        audience = self.cli._endpoint(REQUEST2ENDPOINT[cis.type()])

        algorithm = self.choose_algorithm(**kwargs)
        signing_key = self.get_signing_key(algorithm)

        cis["client_assertion"] = assertion_jwt(self.cli, signing_key, audience,
                                                algorithm)
        cis["client_assertion_type"] = JWT_BEARER

        try:
            del cis["client_secret"]
        except KeyError:
            pass

        return {}

    def verify(self, areq, **kwargs):
        try:
            bjwt = AuthnToken().from_jwt(areq["client_assertion"],
                                         keyjar=self.cli.keyjar)
        except (Invalid, MissingKey), err:
            logger.info("%s" % err)
            return False

        logger.debug("authntoken: %s" % bjwt.to_dict())
        logger.debug("known clients: %s" % self.cli.cdb.keys())
        try:
            # There might not be a client_id in the request
            assert str(bjwt["iss"]) in self.cli.cdb  # It's a client I know
        except KeyError:
            pass

        # aud can be a string or a list
        _aud = bjwt["aud"]
        logger.debug("audience: %s, baseurl: %s" % (_aud, self.cli.baseurl))
        try:
            if isinstance(_aud, basestring):
                assert str(_aud).startswith(self.cli.baseurl)
            else:
                for target in _aud:
                    if target.startswith(self.cli.baseurl):
                        return True
                raise NotForMe("Not for me!")
        except AssertionError:
            raise NotForMe("Not for me!")

        return True


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """
    def choose_algorithm(self, entity="client_secret_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, entity, **kwargs)

    def get_signing_key(self, algorithm):
        return self.cli.keyjar.get_signing_key(alg2keytype(algorithm))


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key sign a JWT using that key.
    """
    def choose_algorithm(self, entity="private_key_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, entity, **kwargs)

    def get_signing_key(self, algorithm):
        return self.cli.keyjar.get_signing_key(alg2keytype(algorithm), "")


#from oic.utils.authn.client_saml import SAML2_BEARER_ASSERTION_TYPE


CLIENT_AUTHN_METHOD = {
    "client_secret_basic": ClientSecretBasic,
    "client_secret_post": ClientSecretPost,
    "bearer_header": BearerHeader,
    "bearer_body": BearerBody,
    "client_secret_jwt": ClientSecretJWT,
    "private_key_jwt": PrivateKeyJWT,
}

TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)]


def verify_client(inst, areq, authn, type_method=TYPE_METHOD):
    """

    :param areq: The request
    :param authn: client authentication information
    :return:
    """

    client_id = inst.get_client_id(areq, authn)

    logger.debug("Verified Client ID: %s" % client_id)

    if "client_secret" in areq:  # client_secret_post/client_secret_basic
        return ClientSecretBasic(inst).verify(areq, client_id)
    elif "client_assertion" in areq:  # client_secret_jwt or public_key_jwt
        for typ, method in type_method:
            if areq["client_assertion_type"] == typ:
                return method(inst).verify(areq)
        else:
            raise UnknownAssertionType(areq["client_assertion_type"])
    else:
        return client_id
