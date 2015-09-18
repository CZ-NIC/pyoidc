import logging
import base64
from jwkest import Invalid
from jwkest import MissingKey
from jwkest.jws import alg2keytype
import time
import six

from oic.exception import UnknownAssertionType, FailedAuthentication
from oic.exception import NotForMe
from oic.oauth2 import rndstr, VREQUIRED
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oic import REQUEST2ENDPOINT
from oic.oic import DEF_SIGN_ALG
from oic.oic import AuthnToken
from oic.oic import JWT_BEARER


logger = logging.getLogger(__name__)

__author__ = 'rolandh'


class AuthnFailure(Exception):
    pass


class NoMatchingKey(Exception):
    pass


# ========================================================================
def assertion_jwt(cli, keys, audience, algorithm):
    _now = time.time()

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
        """
        :param cis: Request class instance
        :param request_args: Request arguments
        :param http_args: HTTP arguments
        :return: dictionary of HTTP arguments
        """

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

        if "headers" not in http_args:
            http_args["headers"] = {}

        http_args["headers"]["Authorization"] = "Basic %s" % base64.b64encode(
            "{}:{}".format(user, passwd).encode("utf-8")).decode("utf-8")

        try:
            del cis["client_secret"]
        except KeyError:
            pass

        if cis and not cis.c_param["client_id"][VREQUIRED]:
            try:
                del cis["client_id"]
            except KeyError:
                pass

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
                        _acc_token = self.cli.get_token(**kwargs).access_token
        else:
            try:
                _acc_token = kwargs["access_token"]
            except KeyError:
                _acc_token = request_args["access_token"]

        # Do I need to base64 encode the access token ? Probably !
        # _bearer = "Bearer %s" % base64.b64encode(_acc_token)
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

    def verify(self, environ, **kwargs):
        try:
            cred = environ["HTTP_AUTHORIZATION"]
        except KeyError:
            raise AuthnFailure("missing authorization info")

        try:
            assert cred.startswith("Bearer ")
        except AssertionError:
            raise AuthnFailure("Wrong type of authorization token")

        label, token = cred.split(" ")
        return token


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
                        raise AuthnFailure("Missing state specification")
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
            raise AuthnFailure("Missing algorithm specification")
        return algorithm

    def get_signing_key(self, algorithm):
        return self.cli.keyjar.get_signing_key(alg2keytype(algorithm),
                                               alg=algorithm)

    def get_key_by_kid(self, kid, algorithm):
        _key = self.cli.keyjar.get_key_by_kid(kid)
        if _key:
            ktype = alg2keytype(algorithm)
            try:
                assert _key.kty == ktype
            except AssertionError:
                raise NoMatchingKey("Wrong key type")
            else:
                return _key
        else:
            raise NoMatchingKey("No key with kid:%s" % kid)

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
        ktype = alg2keytype(algorithm)
        try:
            if 'kid' in kwargs:
                signing_key = [self.get_key_by_kid(kwargs["kid"], algorithm)]
            elif ktype in self.cli.kid["sig"]:
                try:
                    signing_key = [self.get_key_by_kid(
                        self.cli.kid["sig"][ktype], algorithm)]
                except KeyError:
                    signing_key = self.get_signing_key(algorithm)
            else:
                signing_key = self.get_signing_key(algorithm)
        except NoMatchingKey as err:
            logger.error("%s" % err)
            raise SystemError()

        cis["client_assertion"] = assertion_jwt(self.cli, signing_key, audience,
                                                algorithm)
        cis["client_assertion_type"] = JWT_BEARER

        try:
            del cis["client_secret"]
        except KeyError:
            pass

        if not cis.c_param["client_id"][VREQUIRED]:
            try:
                del cis["client_id"]
            except KeyError:
                pass

        return {}

    def verify(self, areq, **kwargs):
        try:
            bjwt = AuthnToken().from_jwt(areq["client_assertion"],
                                         keyjar=self.cli.keyjar)
        except (Invalid, MissingKey) as err:
            logger.info("%s" % err)
            raise AuthnFailure("Could not verify client_assertion.")

        logger.debug("authntoken: %s" % bjwt.to_dict())
        # logger.debug("known clients: %s" % self.cli.cdb.keys())
        try:
            cid = kwargs["client_id"]
        except KeyError:
            cid = bjwt["iss"]

        try:
            # There might not be a client_id in the request
            assert str(cid) in self.cli.cdb  # It's a client I know
        except KeyError:
            pass

        # aud can be a string or a list
        _aud = bjwt["aud"]
        logger.debug("audience: %s, baseurl: %s" % (_aud, self.cli.baseurl))
        try:
            if isinstance(_aud, six.string_types):
                assert str(_aud).startswith(self.cli.baseurl)
            else:
                for target in _aud:
                    if target.startswith(self.cli.baseurl):
                        return cid
                raise NotForMe("Not for me!")
        except AssertionError:
            raise NotForMe("Not for me!")

        return cid


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
        return self.cli.keyjar.get_signing_key(alg2keytype(algorithm),
                                               alg=algorithm)


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key sign a JWT using that key.
    """

    def choose_algorithm(self, entity="private_key_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, entity, **kwargs)

    def get_signing_key(self, algorithm):
        return self.cli.keyjar.get_signing_key(alg2keytype(algorithm), "",
                                               alg=algorithm)


# from oic.utils.authn.client_saml import SAML2_BEARER_ASSERTION_TYPE


CLIENT_AUTHN_METHOD = {
    "client_secret_basic": ClientSecretBasic,
    "client_secret_post": ClientSecretPost,
    "bearer_header": BearerHeader,
    "bearer_body": BearerBody,
    "client_secret_jwt": ClientSecretJWT,
    "private_key_jwt": PrivateKeyJWT,
}

TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)]


def get_client_id(cdb, req, authn):
    """
    Verify the client and return the client id

    :param req: The request
    :param authn: Authentication information from the HTTP header
    :return:
    """

    logger.debug("REQ: %s" % req.to_dict())
    if authn:
        if authn.startswith("Basic "):
            logger.debug("Basic auth")
            (_id, _secret) = base64.b64decode(
                authn[6:].encode("utf-8")).decode("utf-8").split(":")
            _id = _id.encode("utf-8")
            if _id not in cdb:
                logger.debug("Unknown client_id")
                raise FailedAuthentication("Unknown client_id")
            else:
                try:
                    assert _secret == cdb[_id]["client_secret"]
                except AssertionError:
                    logger.debug("Incorrect secret")
                    raise FailedAuthentication("Incorrect secret")
        else:
            try:
                assert authn[:6].lower() == "bearer"
                logger.debug("Bearer auth")
                _token = authn[7:]
            except AssertionError:
                raise FailedAuthentication("AuthZ type I don't know")

            try:
                _id = cdb[_token]
            except KeyError:
                logger.debug("Unknown access token")
                raise FailedAuthentication("Unknown access token")
    else:
        try:
            _id = str(req["client_id"])
            if _id not in cdb:
                logger.debug("Unknown client_id")
                raise FailedAuthentication("Unknown client_id")
        except KeyError:
            raise FailedAuthentication("Missing client_id")

    return _id


def verify_client(inst, areq, authn, type_method=TYPE_METHOD):
    """
    Initiated Guessing !

    :param areq: The request
    :param authn: client authentication information
    :return:
    """

    if authn:  # HTTP Basic auth (client_secret_basic)
        return get_client_id(inst.cdb, areq, authn)
    elif "client_secret" in areq:  # client_secret_post
        client_id = get_client_id(inst.cdb, areq, authn)
        logger.debug("Verified Client ID: %s" % client_id)
        return ClientSecretBasic(inst).verify(areq, client_id)
    elif "client_assertion" in areq:  # client_secret_jwt or private_key_jwt
        for typ, method in type_method:
            if areq["client_assertion_type"] == typ:
                return method(inst).verify(areq)
        else:
            raise UnknownAssertionType(areq["client_assertion_type"], areq)
    else:
        raise FailedAuthentication("Missing client authentication.")
