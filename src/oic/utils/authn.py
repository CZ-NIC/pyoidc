import base64
import logging
import time
from urllib import urlencode
from urlparse import parse_qs
from urlparse import urlsplit
from jwkest import Invalid
from jwkest import MissingKey
from jwkest.jws import alg2keytype
from oic.oauth2.exception import UnknownAssertionType
from oic.oauth2.exception import NotForMe
from oic.oauth2 import rndstr
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oic import REQUEST2ENDPOINT
from oic.oic import DEF_SIGN_ALG
from oic.oic import AuthnToken
from oic.oic import JWT_BEARER
from oic.utils.aes_m2c import AES_encrypt
from oic.utils.aes_m2c import AES_decrypt
from oic.utils.time_util import utc_now
from oic.utils.http_util import Response
from oic.utils.http_util import parse_cookie
from oic.utils.http_util import make_cookie
from oic.utils.http_util import Redirect
from oic.utils.http_util import Unauthorized
from saml2.saml import assertion_from_string

logger = logging.getLogger(__name__)

__author__ = 'rolandh'


class AuthnFailure(Exception):
    pass


class UserAuthnMethod(object):
    def __init__(self, srv):
        self.srv = srv

    def __call__(self, *args, **kwargs):
        raise NotImplemented

    def authenticated_as(self, **kwargs):
        raise NotImplemented

    def verify(self, **kwargs):
        raise NotImplemented


def url_encode_params(params=None):
    if not isinstance(params, dict):
        raise Exception("You must pass in a dictionary!")
    params_list = []
    for k, v in params.items():
        if isinstance(v, list):
            params_list.extend([(k, x) for x in v])
        else:
            params_list.append((k, v))
    return urlencode(params_list)


def create_return_url(base, query, **kwargs):
    """
    Add a query string plus extra parameters to a base URL which may contain
    a query part already.

    :param base: redirect_uri may contain a query part, no fragment allowed.
    :param query: Old query part as a string
    :param kwargs: extra query parameters
    :return:
    """
    part = urlsplit(base)
    if part.fragment:
        raise ValueError("Base URL contained parts it shouldn't")

    for key, values in parse_qs(query).items():
        if key in kwargs:
            if isinstance(kwargs[key], basestring):
                kwargs[key] = [kwargs[key]]
            kwargs[key].extend(values)
        else:
            kwargs[key] = values

    if part.query:
        for key, values in parse_qs(part.query).items():
            if key in kwargs:
                if isinstance(kwargs[key], basestring):
                    kwargs[key] = [kwargs[key]]
                kwargs[key].extend(values)
            else:
                kwargs[key] = values

        _pre = base.split("?")[0]
    else:
        _pre = base

    logger.debug("kwargs: %s" % kwargs)

    return "%s?%s" % (_pre, url_encode_params(kwargs))


class UsernamePasswordMako(UserAuthnMethod):
    """Do user authentication using the normal username password form in a
    WSGI environment using Mako as template system"""

    def __init__(self, srv, mako_template, template_lookup, pwd, return_to):
        """
        :param srv: The server instance
        :param mako_template: Which Mako template to use
        :param pwd: Username/password dictionary like database
        :param return_to: Where to send the user after authentication
        :return:
        """
        UserAuthnMethod.__init__(self, srv)
        self.mako_template = mako_template
        self.template_lookup = template_lookup
        self.passwd = pwd
        self.return_to = return_to
        self.active = {}
        self.query_param = "upm_answer"

    def __call__(self, cookie=None, policy_url=None, logo_url=None,
                 query="", **kwargs):
        """
        Put up the login form
        """
        if cookie:
            headers = [cookie]
        else:
            headers = []

        resp = Response(headers=headers)

        argv = {"login": "",
                "password": "",
                "action": "verify",
                "policy_url": policy_url,
                "logo_url": logo_url,
                "query": query}
        logger.info("do_authentication argv: %s" % argv)
        mte = self.template_lookup.get_template(self.mako_template)
        resp.message = mte.render(**argv)
        return resp

    def verify(self, request, **kwargs):
        """
        Verifies that the given username and password was correct
        :param request: Either the query part of a URL a urlencoded
            body of a HTTP message or a parse such.
        :param kwargs: Catch whatever else is sent.
        :return: redirect back to where ever the base applications
            wants the user after authentication.
        """

        logger.debug("verify(%s)" % request)
        if isinstance(request, basestring):
            _dict = parse_qs(request)
        elif isinstance(request, dict):
            _dict = request
        else:
            raise ValueError("Wrong type of input")

        logger.debug("dict: %s" % _dict)
        logger.debug("passwd: %s" % self.passwd)
        # verify username and password
        try:
            assert _dict["password"][0] == self.passwd[_dict["login"][0]]
            timestamp = str(int(time.mktime(time.gmtime())))
            info = AES_encrypt(self.srv.symkey,
                               "::".join([_dict["login"][0], timestamp]),
                               self.srv.iv)
            self.active[info] = timestamp
            cookie = make_cookie(self.srv.cookie_name, info, self.srv.seed,
                                 expire=0, domain="", path="")
            return_to = create_return_url(self.return_to, _dict["query"][0],
                                          **{self.query_param: "true"})
            resp = Redirect(return_to, headers=[cookie])
        except (AssertionError, KeyError):
            resp = Unauthorized("Unknown user or wrong password")

        return resp

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie is None:
            return None
        else:
            logger.debug("kwargs: %s" % kwargs)
            try:
                info, timestamp = parse_cookie(self.srv.cookie_name,
                                               self.srv.seed, cookie)
                if self.active[info] == timestamp:
                    #del self.active[info]
                    uid, _ts = AES_decrypt(self.srv.symkey,
                                           info, self.srv.iv).split("::")
                    if timestamp == _ts:
                        if "max_age" in kwargs and kwargs["max_age"]:
                            _now = int(time.mktime(time.gmtime()))
                            if _now > (int(_ts) + int(kwargs["max_age"])):
                                logger.debug("Authentication too old")
                                return None
                        return {"uid": uid}
            except Exception:
                pass

        return None

    def done(self, areq):
        try:
            _ = areq[self.query_param]
            return False
        except KeyError:
            return True


class AuthnMethodChooser(object):
    def __init__(self, methods=None):
        self.methods = methods

    def __call__(self, **kwargs):
        if not self.methods:
            raise Exception("No authentication methods defined")
        elif len(self.methods) == 1:
            return self.methods[0]
        else:
            pass  # TODO 


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
    def construct(self, cis, request_args=None, http_args=None, **kwargs):
        # Basic HTTP Authentication
        if http_args is None:
            http_args = {}
        try:
            http_args["auth"] = (self.cli.client_id, http_args["password"])
        except KeyError:
            try:
                http_args["auth"] = (self.cli.client_id, cis["client_secret"])
            except KeyError:
                http_args["auth"] = (self.cli.client_id, self.cli.client_secret)

        try:
            del cis["client_secret"]
        except KeyError:
            pass

        return http_args

    def verify(self, areq, client_id, **kwargs):
        if self.cli.cdb[client_id]["client_secret"] == areq["client_secret"]:
            return True
        else:
            return False


class ClientSecretPost(ClientSecretBasic):
    def construct(self, cis, request_args=None, http_args=None, **kwargs):
        if "client_secret" not in cis:
            try:
                cis["client_secret"] = http_args["client_secret"]
                del http_args["client_secret"]
            except (KeyError, TypeError):
                cis["client_secret"] = self.cli.client_secret

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
            _acc_token = kwargs["access_token"]

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
    def choose_algorithm(self, entity="client_secret_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, entity, **kwargs)

    def get_signing_key(self, algorithm):
        return self.cli.keyjar.get_signing_key(alg2keytype(algorithm))


class PrivateKeyJWT(JWSAuthnMethod):

    def choose_algorithm(self, entity="private_key_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(self, entity, **kwargs)

    def get_signing_key(self, algorithm):
        return self.cli.keyjar.get_signing_key(alg2keytype(algorithm), "")


SAML2_BEARER_ASSERTION_TYPE = \
    "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"


class SAML2AuthnMethod(ClientAuthnMethod):
    """
    Authenticating clients using the SAML2 assertion profile
    """
    def construct(self, cis, assertion=None, **kwargs):
        """

        :param cis: The request
        :param assertion: A SAML2 Assertion
        :param kwargs: Extra arguments
        :return: Constructed HTTP arguments, in this case none
        """

        cis["client_assertion"] = base64.urlsafe_b64encode(str(assertion))
        cis["client_assertion_type"] = SAML2_BEARER_ASSERTION_TYPE

    def verify(self, areq, **kwargs):
        xmlstr = base64.urlsafe_b64decode(areq["client_assertion"])
        try:
            assertion = assertion_from_string(xmlstr)
        except:
            return False
        return self._verify_saml2_assertion(assertion)

    def _verify_saml2_assertion(self, assertion):
        subject = assertion.subject
        #client_id = subject.name_id.text
        #who_ever_issued_it = assertion.issuer.text

        audience = []
        for ar in subject.audience_restiction:
            for aud in ar.audience:
                audience.append(aud)


CLIENT_AUTHN_METHOD = {
    "client_secret_basic": ClientSecretBasic,
    "client_secret_post": ClientSecretPost,
    "bearer_header": BearerHeader,
    "bearer_body": BearerBody,
    "client_secret_jwt": ClientSecretJWT,
    "private_key_jwt": PrivateKeyJWT,
    "saml2_bearer": SAML2AuthnMethod
}


def verify_client(inst, areq, authn):
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
        if areq["client_assertion_type"] == JWT_BEARER:
            return JWSAuthnMethod(inst).verify(areq)
        elif areq["client_assertion_type"] == SAML2_BEARER_ASSERTION_TYPE:
            return SAML2AuthnMethod(inst).verify(areq)
        else:
            raise UnknownAssertionType(areq["client_assertion_type"])
    else:
        return True
