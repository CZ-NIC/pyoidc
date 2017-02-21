import importlib
import json
import logging
import sys
from urllib.parse import quote_plus, unquote_plus

from jwkest import as_unicode

from oic.federation.bundle import FSJWKSBundle
from oic.federation.entity import FederationEntity
from oic.federation.operator import Operator
from oic.utils import shelve_wrapper
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.authn_context import make_auth_verify
from oic.utils.authn.client import verify_client
from oic.utils.authn.javascript_login import JavascriptFormMako
from oic.utils.authn.multi_auth import AuthnIndexedEndpointWrapper
from oic.utils.authn.multi_auth import setup_multi_auth
from oic.utils.authn.saml import SAMLAuthnMethod
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import keyjar_init, build_keyjar
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
from oic.utils.userinfo.aa_info import AaUserInfo

logger = logging.getLogger(__name__)


class AuthSetup(object):
    def __init__(self, config, issuer):
        self.config = config
        self.issuer = issuer
        self.root = None
        self.lookup = None
        self.username_password_authn = None
        self.saml_authn = None
        self.javascript_login_authn = None
        self.urls = []
        self.ac = AuthnBroker()
        self.authn = False

        end_points = config.AUTHENTICATION["UserPassword"]["END_POINTS"]
        self.full_end_point_paths = [
            "{}{}".format(self.issuer, ep) for ep in end_points]

        self.auth_methods = {
            "UserPassword": self.user_password,
            "JavascriptLogin": self.javascript_login,
            "SAML": self.saml_login,
            "SamlPass": self.saml_pass_login,
            "JavascriptPass": self.javascript_passw_login
        }

    def init_mako(self):
        if self.root is None:
            self.root = self.config.MAKO_ROOT
        if self.lookup is None:
            from mako.lookup import TemplateLookup

            self.lookup = TemplateLookup(
                directories=[self.root + 'templates', self.root + 'htdocs'],
                module_directory=self.root + 'modules',
                input_encoding='utf-8', output_encoding='utf-8')

    def user_password(self, info):
        self.init_mako()

        self.username_password_authn = UsernamePasswordMako(
            None, "login.mako", self.lookup, self.config.PASSWD,
            "%sauthorization" % self.issuer,
            None, self.full_end_point_paths)

        PASSWORD_END_POINT_INDEX = 0

        end_point = info["END_POINTS"][PASSWORD_END_POINT_INDEX]
        authn = AuthnIndexedEndpointWrapper(self.username_password_authn,
                                            PASSWORD_END_POINT_INDEX)
        self.urls.append((r'^' + end_point, make_auth_verify(authn.verify)))
        return authn

    def javascript_login(self, info):
        if self.javascript_login_authn is None:
            self.init_mako()

            end_points = self.config.AUTHENTICATION[
                "JavascriptLogin"]["END_POINTS"]
            full_end_point_paths = [
                "{}{}".format(self.issuer, ep) for ep in end_points]

            self.javascript_login_authn = JavascriptFormMako(
                None, "javascript_login.mako", self.lookup, self.config.PASSWD,
                "{}authorization".format(self.issuer), None,
                full_end_point_paths)

        self.ac.add("", self.javascript_login_authn, "", "")
        JAVASCRIPT_END_POINT_INDEX = 0
        end_point = info["END_POINTS"][JAVASCRIPT_END_POINT_INDEX]
        authn = AuthnIndexedEndpointWrapper(self.javascript_login_authn,
                                            JAVASCRIPT_END_POINT_INDEX)
        self.urls.append((r'^' + end_point, make_auth_verify(authn.verify)))
        return authn

    def saml_login(self, info):
        from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST

        if self.saml_authn is None:
            self.init_mako()

            self.saml_authn = SAMLAuthnMethod(
                None, self.lookup, self.config.SAML, self.config.SP_CONFIG,
                self.issuer, "{}authorization".format(self.issuer),
                userinfo=self.config.USERINFO)

        self.ac.add("", self.saml_authn, "", "")
        SAML_END_POINT_INDEX = 0
        end_point = info["END_POINTS"][SAML_END_POINT_INDEX]
        end_point_indexes = {BINDING_HTTP_REDIRECT: 0, BINDING_HTTP_POST: 0,
                             "disco_end_point_index": 0}
        authn = AuthnIndexedEndpointWrapper(self.saml_authn, end_point_indexes)
        self.urls.append((r'^' + end_point, make_auth_verify(authn.verify)))
        return authn

    def saml_pass_login(self, info):
        from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST

        if self.saml_authn is None:
            self.init_mako()

            self.saml_authn = SAMLAuthnMethod(
                None, self.lookup, self.config.SAML, self.config.SP_CONFIG,
                self.issuer, "{}authorization".format(self.issuer),
                userinfo=self.config.USERINFO)

        PASSWORD_END_POINT_INDEX = 1
        SAML_END_POINT_INDEX = 1
        password_end_point = self.config.AUTHENTICATION['UserPassword'][
            "END_POINTS"][PASSWORD_END_POINT_INDEX]
        saml_endpoint = info["END_POINTS"][SAML_END_POINT_INDEX]

        end_point_indexes = {BINDING_HTTP_REDIRECT: 1, BINDING_HTTP_POST: 1,
                             "disco_end_point_index": 1}
        multi_saml = AuthnIndexedEndpointWrapper(self.saml_authn,
                                                 end_point_indexes)
        multi_password = AuthnIndexedEndpointWrapper(
            self.username_password_authn, PASSWORD_END_POINT_INDEX)

        auth_modules = [(multi_saml, r'^' + saml_endpoint),
                        (multi_password, r'^' + password_end_point)]
        return setup_multi_auth(self.ac, self.urls, auth_modules)

    def javascript_passw_login(self, info):
        if self.javascript_login_authn is None:
            self.init_mako()

            end_points = self.config.AUTHENTICATION[
                "JavascriptLogin"]["END_POINTS"]
            full_end_point_paths = [
                "{}{}".format(self.issuer, ep) for ep in end_points]
            self.javascript_login_authn = JavascriptFormMako(
                None, "javascript_login.mako", self.lookup, self.config.PASSWD,
                "{}authorization".format(self.issuer), None,
                full_end_point_paths)

        PASSWORD_END_POINT_INDEX = 2
        JAVASCRIPT_POINT_INDEX = 1

        password_end_point = self.config.AUTHENTICATION["UserPassword"][
            "END_POINTS"][PASSWORD_END_POINT_INDEX]
        javascript_end_point = info["END_POINTS"][JAVASCRIPT_POINT_INDEX]

        multi_password = AuthnIndexedEndpointWrapper(
            self.username_password_authn, PASSWORD_END_POINT_INDEX)
        multi_javascript = AuthnIndexedEndpointWrapper(
            self.javascript_login_authn, JAVASCRIPT_POINT_INDEX)

        auth_modules = [(multi_password, r'^' + password_end_point),
                        (multi_javascript, r'^' + javascript_end_point)]
        return setup_multi_auth(self.ac, self.urls, auth_modules)

    def __call__(self):
        for authkey, value in self.config.AUTHENTICATION.items():
            authn = self.auth_methods[authkey](value)
            if authn is not None:
                self.ac.add(value["ACR"], authn, value["WEIGHT"], "")


def op_setup(args, config, provider_cls):
    # Client data base
    cdb = shelve_wrapper.open("client_db")

    if args.issuer:
        _issuer = args.issuer[0]
    else:
        if args.port not in [80, 443]:
            _issuer = config.ISSUER + ':{}'.format(args.port)
        else:
            _issuer = config.ISSUER

    if _issuer[-1] != '/':
        _issuer += '/'

    config.SERVICE_URL = config.SERVICE_URL.format(issuer=_issuer)

    auth_setup = AuthSetup(config, _issuer)
    auth_setup()

    # dealing with authorization
    authz = AuthzHandling()

    auth_setup.init_mako()

    kwargs = {
        "template_lookup": auth_setup.lookup,
        "template": {"form_post": "form_response.mako"},
        # "template_args": {"form_post": {"action": "form_post"}}
    }

    # Should I care about verifying the certificates used by other entities
    if args.insecure:
        kwargs["verify_ssl"] = False
    else:
        kwargs["verify_ssl"] = True

    if args.capabilities:
        kwargs["capabilities"] = json.loads(open(args.capabilities).read())
    else:
        pass

    _op = provider_cls(_issuer, SessionDB(_issuer), cdb, auth_setup.ac, None,
                       authz, verify_client, config.SYM_KEY, **kwargs)
    _op.baseurl = _issuer

    for authn in auth_setup.ac:
        authn.srv = _op

    if config.USERINFO == "SIMPLE":
        # User info is a simple dictionary in this case statically defined in
        # the configuration file
        _op.userinfo = UserInfo(config.USERDB)
    elif config.USERINFO == "SAML":
        _op.userinfo = UserInfo(config.SAML)
    elif config.USERINFO == "AA":
        _op.userinfo = AaUserInfo(config.SP_CONFIG, _issuer, config.SAML)
    else:
        raise Exception("Unsupported userinfo source")

    try:
        _op.cookie_ttl = config.COOKIETTL
    except AttributeError:
        pass

    try:
        _op.cookie_name = config.COOKIENAME
    except AttributeError:
        pass

    # print URLS
    if args.debug:
        _op.debug = True

    try:
        jwks = keyjar_init(_op, config.keys, kid_template="op%d")
    except Exception as err:
        logger.error("Key setup failed: %s" % err)
        _op.key_setup("static", sig={"format": "jwk", "alg": "rsa"})
    else:
        f = open(config.JWKS_FILE_NAME, "w")
        f.write(json.dumps(jwks))
        f.close()

        _op.jwks_uri = "%s%s" % (_op.baseurl, config.JWKS_FILE_NAME)
        _op.keyjar.verify_ssl = kwargs["verify_ssl"]

    for b in _op.keyjar[""]:
        logger.info("OC3 server keys: %s" % b)

    return _op


def fed_setup(iss, provider, conf):
    bundle = FSJWKSBundle(iss, fdir=conf.JWKS_DIR,
                          key_conv={'to': quote_plus, 'from': unquote_plus})

    sig_keys = build_keyjar(conf.SIG_KEYS)[1]

    provider.federation_entity = FederationEntity(
        provider, iss=iss, keyjar=sig_keys, fo_bundle=bundle,
        signed_metadata_statements_dir=conf.SMS_DIR)

    provider.fo_priority = conf.FO_PRIORITY
