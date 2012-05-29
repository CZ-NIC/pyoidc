#!/usr/bin/env python
#
__author__ = 'rohe0002'

import requests
import random
import string
import copy

from oic.utils.time_util import utc_time_sans_frac
from oic.utils.jwt import construct_rsa_jwk

DEF_SIGN_ALG = "HS256"

from oic.oauth2.message import *

Version = "2.0"

HTTP_ARGS = ["headers", "redirections", "connection_type"]

DEFAULT_POST_CONTENT_TYPE = 'application/x-www-form-urlencoded'

REQUEST2ENDPOINT = {
    "AuthorizationRequest": "authorization_endpoint",
    "AccessTokenRequest": "token_endpoint",
    #    ROPCAccessTokenRequest: "authorization_endpoint",
    #    CCAccessTokenRequest: "authorization_endpoint",
    "RefreshAccessTokenRequest": "token_endpoint",
    "TokenRevocationRequest": "token_endpoint",
    }

RESPONSE2ERROR = {
    "AuthorizationResponse": [AuthorizationErrorResponse, TokenErrorResponse],
    "AccessTokenResponse": [TokenErrorResponse]
}

ENDPOINTS = ["authorization_endpoint", "token_endpoint",
             "token_revocation_endpoint"]

class HTTP_ERROR(Exception):
    pass

class MISSING_REQUIRED_ATTRIBUTE(Exception):
    pass

def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    _basech = string.ascii_letters + string.digits
    return "".join([random.choice(_basech) for _ in range(size)])

# -----------------------------------------------------------------------------
# Authentication Methods

#noinspection PyUnusedLocal
def client_secret_basic(cli, cis, request_args=None, http_args=None, **kwargs):
    if http_args is None:
        http_args = {}
    try:
        http_args["auth"] = (cli.client_id, http_args["password"])
    except KeyError:
        http_args["auth"] = (cli.client_id, cli.client_secret)

    return http_args

#noinspection PyUnusedLocal
def client_secret_post(cli, cis, request_args=None, http_args=None, **kwargs):

    if request_args is None:
        request_args = {}

    if "client_secret" not in cis:
        try:
            cis["client_secret"] = http_args["client_secret"]
            del http_args["client_secret"]
        except (KeyError, TypeError):
            cis["client_secret"] = cli.client_secret

    cis["client_id"] = cli.client_id

    return http_args

#noinspection PyUnusedLocal
def bearer_header(cli, cis, request_args=None, http_args=None, **kwargs):
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
                _state = kwargs["state"]
            except KeyError:
                if not cli.state:
                    raise Exception("Missing state specification")
                kwargs["state"] = cli.state

            _acc_token= cli.get_token(**kwargs).access_token

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

#noinspection PyUnusedLocal
def bearer_body(cli, cis, request_args=None, http_args=None, **kwargs):
    if request_args is None:
        request_args = {}

    if "access_token" in cis:
        pass
    else:
        try:
            cis["access_token"] = request_args["access_token"]
        except KeyError:
            try:
                _state = kwargs["state"]
            except KeyError:
                if not cli.state:
                    raise Exception("Missing state specification")
                kwargs["state"] = cli.state

            cis["access_token"] = cli.get_token(**kwargs).access_token

    return http_args

AUTHN_METHOD = {
    "client_secret_basic": client_secret_basic,
    "client_secret_post" : client_secret_post,
    "bearer_header": bearer_header,
    "bearer_body": bearer_body,
    }

# -----------------------------------------------------------------------------

class ExpiredToken(Exception):
    pass

# -----------------------------------------------------------------------------

class Token(object):
    def __init__(self, resp=None):
        self.scope = []
        self.token_expiration_time = 0
        self.access_token = None
        self.refresh_token = None
        self.token_type = None
        self.replaced = False

        if resp:
            for prop, val in resp.items():
                setattr(self, prop, val)

            try:
                _expires_in = resp["expires_in"]
            except KeyError:
                return

            if _expires_in:
                _tet = utc_time_sans_frac() + int(_expires_in)
            else:
                _tet = 0
            self.token_expiration_time = int(_tet)


    def is_valid(self):
        if self.token_expiration_time:
            if utc_time_sans_frac() > self.token_expiration_time:
                return False

        return True

    def __str__(self):
        return "%s" % self.__dict__

    def keys(self):
        return self.__dict__.keys()

    def __eq__(self, other):
        skeys = self.keys()
        okeys = other.keys()
        if set(skeys) != set(okeys):
            return False

        for key in skeys:
            if getattr(self, key) != getattr(other, key):
                return False

        return True

class Grant(object):
    _authz_resp = AuthorizationResponse
    _acc_resp = AccessTokenResponse
    _token_class = Token

    def __init__(self, exp_in=600, resp=None, seed=""):
        self.grant_expiration_time = 0
        self.exp_in = exp_in
        self.seed = seed
        self.tokens = []
        self.id_token = None
        if resp:
            self.add_code(resp)
            self.add_token(resp)

    @classmethod
    def from_code(cls, resp):
        instance = cls()
        instance.add_code(resp)
        return instance

    def add_code(self, resp):
        try:
            self.code = resp["code"]
            self.grant_expiration_time = utc_time_sans_frac() + self.exp_in
        except KeyError:
            pass

    def add_token(self, resp):
        """
        :param resp: A Authorization Response instance
        """

        if "access_token" in resp:
            tok = self._token_class(resp)
            self.tokens.append(tok)

    def is_valid(self):
        if utc_time_sans_frac() > self.grant_expiration_time:
            return False
        else:
            return True

    def __str__(self):
        return "%s" % self.__dict__

    def keys(self):
        return self.__dict__.keys()

    def update(self, resp):
        if "access_token" in resp or "id_token" in resp:
            tok = self._token_class(resp)
            if tok not in self.tokens:
                for otok in self.tokens:
                    otok.replaced = True
                self.tokens.append(tok)

        if "code" in resp:
            self.add_code(resp)

    def get_token(self, scope=""):
        token = None
        if scope:
            for token in self.tokens:
                if scope in token.scope and not token.replaced:
                    return token
        else:
            for token in self.tokens:
                if token.is_valid() and not token.replaced:
                    return token

        return token

    def get_id_token(self):
        return self.id_token

    def join(self, grant):
        if not self.exp_in:
            self.exp_in = grant.exp_in
        if not self.grant_expiration_time:
            self.grant_expiration_time = grant.grant_expiration_time
        if not self.seed:
            self.seed = grant.seed
        for token in grant.tokens:
            if token not in self.tokens:
                for otok in self.tokens:
                    if token.scope == otok.scope:
                        otok.replaced = True
                self.tokens.append(token)

KEYLOADERR = "Failed to load %s key from '%s' (%s)"

class KeyStore(object):
    use = ["sign", "verify", "enc", "dec"]
    url_types = ["x509_url", "x509_encryption_url", "jwk_url",
                 "jwk_encryption_url"]

    def __init__(self, http_request, keyspecs=None):
        self._store = {}
        self.http_request = http_request

        if keyspecs:
            for keyspec in keyspecs:
                self.add_key(*keyspec)

    def add_key(self, key, type, usage, owner="."):
        """
        :param key: The key
        :param type: Type of key (rsa, ec, hmac, .. )
        :param usage: What to use the key for (signing, verifying, encrypting,
            decrypting
        """

        if owner not in self._store:
            self._store[owner] = {"sign": {}, "verify": {}, "enc": {},
                                  "dec": {}}
            self._store[owner][usage][type] = [key]
        else:
            _keys = self._store[owner][usage]
            try:
                _keys[type].append(key)
            except KeyError:
                _keys[type] = [key]

    def get_keys(self, usage, type=None, owner="."):
        if not owner:
            res = {}
            for owner, _spec in self._store.items():
                res[owner] = _spec[usage]
            return res
        else:
            try:
                if type:
                    return self._store[owner][usage][type]
                else:
                    return self._store[owner][usage]
            except KeyError:
                return {}

    def pairkeys(self, part):
        """
        Keys for me and someone else.

        :param part: The other part
        :return: dictionary of keys
        """
        _coll = self.keys_by_owner(part)
        if part != ".":
            for usage, spec in self.keys_by_owner(".").items():
                for typ, keys in spec.items():
                    try:
                        _coll[usage][typ].extend(keys)
                    except KeyError:
                        _coll[usage][typ] = keys

        return _coll

    def keys_by_owner(self, owner):
        try:
            return self._store[owner]
        except KeyError:
            return {}

    def remove_key_collection(self, owner):
        try:
            del self._store[owner]
        except Exception:
            pass

    def remove_key(self, key, owner=".", type=None, usage=None):
        try:
            _keys = self._store[owner]
        except KeyError:
            return

        rem = []
        if usage:
            if type:
                _keys[usage][type].remove(key)
            else:
                for _typ, vals in self._store[owner][usage].items():
                    try:
                        vals.remove(key)
                        if not vals:
                            rem.append((usage, _typ))
                    except Exception:
                        pass
        else:
            for _usage, item in _keys.items():
                if type:
                    _keys[_usage][type].remove(key)
                else:
                    for _typ, vals in _keys[_usage].items():
                        try:
                            vals.remove(key)
                            if not vals:
                                rem.append((_usage, _typ))
                        except Exception:
                            pass

        for _use, _typ in rem:
            del self._store[owner][_use][_typ]
            if not self._store[owner][_use]:
                del self._store[owner][_use]

    def remove_key_type(self, type, owner="."):
        try:
            _keys = self._store[owner]
        except KeyError:
            return

        for _usage in _keys.keys():
            try:
                del self._store[owner][_usage][type]
                if not self._store[owner][_usage]:
                    del self._store[owner][_usage]
            except KeyError:
                pass

    def get_verify_key(self, type="", owner="."):
        return self.get_keys("verify", type, owner)

    def get_sign_key(self, type="", owner="."):
        return self.get_keys("sign", type, owner)

    def get_encrypt_key(self, type="", owner="."):
        return self.get_keys("enc", type, owner)

    def get_decrypt_key(self, type="", owner="."):
        return self.get_keys("dec", type, owner)

    def set_verify_key(self, val, type="hmac", owner="."):
        self.add_key(val, type, "verify", owner)

    def set_sign_key(self, val, type="hmac", owner="."):
        self.add_key(val, type, "sign", owner)

    def set_encrypt_key(self, val, type="hmac", owner="."):
        self.add_key(val, type, "enc", owner)

    def set_decrypt_key(self, val, type="hmac", owner="."):
        self.add_key(val, type, "dec", owner)

    def match_owner(self, url):
        for owner in self._store.keys():
            if url.startswith(owner):
                return owner

        raise Exception("No keys for '%s'" % url)

    def collect_keys(self, url, usage="verify"):
        try:
            owner = self.match_owner(url)
            keys = self.get_keys(usage, owner=owner)
        except Exception:
            keys = None

        try:
            own_keys = self.get_keys(usage)
            if keys:
                for type, key in own_keys.items():
                    keys[type].extend(key)
            else:
                keys = own_keys
        except KeyError:
            pass

        return keys

    def __contains__(self, owner):
        if owner in self._store:
            return True
        else:
            return False

    def has_key_of_type(self, owner, usage, type):
        try:
            _ = self._store[owner][usage][type]
            return True
        except KeyError:
            return False

    def load_x509_cert(self, url, usage, owner):
        try:
            r = self.http_request(url, allow_redirects=True)
            if r.status_code == 200:
                _key = jwt.x509_rsa_loads(r.text)
                self.add_key(_key, "rsa", usage, owner)
                return _key
            else:
                raise Exception("HTTP Get error: %s" % r.status_code)
        except Exception, err: # not a RSA key
            return None

    def load_jwk(self, url, usage, owner):
        r = self.http_request(url, allow_redirects=True)
        if r.status_code != 200:
            raise Exception("HTTP Get error: %s" % r.status_code)

        res = []
        for tag, key in jwt.jwk_loads(r.text).items():
            if tag.startswith("rsa"):
                self.add_key(key, "rsa", usage, owner)
                res.append(key)

        return res

    def load_keys(self, inst, _issuer, replace=False):
        for attr in self.url_types:
            if attr in inst:
                if replace:
                    self.remove_key_collection(_issuer)
                break

        if "x509_url" in inst and inst["x509_url"]:
            try:
                _verkey = self.load_x509_cert(inst["x509_url"], "verify",
                                              _issuer)
            except Exception:
                raise Exception(KEYLOADERR % ('x509', inst["x509_url"]))
        else:
            _verkey = None

        if "x509_encryption_url" in inst and inst["x509_encryption_url"]:
            try:
                self.load_x509_cert(inst["x509_encryption_url"], "enc",
                                    _issuer)
            except Exception:
                raise Exception(KEYLOADERR % ('x509_encryption',
                                              inst["x509_encryption_url"]))
        elif _verkey:
            self.set_decrypt_key(_verkey, "rsa", _issuer)

        if "jwk_url" in inst and inst["jwk_url"]:
            try:
                _verkeys = self.load_jwk(inst["jwk_url"], "verify", _issuer)
            except Exception, err:
                raise Exception(KEYLOADERR % ('jwk', inst["jwk_url"], err))
        else:
            _verkeys = []

        if "jwk_encryption_url" in inst and inst["jwk_encryption_url"]:
            try:
                self.load_jwk(inst["jwk_encryption_url"], "enc", _issuer)
            except Exception:
                raise Exception(KEYLOADERR % ('jwk',
                                              inst["jwk_encryption_url"]))
        elif _verkeys:
            for key in _verkeys:
                self.set_decrypt_key(key, "rsa", _issuer)

    def publishable_jwks(self, usage, type="rsa"):
        jwks = []
        for key in self.get_keys(usage, type):
            jwks.append(construct_rsa_jwk(key))
        return jwks

    def update(self, keystore):
        for owner, spec in keystore._store.items():
            if owner == ".":
                continue
            self._store[owner] = spec

# =============================================================================
# =============================================================================

class PBase(object):
    def __init__(self, ca_certs=None, jwt_keys=None):

        if jwt_keys is None:
            self.keystore = KeyStore(self.http_request)
        else:
            self.keystore = KeyStore(self.http_request, jwt_keys)


        self.request_args = {"allow_redirects": False,}
        self.cookies = {}
        if ca_certs:
            self.request_args["verify"] = True
        else:
            self.request_args["verify"] = False

    def http_request(self, url, method="GET", **kwargs):
        _kwargs = copy.copy(self.request_args)
        if kwargs:
            _kwargs.update(kwargs)
        if self.cookies:
            _kwargs["cookies"] = self.cookies

        r = requests.request(method, url, **_kwargs)
        self.cookies = r.cookies
        return r

class Client(PBase):
    _endpoints = ENDPOINTS

    def __init__(self, client_id=None, ca_certs=None,
                 grant_expire_in=600, client_timeout=0, jwt_keys=None):

        PBase.__init__(self, ca_certs, jwt_keys)

        self.client_id = client_id
        self.client_timeout = client_timeout
        #self.secret_type = "basic "

        self.state = None
        self.nonce = None

        self.grant_expire_in = grant_expire_in
        self.grant = {}

        # own endpoint
        self.redirect_uris = [None]

        # service endpoints
        self.authorization_endpoint=None
        self.token_endpoint=None
        self.token_revocation_endpoint=None

        self.request2endpoint = REQUEST2ENDPOINT
        self.response2error = RESPONSE2ERROR
        self.authn_method = AUTHN_METHOD
        self.grant_class = Grant
        self.token_class = Token

    def get_client_secret(self):
        return self._c_secret

    def set_client_secret(self, val):
        self._c_secret = val
        # client uses it for signing
        self.keystore.add_key(val, "hmac", "sign")

        # Server might also use it for signing which means the
        # client uses it for verifying server signatures
        self.keystore.add_key(val, "hmac", "verify")

    client_secret = property(get_client_secret, set_client_secret)

    def reset(self):
        self.state = None
        self.nonce = None

        self.grant = {}

        self.authorization_endpoint=None
        self.token_endpoint=None
        self.redirect_uris = None

    def grant_from_state(self, state):
        for key, grant in self.grant.items():
            if key == state:
                return grant

        return None

    def _parse_args(self, request, **kwargs):
        ar_args = kwargs.copy()

        for prop in request.c_param.keys():
            if prop in ar_args:
                continue
            else:
                if prop == "redirect_uri":
                    _val = getattr(self, "redirect_uris", [None])[0]
                    if _val:
                        ar_args[prop] = _val
                else:
                    _val = getattr(self, prop, None)
                    if _val:
                        ar_args[prop] = _val

        return ar_args

    def _endpoint(self, endpoint, **kwargs):
        try:
            uri = kwargs[endpoint]
            if uri:
                del kwargs[endpoint]
        except KeyError:
            uri = ""

        if not uri:
            try:
                uri = getattr(self, endpoint)
            except Exception:
                raise Exception("No '%s' specified" % endpoint)

        if not uri:
            raise Exception("No '%s' specified" % endpoint)

        return uri

    def get_grant(self, **kwargs):
        try:
            _state = kwargs["state"]
            if not _state:
                _state = self.state
        except KeyError:
            _state = self.state

        try:
            return self.grant[_state]
        except:
            raise Exception("No grant found for state:'%s'" % _state)

    def get_token(self, also_expired=False, **kwargs):
        try:
            return kwargs["token"]
        except KeyError:
            grant = self.get_grant(**kwargs)

            try:
                token = grant.get_token(kwargs["scope"])
            except KeyError:
                token = grant.get_token("")
                if not token:
                    try:
                        token = self.grant[kwargs["state"]].get_token("")
                    except KeyError:
                        raise Exception("No token found for scope")

        if token is None:
            raise Exception("No suitable token found")

        if also_expired:
            return token
        elif token.is_valid():
            return token
        else:
            raise ExpiredToken()

    def construct_request(self, request, request_args=None, extra_args=None):
        if request_args is None:
            request_args = {}

        kwargs = self._parse_args(request, **request_args)

        if extra_args:
            kwargs.update(extra_args)
            
        return request(**kwargs)

    #noinspection PyUnusedLocal
    def construct_AuthorizationRequest(self, request=AuthorizationRequest,
                                       request_args=None, extra_args=None,
                                       **kwargs):

        if request_args is not None:
            try: # change default
                self.redirect_uris = [request_args["redirect_uri"]]
            except KeyError:
                pass
        else:
            request_args = {}

        return self.construct_request(request, request_args, extra_args)

    #noinspection PyUnusedLocal
    def construct_AccessTokenRequest(self,
                                     request=AccessTokenRequest,
                                     request_args=None, extra_args=None,
                                     **kwargs):

        grant = self.get_grant(**kwargs)

        if not grant.is_valid():
            raise GrantExpired("Authorization Code to old %s > %s" % (
                utc_time_sans_frac(),
                grant.grant_expiration_time))

        if request_args is None:
            request_args = {}

        request_args["code"] = grant.code

        if "grant_type" not in request_args:
            request_args["grant_type"] = "authorization_code"

        if "client_id" not in request_args:
            request_args["client_id"] = self.client_id
        elif not request_args["client_id"]:
            request_args["client_id"] = self.client_id

        return self.construct_request(request, request_args, extra_args)

    def construct_RefreshAccessTokenRequest(self,
                                            request=RefreshAccessTokenRequest,
                                            request_args=None, extra_args=None,
                                            **kwargs):

        if request_args is None:
            request_args = {}

        token = self.get_token(also_expired=True, **kwargs)

        request_args["refresh_token"] = token.refresh_token

        try:
            request_args["scope"] = token.scope
        except AttributeError:
            pass

        return self.construct_request(request, request_args, extra_args)

    def construct_TokenRevocationRequest(self,
                                         request=TokenRevocationRequest,
                                         request_args=None, extra_args=None,
                                         **kwargs):

        if request_args is None:
            request_args = {}

        token = self.get_token(**kwargs)

        request_args["token"] = token.access_token
        return self.construct_request(request, request_args, extra_args)

    def construct_ResourceRequest(self, request=ResourceRequest,
                                  request_args=None, extra_args=None,
                                  **kwargs):

        if request_args is None:
            request_args = {}

        token = self.get_token(**kwargs)

        request_args["access_token"] = token.access_token
        return self.construct_request(request, request_args, extra_args)

    def get_or_post(self, uri, method, req, **kwargs):
        if method == "GET":
            _qp = req.to_urlencoded()
            if _qp:
                path = uri + '?' + _qp
            else:
                path = uri
            body = None
        elif method == "POST":
            path = uri
            body = req.to_urlencoded()
            header_ext = {"content-type": DEFAULT_POST_CONTENT_TYPE}
            if "headers" in kwargs.keys():
                kwargs["headers"].update(header_ext)
            else:
                kwargs["headers"] = header_ext
        else:
            raise Exception("Unsupported HTTP method: '%s'" % method)

        return path, body, kwargs

    def uri_and_body(self, reqmsg, cis, method="POST", request_args=None,
                     **kwargs):

        uri = self._endpoint(self.request2endpoint[reqmsg.__name__],
                             **request_args)

        uri, body, kwargs = self.get_or_post(uri, method, cis, **kwargs)
        try:
            h_args = {"headers": kwargs["headers"]}
        except KeyError:
            h_args = {}

        return uri, body, h_args, cis

    def request_info(self, request, method="POST", request_args=None,
                     extra_args=None, **kwargs):

        if request_args is None:
            request_args = {}

        cis = getattr(self, "construct_%s" % request.__name__)(
                                                request_args=request_args,
                                                extra_args=extra_args,
                                                **kwargs)

        if "authn_method" in kwargs:
            h_arg = self.init_authentication_method(cis,
                                                    request_args=request_args,
                                                    **kwargs)
        else:
            h_arg = None

        if h_arg:
            if "headers" in kwargs.keys():
                kwargs["headers"].update(h_arg)
            else:
                kwargs["headers"] = h_arg

        return self.uri_and_body(request, cis, method, request_args,
                                 **kwargs)

    def authorization_request_info(self, request_args=None, extra_args=None,
                                   **kwargs):
        return self.request_info(AuthorizationRequest, "GET",
                                 request_args, extra_args, **kwargs)

    def parse_response(self, response, info="", format="json", state="",
                       **kwargs):
        """
        Parse a response

        :param response: Response type
        :param info: The response, can be either an JSON code or an urlencoded
            form:
        :param format: Which serialization that was used
        :return: The parsed and to some extend verified response
        """

        _r2e = self.response2error

        err = None
        if format == "urlencoded":
            if '?' in info or '#' in info:
                parts = urlparse.urlparse(info)
                scheme, netloc, path, params, query, fragment = parts[:6]
                # either query of fragment
                if query:
                    info = query
                else:
                    info = fragment

        try:
            resp = response().deserialize(info, format)
            verf = resp.verify(**kwargs)
            if not verf:
                raise Exception("Verification of the response failed")
            if resp.type() == "AuthorizationResponse" and "scope" not in resp:
                try:
                    resp["scope"] = kwargs["scope"]
                except KeyError:
                    pass
        except Exception, err:
            resp = None

        eresp = None
        try:
            for errmsg in _r2e[response.__name__]:
                try:
                    eresp = errmsg().deserialize(info, format)
                    eresp.verify()
                    break
                except Exception:
                    eresp = None
        except KeyError:
            pass

        # Error responses has higher precedence
        if eresp:
            resp = eresp

        if not resp:
            raise err

        if resp.type() in ["AuthorizationResponse", "AccessTokenResponse"]:
            try:
                _state = resp["state"]
            except (AttributeError, KeyError):
                _state = ""

            if not _state:
                _state = state

            try:
                self.grant[_state].update(resp)
            except KeyError:
                self.grant[_state] = self.grant_class(resp=resp)

        return resp

    #noinspection PyUnusedLocal
    def init_authentication_method(self, cis, authn_method, request_args=None,
                                   http_args=None, **kwargs):

        if http_args is None:
            http_args = {}
        if request_args is None:
            request_args = {}

        if authn_method:
            return self.authn_method[authn_method](self, cis, request_args,
                                                   http_args)
        else:
            return http_args

    def request_and_return(self, url, response=None, method="GET", body=None,
                           body_type="json", state="", http_args=None,
                           **kwargs):
        """
        :param url: The URL to which the request should be sent
        :param response: Response type
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param body_type: The format of the body of the return message
        :param http_args: Arguments for the HTTP client
        :return: A cls or ErrorResponse instance or the HTTP response
            instance if no response body was expected.
        """

        if http_args is None:
            http_args = {}

        try:
            resp = self.http_request(url, method, data=body, **http_args)
        except Exception:
            raise

        if resp.status_code == 200:
            if body_type == "":
                pass
            elif body_type == "json":
                assert "application/json" in resp.headers["content-type"]
            elif body_type == "urlencoded":
                assert DEFAULT_POST_CONTENT_TYPE in resp.headers["content-type"]
            else:
                raise ValueError("Unknown return format: %s" % body_type)
        elif resp.status_code == 302: # redirect
            pass
        elif resp.status_code == 500:
            raise Exception("ERROR: Something went wrong: %s" % resp.text)
        else:
            raise Exception("ERROR: Something went wrong [%s]" % (
                                                            resp.status_code,))

        if body_type:
            if response:
                return self.parse_response(response, resp.text, body_type,
                                           state, **kwargs)
            else:
                raise Exception("Didn't expect a response body")
        else:
            return resp

    def do_authorization_request(self, request=AuthorizationRequest,
                                 state="", body_type="", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 resp_request=AuthorizationResponse):

        url, body, ht_args, csi = self.request_info(request, method,
                                                    request_args, extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        resp = self.request_and_return(url, resp_request, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

        if isinstance(resp, Message):
            if resp.type() in RESPONSE2ERROR["AuthorizationRequest"]:
                resp.state = csi.state

        return resp

    def do_access_token_request(self, request=AccessTokenRequest,
                                scope="", state="", body_type="json",
                                method="POST", request_args=None,
                                extra_args=None, http_args=None,
                                resp_request=AccessTokenResponse,
                                authn_method="", **kwargs):

        # method is default POST
        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state,
                                                    authn_method=authn_method,
                                                    **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_request, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def do_access_token_refresh(self, request=RefreshAccessTokenRequest,
                                state="", body_type="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None,
                                resp_request=AccessTokenResponse,
                                authn_method="", **kwargs):

        token = self.get_token(also_expired=True, state=state, **kwargs)

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    token=token,
                                                    authn_method=authn_method)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_request, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def do_revocate_token(self, request=TokenRevocationRequest,
                          scope="", state="", body_type="json", method="POST",
                          request_args=None, extra_args=None, http_args=None,
                          resp_request=None, authn_method=""):

        url, body, ht_args, csi = self.request_info(request, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state,
                                                    authn_method=authn_method)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_request, method, body,
                                       body_type, state=state,
                                       http_args=http_args)

    def fetch_protected_resource(self, uri, method="GET", headers=None,
                                 state="", **kwargs):

        try:
            token = self.get_token(state=state, **kwargs)
        except ExpiredToken:
            # The token is to old, refresh
            self.do_access_token_refresh()
            token = self.get_token(state=state, **kwargs)

        if headers is None:
            headers = {}

        request_args = {"access_token": token.access_token}

        if "authn_method" in kwargs:
            http_args = self.init_authentication_method(request_args, **kwargs)
        else:
            # If nothing defined this is the default
            http_args = bearer_header(self, request_args, **kwargs)

        headers.update(http_args["headers"])

        return self.http_request(uri, method, headers=headers, **kwargs)


class Server(PBase):
    def __init__(self, jwt_keys=None, ca_certs=None):

        PBase.__init__(self, ca_certs, jwt_keys)


    def parse_url_request(self, request, url=None, query=None):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        req = request().deserialize(query, "urlencoded")
        req.verify()
        return req

    def parse_authorization_request(self, request=AuthorizationRequest,
                                    url=None, query=None):

        return self.parse_url_request(request, url, query)

    def parse_jwt_request(self, request=AuthorizationRequest, txt="",
                          keystore="", verify=True):

        if not keystore:
                keystore = self.keystore

        keys = keystore.get_keys("verify", owner=None)
        #areq = message().from_(txt, keys, verify)
        areq = request().deserialize(txt, "jwt", key=keys, verify=verify)
        areq.verify()
        return areq

    def parse_body_request(self, request=AccessTokenRequest, body=None):
        #req = message(reqmsg).from_urlencoded(body)
        req = request().deserialize(body, "urlencoded")
        req.verify()
        return req

    def parse_token_request(self, request=AccessTokenRequest,
                            body=None):
        return self.parse_body_request(request, body)

    def parse_refresh_token_request(self, request=RefreshAccessTokenRequest,
                                    body=None):
        return self.parse_body_request(request, body)

