import copy
import logging
import os
import sys
import json
import time

from jwkest import jws
from jwkest import jwe
from jwkest import as_unicode
from Crypto.PublicKey import RSA
from requests import request
from jwkest.ecc import NISTEllipticCurve
from jwkest.jwk import rsa_load
from jwkest.jwk import RSAKey
from jwkest.jwk import ECKey
from jwkest.jwk import SYMKey

from six.moves.urllib.parse import urlsplit
from six import string_types

from oic.exception import MessageException
from oic.exception import PyoidcError
from oic.utils import elements_to_unicode

__author__ = 'rohe0002'

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
logger = logging.getLogger(__name__)

# ======================================================================


class KeyIOError(PyoidcError):
    pass


class UnknownKeyType(KeyIOError):
    pass


class UpdateFailed(KeyIOError):
    pass


K2C = {
    "RSA": RSAKey,
    "EC": ECKey,
    "oct": SYMKey,
}


class KeyBundle(object):
    def __init__(self, keys=None, source="", cache_time=300, verify_ssl=True,
                 fileformat="jwk", keytype="RSA", keyusage=None):
        """

        :param keys: A list of dictionaries
            with the keys ["kty", "key", "alg", "use", "kid"]
        :param source: Where the key set can be fetch from
        :param verify_ssl: Verify the SSL cert used by the server
        :param fileformat: For a local file either "jwk" or "der"
        :param keytype: Iff local file and 'der' format what kind of key it is.
        """

        self._keys = []
        self.remote = False
        self.verify_ssl = verify_ssl
        self.cache_time = cache_time
        self.time_out = 0
        self.etag = ""
        self.cache_control = None
        self.source = None
        self.fileformat = fileformat.lower()
        self.keytype = keytype
        self.keyusage = keyusage
        self.imp_jwks = None

        if keys:
            self.source = None
            if isinstance(keys, dict):
                self.do_keys([keys])
            else:
                self.do_keys(keys)
        else:
            if source.startswith("file://"):
                self.source = source[7:]
            elif source.startswith("http://") or source.startswith("https://"):
                self.source = source
                self.remote = True
            elif source == "":
                return
            else:
                raise KeyIOError("Unsupported source type: %s" % source)

            if not self.remote:  # local file
                if self.fileformat == "jwk":
                    self.do_local_jwk(self.source)
                elif self.fileformat == "der":  # Only valid for RSA keys
                    self.do_local_der(self.source, self.keytype, self.keyusage)

    def do_keys(self, keys):
        """
        Go from JWK description to binary keys

        :param keys:
        :return:
        """
        for inst in keys:
            typ = inst["kty"]
            flag = 0
            for _typ in [typ, typ.lower(), typ.upper()]:
                try:
                    _key = K2C[_typ](**inst)
                except KeyError:
                    continue
                else:
                    self._keys.append(_key)
                    flag = 1
                    break
            if not flag:
                raise UnknownKeyType(typ)

    def do_local_jwk(self, filename):
        self.do_keys(json.loads(open(filename).read())["keys"])

    def do_local_der(self, filename, keytype, keyusage):
        # This is only for RSA keys
        _bkey = rsa_load(filename)

        if not keyusage:
            keyusage = ["enc", "sig"]

        for use in keyusage:
            _key = RSAKey().load_key(_bkey)
            _key.use = use
            self._keys.append(_key)

    def do_remote(self):
        args = {"allow_redirects": True,
                "verify": self.verify_ssl,
                "timeout": 5.0}
        if self.etag:
            args["headers"] = {"If-None-Match": self.etag}

        r = request("GET", self.source, **args)

        if r.status_code == 304:  # file has not changed
            self.time_out = time.time() + self.cache_time
            return False
        elif r.status_code == 200:  # New content
            self.time_out = time.time() + self.cache_time

            logger.debug("Loaded JWKS: %s from %s" % (r.text, self.source))
            self.imp_jwks = json.loads(r.text)  # For use else where
            self.do_keys(self.imp_jwks["keys"])

            try:
                self.etag = r.headers["Etag"]
            except KeyError:
                pass
            try:
                self.cache_control = r.headers["Cache-Control"]
            except KeyError:
                pass
            return True
        else:
            raise UpdateFailed(
                "Remote key update from '{}' failed.".format(self.source))

    def _uptodate(self):
        res = False
        if self._keys is not []:
            if self.remote:  # verify that it's not to old
                if time.time() > self.time_out:
                    if self.update():
                        res = True
        elif self.remote:
            if self.update():
                res = True
        return res

    def update(self):
        """
        Reload the key if necessary
        This is a forced update, will happen even if cache time has not elapsed
        """
        res = True  # An update was successful
        if self.source:
            # reread everything
            self._keys = []

            if self.remote is False:
                if self.fileformat == "jwk":
                    self.do_local_jwk(self.source)
                elif self.fileformat == "der":
                    self.do_local_der(self.source, self.keytype, self.keyusage)
            else:
                res = self.do_remote()
        return res

    def get(self, typ=""):
        """

        :param typ: Type of key (rsa, ec, oct, ..)
        :return: If typ is undefined all the keys as a dictionary
            otherwise the appropriate keys in a list
        """
        self._uptodate()
        _typs = [typ.lower(), typ.upper()]

        if typ:
            return [k for k in self._keys if k.kty in _typs]
        else:
            return self._keys

    def keys(self):
        self._uptodate()

        return self._keys

    def available_keys(self):
        return self._keys

    def remove_key(self, typ, val=None):
        """

        :param typ: Type of key (rsa, ec, oct, ..)
        :param val: The key itself
        """
        if val:
            self._keys = [k for k in self._keys if
                          not (k.kty == typ and k.key == val.key)]
        else:
            self._keys = [k for k in self._keys if not k.kty == typ]

    def __str__(self):
        return str(self.jwks())

    def jwks(self):
        self._uptodate()
        keys = list()
        for k in self._keys:
            key = k.to_dict()
            for k, v in key.items():
                key[k] = as_unicode(v)
            keys.append(key)
        return json.dumps({"keys": keys})

    def append(self, key):
        self._keys.append(key)

    def remove(self, key):
        self._keys.remove(key)

    def __len__(self):
        return len(self._keys)

    def get_key_with_kid(self, kid):
        for key in self._keys:
            if key.kid == kid:
                return key

        # Try updating since there might have been an update to the key file
        self.update()

        for key in self._keys:
            if key.kid == kid:
                return key

        return None

    def kids(self):
        self._uptodate()
        return [key.kid for key in self._keys if key.kid != ""]


def keybundle_from_local_file(filename, typ, usage):
    if typ.upper() == "RSA":
        kb = KeyBundle()
        k = RSAKey()
        k.load(filename)
        k.use = usage[0]
        kb.append(k)
        for use in usage[1:]:
            _k = RSAKey()
            _k.use = use
            _k.load_key(k.key)
            kb.append(_k)
    elif typ.lower() == "jwk":
        kb = KeyBundle(source=filename, fileformat="jwk", keyusage=usage)
    else:
        raise UnknownKeyType("Unsupported key type")

    return kb


def dump_jwks(kbl, target):
    """
    Write a JWK to a file

    :param kbl: List of KeyBundles
    :param target: Name of the file to which everything should be written
    """
    res = {"keys": []}
    for kb in kbl:
        # ignore simple keys
        res["keys"].extend([k.to_dict() for k in kb.keys() if
                            k.kty != 'oct' and not k.inactive_since])

    try:
        f = open(target, 'w')
    except IOError:
        (head, tail) = os.path.split(target)
        os.makedirs(head)
        f = open(target, 'w')

    _txt = json.dumps(res)
    f.write(_txt)
    f.close()


class KeyJar(object):
    """ A keyjar contains a number of KeyBundles """

    def __init__(self, ca_certs=None, verify_ssl=True):
        """

        :param ca_certs:
        :param verify_ssl: Attempting SSL certificate verification
        :return:
        """
        self.spec2key = {}
        self.issuer_keys = {}
        self.ca_certs = ca_certs
        self.verify_ssl = verify_ssl

    def add_if_unique(self, issuer, use, keys):
        if use in self.issuer_keys[issuer] and self.issuer_keys[issuer][use]:
            for typ, key in keys:
                flag = 1
                for _typ, _key in self.issuer_keys[issuer][use]:
                    if _typ == typ and key is _key:
                        flag = 0
                        break
                if flag:
                    self.issuer_keys[issuer][use].append((typ, key))
        else:
            self.issuer_keys[issuer][use] = keys

    def add(self, issuer, url):
        """

        :param issuer: Who issued the keys
        :param url: Where can the key/-s be found
        """

        if not url:
            raise KeyError("No jwks_uri")

        if "/localhost:" in url or "/localhost/" in url:
            kc = KeyBundle(source=url, verify_ssl=False)
        else:
            kc = KeyBundle(source=url, verify_ssl=self.verify_ssl)

        try:
            self.issuer_keys[issuer].append(kc)
        except KeyError:
            self.issuer_keys[issuer] = [kc]

        return kc

    def add_symmetric(self, issuer, key, usage):
        if issuer not in self.issuer_keys:
            self.issuer_keys[issuer] = []

        for use in usage:
            self.issuer_keys[issuer].append(KeyBundle([{"kty": "oct",
                                                        "key": key,
                                                        "use": use}]))

    def add_kb(self, issuer, kb):
        try:
            self.issuer_keys[issuer].append(kb)
        except KeyError:
            self.issuer_keys[issuer] = [kb]

    def __setitem__(self, issuer, val):
        if isinstance(val, string_types):
            val = [val]
        elif not isinstance(val, list):
            val = [val]

        self.issuer_keys[issuer] = val

    def get(self, key_use, key_type="", issuer="", kid=None, **kwargs):
        """

        :param key_use: A key useful for this usage (enc, dec, sig, ver)
        :param key_type: Type of key (rsa, ec, symmetric, ..)
        :param issuer: Who is responsible for the keys, "" == me
        :param kid: A Key Identifier
        :return: A possibly empty list of keys
        """

        if key_use in ["dec", "enc"]:
            use = "enc"
        elif key_use in ["ver", "sig"]:
            use = "sig"

        if issuer != "":
            try:
                _keys = self.issuer_keys[issuer]
            except KeyError:
                if issuer.endswith("/"):
                    try:
                        _keys = self.issuer_keys[issuer[:-1]]
                    except KeyError:
                        _keys = []
                else:
                    try:
                        _keys = self.issuer_keys[issuer + "/"]
                    except KeyError:
                        _keys = []
        else:
            try:
                _keys = self.issuer_keys[issuer]
            except KeyError:
                _keys = []

        lst = []
        if _keys:
            for bundles in _keys:
                if key_type:
                    _keys = bundles.get(key_type)
                else:
                    _keys = bundles.keys()
                for key in _keys:
                    if key.inactive_since and key_use != "ver":
                        # Skip inactive keys unless for signature verification
                        continue
                    if kid and key.kid == kid:
                        lst = [key]
                        break
                    if not key.use or use == key.use:
                        lst.append(key)

        # if elliptic curve have to check I have a key of the right curve
        if key_type == "EC" and "alg" in kwargs:
            name = "P-{}".format(kwargs["alg"][2:])  # the type
            _lst = []
            for key in lst:
                try:
                    assert name == key.crv
                except AssertionError:
                    pass
                else:
                    _lst.append(key)
            lst = _lst

        return lst

    def get_signing_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("sig", key_type, owner, kid, **kwargs)

    def get_verify_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("ver", key_type, owner, kid, **kwargs)

    def get_encrypt_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("enc", key_type, owner, kid, **kwargs)

    def get_decrypt_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("dec", key_type, owner, kid, **kwargs)

    def get_key_by_kid(self, kid, owner=""):
        """
        Return the key from a specific owner that has a specific kid

        :param kid: The key identifier
        :param owner: The owner of the key
        :return: a specific key instance or None
        """
        for kb in self.issuer_keys[owner]:
            _key = kb.get_key_with_kid(kid)
            if _key:
                return _key
        return None

    def __contains__(self, item):
        if item in self.issuer_keys:
            return True
        else:
            return False

    def x_keys(self, var, part):
        _func = getattr(self, "get_%s_key" % var)

        keys = _func(key_type="", owner=part)
        keys.extend(_func(key_type="", owner=""))
        return keys

    def verify_keys(self, part):
        """
        Keys for me and someone else.

        :param part: The other part
        :return: dictionary of keys
        """
        return self.x_keys("verify", part)

    def decrypt_keys(self, part):
        """
        Keys for me and someone else.

        :param part: The other part
        :return: dictionary of keys
        """

        return self.x_keys("decrypt", part)

    def __getitem__(self, issuer):
        try:
            return self.issuer_keys[issuer]
        except KeyError:
            logger.debug(
                "Available key issuers: {}".format(self.issuer_keys.keys()))
            raise

    def remove_key(self, issuer, key_type, key):
        try:
            kcs = self.issuer_keys[issuer]
        except KeyError:
            return

        for kc in kcs:
            kc.remove_key(key_type, key)
            if len(kc) == 0:
                self.issuer_keys[issuer].remove(kc)

    def update(self, kj):
        for key, val in kj.issuer_keys.items():
            if isinstance(val, string_types):
                val = [val]
            elif not isinstance(val, list):
                val = [val]

            try:
                self.issuer_keys[key].extend(val)
            except KeyError:
                self.issuer_keys[key] = val

    def match_owner(self, url):
        for owner in self.issuer_keys.keys():
            if url.startswith(owner):
                return owner

        raise KeyIOError("No keys for '%s'" % url)

    def __str__(self):
        _res = {}
        for _id, kbs in self.issuer_keys.items():
            _l = []
            for kb in kbs:
                _l.extend(json.loads(kb.jwks())["keys"])
            _res[_id] = {"keys": _l}
        return "%s" % (_res,)

    def keys(self):
        return self.issuer_keys.keys()

    def load_keys(self, pcr, issuer, replace=False):
        """
        Fetch keys from another server

        :param pcr: The provider information
        :param issuer: The provider URL
        :param replace: If all previously gathered keys from this provider
            should be replace.
        :return: Dictionary with usage as key and keys as values
        """

        logger.debug("loading keys for issuer: %s" % issuer)
        try:
            logger.debug("pcr: %s" % pcr)
        except MessageException:
            pass

        if issuer not in self.issuer_keys:
            self.issuer_keys[issuer] = []
        elif replace:
            self.issuer_keys[issuer] = []

        try:
            self.add(issuer, pcr["jwks_uri"])
        except KeyError:
            # jwks should only be considered if no jwks_uri is present
            try:
                _keys = pcr["jwks"]["keys"]
                self.issuer_keys[issuer].append(KeyBundle(_keys))
            except KeyError:
                pass

    def find(self, source, issuer):
        """
        Find a key bundle
        :param source: A url
        :param issuer: The issuer of keys
        """
        try:
            for kb in self.issuer_keys[issuer]:
                if kb.source == source:
                    return kb
        except KeyError:
            return None

    def dump_issuer_keys(self, issuer):
        res = []
        try:
            for kb in self.issuer_keys[issuer]:
                res.extend([k.to_dict() for k in kb.keys()])
        except KeyError:
            pass

        return res

    def export_jwks(self):
        keys = []
        for kb in self.issuer_keys[""]:
            keys.extend([k.serialize() for k in kb.keys()])
        return {"keys": keys}

    def dump(self):
        res = {}
        for issuer in self.issuer_keys.keys():
            res[issuer] = self.dump_issuer_keys(issuer)
        return res

    def restore(self, info):
        for issuer, keys in info.items():
            self.issuer_keys[issuer] = [KeyBundle(keys)]

    def copy(self):
        copy_keyjar = KeyJar()
        for issuer, keybundles in self.issuer_keys.iteritems():
            _kb = KeyBundle()
            for kb in keybundles:
                for k in kb.keys():
                    _kb.append(copy.copy(k))
            copy_keyjar.issuer_keys[issuer] = [_kb]

        return copy_keyjar

    def keys_by_alg_and_usage(self, issuer, alg, usage):
        if usage in ["sig", "ver"]:
            ktype = jws.alg2keytype(alg)
        else:
            ktype = jwe.alg2keytype(alg)

        return self.get(usage, ktype, issuer)


# =============================================================================


class RedirectStdStreams(object):
    def __init__(self, stdout=None, stderr=None):
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush()
        self.old_stderr.flush()
        sys.stdout, sys.stderr = self._stdout, self._stderr

    # noinspection PyUnusedLocal
    def __exit__(self, exc_type, exc_value, trace_back):
        self._stdout.flush()
        self._stderr.flush()
        sys.stdout = self.old_stdout
        sys.stderr = self.old_stderr


def key_setup(vault, **kwargs):
    """
    :param vault: Where the keys are kept
    :return: 2-tuple: result of urlsplit and a dictionary with
        parameter name as key and url and value
    """
    vault_path = proper_path(vault)

    if not os.path.exists(vault_path):
        os.makedirs(vault_path)

    kb = KeyBundle()
    kid = 1
    for usage in ["sig", "enc"]:
        if usage in kwargs:
            if kwargs[usage] is None:
                continue

            _args = kwargs[usage]
            if _args["alg"] == "RSA":
                try:
                    _key = rsa_load('%s%s' % (vault_path, "pyoidc"))
                except Exception:
                    devnull = open(os.devnull, 'w')
                    with RedirectStdStreams(stdout=devnull, stderr=devnull):
                        _key = create_and_store_rsa_key_pair(
                            path=vault_path)

                kb.append(RSAKey(key=_key, use=usage, kid=str(kid)))
                kid += 1
                if usage == "sig" and "enc" not in kwargs:
                    kb.append(RSAKey(key=_key, use="enc", kid=str(kid)))
                    kid += 1

    return kb


def key_export(baseurl, local_path, vault, keyjar, **kwargs):
    """
    :param baseurl: The base URL to which the key file names are added
    :param local_path: Where on the machine the export files are kept
    :param vault: Where the keys are kept
    :param keyjar: Where to store the exported keys
    :return: 2-tuple: result of urlsplit and a dictionary with
        parameter name as key and url and value
    """
    part = urlsplit(baseurl)

    # deal with the export directory
    if part.path.endswith("/"):
        _path = part.path[:-1]
    else:
        _path = part.path[:]

    local_path = proper_path("%s/%s" % (_path, local_path))

    if not os.path.exists(local_path):
        os.makedirs(local_path)

    kb = key_setup(vault, **kwargs)

    try:
        keyjar[""].append(kb)
    except KeyError:
        keyjar[""] = kb

    # the local filename
    _export_filename = os.path.join(local_path, "jwks")

    with open(_export_filename, "w") as f:
        f.write(str(kb))

    _url = "%s://%s%s" % (part.scheme, part.netloc,
                          _export_filename[1:])

    return _url


# ================= create RSA key ======================


def create_and_store_rsa_key_pair(name="pyoidc", path=".", size=2048):
    """
    :param name: Name of the key file
    :param path: Path to where the key files are stored
    :param size: RSA key size
    :return: RSA key
    """

    key = RSA.generate(size)

    if name:
        with open(os.path.join(path, name), 'wb') as f:
            f.write(key.exportKey('PEM'))

        _pub_key = key.publickey()
        with open(os.path.join(path, '{}.pub'.format(name)), 'wb') as f:
            f.write(_pub_key.exportKey('PEM'))

    return key


def proper_path(path):
    """
    Clean up the path specification so it looks like something I could use.
    "./" <path> "/"
    """
    if path.startswith("./"):
        pass
    elif path.startswith("/"):
        path = ".%s" % path
    elif path.startswith("."):
        while path.startswith("."):
            path = path[1:]
        if path.startswith("/"):
            path = ".%s" % path
    else:
        path = "./%s" % path

    if not path.endswith("/"):
        path += "/"

    return path


def ec_init(spec):
    """

    :param spec: Key specifics of the form
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    :return: A KeyBundle instance
    """
    typ = spec["type"].upper()
    _key = NISTEllipticCurve.by_name(spec["crv"])
    kb = KeyBundle(keytype=typ, keyusage=spec["use"])
    for use in spec["use"]:
        priv, pub = _key.key_pair()
        ec = ECKey(x=pub[0], y=pub[1], d=priv, crv=spec["crv"])
        ec.serialize()
        ec.use = use
        kb.append(ec)
    return kb


def rsa_init(spec):
    arg = {}
    for param in ["name", "path", "size"]:
        try:
            arg[param] = spec[param]
        except KeyError:
            pass

    _key = create_and_store_rsa_key_pair(**arg)
    kb = KeyBundle(keytype=spec["type"], keyusage=spec["use"])
    for use in spec["use"]:
        kb.append(RSAKey(use=use, key=_key))
    return kb


def keyjar_init(instance, key_conf, kid_template="a%d"):
    """
    Configuration of the type:
    keys = [
        {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["enc"]}
    ]

    :param instance: server/client instance
    :param key_conf: The key configuration
    :param kid_template: A template by which to build the kids
    :return: a JWKS
    """

    jwks, keyjar, kdd = build_keyjar(key_conf, kid_template, instance.keyjar,
                                     instance.kid)

    instance.keyjar = keyjar
    instance.kid = kdd
    return jwks


def build_keyjar(key_conf, kid_template="a%d", keyjar=None, kidd=None):
    """
    Configuration of the type:
    keys = [
        {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["enc"]}
    ]

    :param key_conf: The key configuration
    :param kid_template: A template by which to build the kids
    :return: a tuple consisting of a JWKS dictionary, a KeyJar instance
        and a representation of which kids that can be used for what.
        Note the JWKS contains private key information !!
    """

    if keyjar is None:
        keyjar = KeyJar()

    if kidd is None:
        kidd = {"sig": {}, "enc": {}}

    kid = 0
    jwks = {"keys": []}

    for spec in key_conf:
        typ = spec["type"].upper()

        if typ == "RSA":
            if "key" in spec:
                kb = KeyBundle(source="file://%s" % spec["key"],
                               fileformat="der",
                               keytype=typ, keyusage=spec["use"])
            else:
                kb = rsa_init(spec)
        elif typ == "EC":
            kb = ec_init(spec)

        for k in kb.keys():
            k.kid = kid_template % kid
            kid += 1
            kidd[k.use][k.kty] = k.kid

        jwks["keys"].extend([elements_to_unicode(k.to_dict())
                             for k in kb.keys() if k.kty != 'oct'])

        keyjar.add_kb("", kb)

    return jwks, keyjar, kidd
