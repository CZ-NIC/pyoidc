import json
import time
from Crypto.PublicKey import RSA

__author__ = 'rohe0002'

import logging
import os
import urlparse
import sys
import traceback

from requests import request

from jwkest.jwk import rsa_load
from jwkest.jwk import RSAKey
from jwkest.jwk import ECKey
from jwkest.jwk import SYMKey

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
logger = logging.getLogger(__name__)

# ======================================================================
traceback.format_exception(*sys.exc_info())


class UnknownKeyType(Exception):
    pass


K2C = {
    "RSA": RSAKey,
    "EC": ECKey,
    "oct": SYMKey,
#    "pkix": PKIX_key
}


class KeyBundle(object):
    def __init__(self, keys=None, source="", cache_time=300, verify_ssl=True,
                 fileformat="jwk", keytype="RSA", keyusage=None):
        """

        :param keys: A list of dictionaries of the format
            with the keys ["kty", "key", "alg", "use", "kid"]
        :param source: Where the key set can be fetch from
        :param verify_ssl: Verify the SSL cert used by the server
        :param fileformat: For a local file either "jwk" or "der"
        :param keytype: Iff local file and 'der' format what kind of key is it.
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
                raise Exception("Unsupported source type: %s" % source)

            if not self.remote:  # local file
                if self.fileformat == "jwk":
                    self.do_local_jwk(self.source)
                elif self.fileformat == "der":
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
                    _key.dc()
                    self._keys.append(_key)
                    flag = 1
                    break
            if not flag:
                raise UnknownKeyType(typ)

    def do_local_jwk(self, filename):
        self.do_keys(json.loads(open(filename).read())["keys"])

    def do_local_der(self, filename, keytype, keyusage):
        _bkey = None
        if keytype == "RSA":
            _bkey = rsa_load(filename)

        if not keyusage:
            keyusage = ["enc", "sig"]

        for use in keyusage:
            _key = K2C[keytype]()
            _key.key = _bkey
            _key.deserialize()
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
        elif r.status_code == 200:  # New content
            self.time_out = time.time() + self.cache_time

            self.do_keys(json.loads(r.text)["keys"])

            try:
                self.etag = r.headers["Etag"]
            except KeyError:
                pass
            try:
                self.cache_control = r.headers["Cache-Control"]
            except KeyError:
                pass

    def _uptodate(self):
        if self._keys is not []:
            if self.remote:  # verify that it's not to old
                if time.time() > self.time_out:
                    self.update()
        elif self.remote:
            self.update()

    def update(self):
        """
        Reload the key if necessary
        This is a forced update, will happen even if cache time has not elapsed
        """
        if self.source:
            # reread everything

            self._keys = []

            if self.remote is False:
                if self.fileformat == "jwk":
                    self.do_local_jwk(self.source)
                elif self.fileformat == "der":
                    self.do_local_der(self.source, self.keytype, self.keyusage)
            else:
                self.do_remote()

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

    def remove(self, typ, val=None):
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
        return json.dumps({"keys": [k.to_dict() for k in self._keys]})

    def append(self, key):
        self._keys.append(key)

    def __len__(self):
        return len(self._keys)

    def get_key_with_kid(self, kid):
        for key in self._keys:
            if key.kid == kid:
                return key
        return None


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
            _k.key = k.key
            kb.append(_k)
    elif typ.lower() == "jwk":
        kb = KeyBundle(source=filename, fileformat="jwk", keyusage=usage)
    else:
        raise Exception("Unsupported key type")

    return kb


def dump_jwks(kbl, target):
    """
    Write a JWK to a file

    :param kbl: List of KeyBundles
    :param target: Name of the file to which everything should be written
    """
    res = {"keys": []}
    for kb in kbl:
        res["keys"].extend([k.to_dict() for k in kb.keys()])

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

    def __init__(self, ca_certs=None):
        self.spec2key = {}
        self.issuer_keys = {}
        self.ca_certs = ca_certs

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

        if "/localhost:" in url or "/localhost/" in url:
            kc = KeyBundle(source=url, verify_ssl=False)
        else:
            kc = KeyBundle(source=url)

        try:
            self.issuer_keys[issuer].append(kc)
        except KeyError:
            self.issuer_keys[issuer] = [kc]

        return kc

    def add_symmetric(self, issuer, key, usage):
        if not issuer in self.issuer_keys:
            self.issuer_keys[issuer] = []

        for use in usage:
            self.issuer_keys[""].append(KeyBundle([{"kty": "oct",
                                                    "key": key,
                                                    "use": use}]))

    def add_kb(self, issuer, kb):
        try:
            self.issuer_keys[issuer].append(kb)
        except KeyError:
            self.issuer_keys[issuer] = [kb]

    def __setitem__(self, issuer, val):
        if isinstance(val, basestring):
            val = [val]
        elif not isinstance(val, list):
            val = [val]

        self.issuer_keys[issuer] = val

    def get(self, use, key_type="", issuer=""):
        """

        :param use: A key useful for this usage (enc, dec, sig, ver)
        :param key_type: Type of key (rsa, ec, symmetric, ..)
        :param issuer: Who is responsible for the keys, "" == me
        :return: A possibly empty list of keys
        """

        if use == "dec":
            use = "enc"
        elif use == "ver":
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
            _keys = self.issuer_keys[issuer]

        lst = []
        if _keys:
            for bundles in _keys:
                if key_type:
                    _keys = bundles.get(key_type)
                else:
                    _keys = bundles.keys()
                for key in _keys:
                    if use == key.use:
                        lst.append(key)
        return lst

    def get_signing_key(self, key_type="", owner=""):
        return self.get("sig", key_type, owner)

    def get_verify_key(self, key_type="", owner=""):
        return self.get("ver", key_type, owner)

    def get_encrypt_key(self, key_type="", owner=""):
        return self.get("enc", key_type, owner)

    def get_decrypt_key(self, key_type="", owner=""):
        return self.get("dec", key_type, owner)

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
        return self.issuer_keys[issuer]

    def remove_key(self, issuer, key_type, key):
        try:
            kcs = self.issuer_keys[issuer]
        except KeyError:
            return

        for kc in kcs:
            kc.remove(key_type, key)
            if len(kc._keys) == 0:
                self.issuer_keys[issuer].remove(kc)

    def update(self, kj):
        for key, val in kj.issuer_keys.items():
            if isinstance(val, basestring):
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

        raise Exception("No keys for '%s'" % url)

    def __str__(self):
        _res = {}
        for k, vs in self.issuer_keys.items():
            _res[k] = [str(v) for v in vs]
        return "%s" % (_res,)

    def keys(self):
        self.issuer_keys.keys()

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
        logger.debug("pcr: %s" % pcr)
        if issuer not in self.issuer_keys:
            self.issuer_keys[issuer] = []
        elif replace:
            self.issuer_keys[issuer] = []

        try:
            self.add(issuer, pcr["jwks_uri"])
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



# =============================================================================

class RedirectStdStreams(object):
    def __init__(self, stdout=None, stderr=None):
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush(); self.old_stderr.flush()
        sys.stdout, sys.stderr = self._stdout, self._stderr

    #noinspection PyUnusedLocal
    def __exit__(self, exc_type, exc_value, traceback):
        self._stdout.flush(); self._stderr.flush()
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

                kb.append(RSAKey(key=_key, use=usage, kid=kid))
                kid += 1
                if usage == "sig" and "enc" not in kwargs:
                    kb.append(RSAKey(key=_key, use="enc", kid=kid))
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
    part = urlparse.urlsplit(baseurl)

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
    _export_filename = "%sjwks" % local_path

    f = open(_export_filename, "w")
    f.write("%s" % kb)
    f.close()

    _url = "%s://%s%s" % (part.scheme, part.netloc,
                          _export_filename[1:])

    return _url

# ================= create RSA key ======================


def create_and_store_rsa_key_pair(name="pyoidc", path=".", size=1024):
    """
    :param name: Name of the key file
    :param path: Path to where the key files are stored
    :param size: Seed the random number generator with <size> random bytes
    :return: RSA key
    """

    key = RSA.generate(size)

    if not path.endswith("/"):
        path += "/"

    f = open('%s%s' % (path, name),'w')
    f.write(key.exportKey('PEM'))
    f.close()

    _pub_key = key.publickey()
    f = open('%s%s.pub' % (path, name), 'w')
    f.write(_pub_key.exportKey('PEM'))
    f.close()

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

# ================= create certificate ======================
# heavily influenced by
# http://svn.osafoundation.org/m2crypto/trunk/tests/test_x509.py

#
#
# def make_req(bits, fqdn="example.com", rsa=None):
#     pk = EVP.PKey()
#     x = X509.Request()
#     if not rsa:
#         rsa = RSA.gen_key(bits, 65537, lambda: None)
#     pk.assign_rsa(rsa)
#     # Because rsa is messed with
#     rsa = pk.get_rsa()
#     x.set_pubkey(pk)
#     name = x.get_subject()
#     name.C = "SE"
#     name.CN = "OpenID Connect Test Server"
#     if fqdn:
#         ext1 = X509.new_extension('subjectAltName', fqdn)
#         extstack = X509.X509_Extension_Stack()
#         extstack.push(ext1)
#         x.add_extensions(extstack)
#     x.sign(pk, 'sha1')
#     return x, pk, rsa
#
#
# def make_cert(bits, fqdn="example.com", rsa=None):
#     req, pk, rsa = make_req(bits, fqdn=fqdn, rsa=rsa)
#     pkey = req.get_pubkey()
#     sub = req.get_subject()
#     cert = X509.X509()
#     cert.set_serial_number(1)
#     cert.set_version(2)
#     cert.set_subject(sub)
#     t = long(time.time()) + time.timezone
#     now = ASN1.ASN1_UTCTIME()
#     now.set_time(t)
#     nowPlusYear = ASN1.ASN1_UTCTIME()
#     nowPlusYear.set_time(t + 60 * 60 * 24 * 365)
#     cert.set_not_before(now)
#     cert.set_not_after(nowPlusYear)
#     issuer = X509.X509_Name()
#     issuer.CN = 'The code tester'
#     issuer.O = 'Umea University'
#     cert.set_issuer(issuer)
#     cert.set_pubkey(pkey)
#     cert.sign(pk, 'sha1')
#     return cert, rsa
