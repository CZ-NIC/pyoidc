__author__ = 'rohe0002'

import M2Crypto
import logging
import os
import urlparse
import sys
import traceback

from requests import request

from jwkest import jwk
from jwkest.jwk import x509_rsa_loads
from jwkest.jwk import loads
from M2Crypto.util import no_passphrase_callback

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
logger = logging.getLogger(__name__)

# ======================================================================
traceback.format_exception(*sys.exc_info())

def rsa_eq(key1, key2):
    # Check if two RSA keys are in fact the same
    if key1.n == key2.n and key1.e == key2.e:
        return True
    else:
        return False

def key_eq(key1, key2):
    if type(key1) == type(key2):
        if isinstance(key1, basestring):
            return key1 == key2
        elif isinstance(key1, M2Crypto.RSA.RSA):
            return rsa_eq(key1, key2)

    return False

def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file."""
    return M2Crypto.RSA.load_key(filename, M2Crypto.util.no_passphrase_callback)

def rsa_loads(key):
    """Read a PEM-encoded RSA key pair from a string."""
    return M2Crypto.RSA.load_key_string(key,
                                        M2Crypto.util.no_passphrase_callback)

def ec_load(filename):
    return M2Crypto.EC.load_key(filename, M2Crypto.util.no_passphrase_callback)

def x509_rsa_load(txt):
    """ So I get the same output format as loads produces
    :param txt:
    :return:
    """
    return [("rsa", x509_rsa_loads(txt))]

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

TYPE2FUNC = {"x509": x509_rsa_load, "jwk": loads}

def uniq_ext(lst, keys):
    rkeys = {}
    for typ, key in lst:
        if typ == "rsa":
            rkeys[(key.n, key.e)] = key

    for typ, item in keys:
        if typ != "rsa":
            lst.append((typ, item))
        else:
            key = (item.n, item.e)
            if key not in rkeys:
                lst.append((typ, item))
                rkeys[key] = item

    return lst

URLPAT = [("%s_url", "ver"), ("%s_encryption_url", "enc")]

class KeyChain(object):
    def __init__(self, keys=None, source="", type="rsa", src_type="",
                 cache_time=300, usage=""):
        """

        :param keys: A dictionary
        :param source: Where the key can be fetch from
        :param type: What type of key it is (rsa, ec, hmac,..)
        :param src_type: How the key is packed (x509, jwk,..)
        :param usage: What the key should be used for (enc, dec, sig, ver)
        """
        self._key = {}
        self.remote = False
        if keys:
            for typ, inst in keys.items():
                try:
                    self._key[typ].append(inst)
                except KeyError:
                    self._key[typ] = [inst]
        else:
            if source.startswith("file://"):
                self.source = source[7:]
            elif source.startswith("http://") or source.startswith("https://"):
                self.source = source
                self.remote = True
            else:
                raise Exception("Unsupported source type: %s" % source)

            self.src_type = src_type
            if not self.remote: # local file
                if src_type == "JWK":
                    for typ, inst in loads(source):
                        try:
                            self._key[type].append(inst)
                        except KeyError:
                            self._key[type] = [inst]
                else: # native format
                    if type == "rsa":
                        _key = rsa_load(self.source)
                    elif type == "ec":
                        _key = ec_load(self.source)
                    else: # Assume hmac
                        _key = open(self.source).read()
                        type = "hmac"

                    try:
                        self._key[type].append(_key)
                    except KeyError:
                        self._key[type] = [_key]

                self._type = type

        if usage:
            if isinstance(usage, basestring):
                self.usage = [usage]
            else:
                self.usage = usage
        else:
            self.usage = []

        self.etag = ""
        self.cache_control = []
        self.time_out = 0
        self.cache_time = cache_time

    def update(self):
        """
        Reload the key if necessary
        """
        args = {"allow_redirects": True}
        if self.etag:
            args["headers"] = {"If-None-Match": self.etag}

        r = request("GET", self.source, **args)

        if r.status_code == 304: # file has not changed
            self.time_out = time.time() + self.cache_time
        elif r.status_code == 200: # New content
            self.time_out = time.time() + self.cache_time
            _new = {}
            if self.src_type == "x509":
                txt = str(r.text)
            else:
                txt = r.text
            for typ,inst in TYPE2FUNC[self.src_type](txt):
                try:
                    _new[typ].append(inst)
                except KeyError:
                    _new[typ] = [inst]
            self._key = _new

            try:
                self.etag = r.headers["Etag"]
            except KeyError:
                pass
            try:
                self.cache_control = r.headers["Cache-Control"]
            except KeyError:
                pass

    def get(self, typ):
        """

        :param typ: Type of key (rsa, ec, hmac, ..)
        :return: If typ is undefined all the keys as a dictionary
            otherwise the appropriate keys in a list
        """
        if self._key:
            if self.remote: # verify that it's not to old
                if time.time() > self.time_out:
                    self.update()
        elif self.remote:
            self.update()

        if typ:
            try:
                return self._key[typ]
            except KeyError:
                return []
        else:
            return self._key

    def keys(self):
        if self.remote: # verify that it's not to old
            if time.time() > self.time_out:
                self.update()

        return self._key

    def remove(self, typ, val=None):
        """

        :param typ: Type of key (rsa, ec, hmac, ..)
        :param val: The key it self
        """
        if val:
            try:
                self._key[typ].remove(val)
            except (ValueError, KeyError):
                pass
        else:
            try:
                del self._key[typ]
            except KeyError:
                pass

    def __str__(self):
        return "%s" % self._key

class KeyJar(object):
    """ A keyjar contains a number of KeyChains """

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

    def add(self, issuer, url, src_type="", use=""):
        """

        :param issuer: Who issued the keys
        :param url: Where can the key/-s be found
        :param src_type: How are the keys packed
        """
        kc = KeyChain(source=url, src_type=src_type, usage=use)

        try:
            self.issuer_keys[issuer].append(kc)
        except KeyError:
            self.issuer_keys[issuer] = [kc]

        return kc

    def __setitem__(self, issuer, val):
        if not isinstance(val, list):
            val = [val]

        self.issuer_keys[issuer] = val

    def get(self, use, type="", issuer=""):
        """

        :param use: A key useful for this usage (enc, dec, sig, ver)
        :param type: Type of key (rsa, ec, hmac, ..)
        :param issuer: Who is responsible for the keys, "" == me
        :return: A possibly empty list of keys
        """
        res = {}
        if type:
            lst = []
            for kc in self.issuer_keys[issuer]:
                if use in kc.usage:
                    lst.extend(kc.get(type))
            res[type] = lst
        else:
            for kc in self.issuer_keys[issuer]:
                if use in kc.usage:
                    res.update(kc.keys())

        return res

    def get_signing_key(self, type="", owner=""):
        return self.get("sig", type, owner)

    def get_verify_key(self, type="", owner=""):
        return self.get("ver", type, owner)

    def get_encrypt_key(self, type="", owner=""):
        return self.get("enc", type, owner)

    def get_decrypt_key(self, type="", owner=""):
        return self.get("dec", type, owner)

    def provider_keys(self, inst, issuer, replace=True):
        """
        Fetch keys from another server

        :param inst: The provider information
        :param issuer: The provider URL
        :param replace: If all previously gathered keys from this provider
            should be replace.
        :return: Dictionary with usage as key and keys as values
        """

        logger.debug("loading keys for issuer: %s" % issuer)
        logger.debug("pcr: %s" % inst)

        for typ in ["jwk", "x509"]:
            _kc = None
            for pat, use in URLPAT:
                spec = pat % typ
                if spec in inst and inst[spec]:
                    _kc = self.add(issuer, inst[spec], typ, use)
                elif use == "enc" and _kc:
                    _kc.usage.append(use)

        try:
            logger.debug("keys: %s" % self.issuer_keys[issuer])
            return self.issuer_keys[issuer]
        except KeyError:
            return None

    def __contains__(self, item):
        if item in self.issuer_keys:
            return True
        else:
            return False

    def verify_keys(self, part):
        """
        Keys for me and someone else.

        :param part: The other part
        :return: dictionary of keys
        """

        keys = self.get_verify_key(type="", owner=part)
        for typ, val in self.get_verify_key(type="", owner="").items():
            try:
                keys[typ].extend(val)
            except KeyError:
                keys[typ] = val
        return keys

    def __getitem__(self, issuer):
        return self.issuer_keys[issuer]

    def remove_key(self, issuer, type, key):
        try:
            kcs = self.issuer_keys[issuer]
        except KeyError:
            return

        for kc in kcs:
            kc.remove(type, key)

    def update(self, kj):
        for key, val in kj.issuer_keys.items():
            self.issuer_keys[key] = val

    def match_owner(self, url):
        for owner in self.issuer_keys.keys():
            if url.startswith(owner):
                return owner

        raise Exception("No keys for '%s'" % url)

    def __str__(self):
        return "%s" % self.issuer_keys

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
            self.issuer_keys[issuer] = {}

        if pcr["jwk_url"]:
            kc_j = self.add(issuer, pcr["jwk_url"], src_type="jwk", use="ver")
        else:
            kc_j = None
        if pcr["x509_url"]:
            kc_x = self.add(issuer, pcr["x509_url"], src_type="x509", use="ver")
        else:
            kc_x = None
        if pcr["jwk_encryption_url"]:
            self.add(issuer, pcr["jwk_encryption_url"], src_type="jwk",
                     use="dec")
        elif kc_j:
            kc_j.usage.append("dec")
        if pcr["x509_encryption_url"]:
            self.add(issuer, pcr["x509_encryption_url"], src_type="x509",
                     use="dec")
        else:
            kc_x.usage.append("dec")

# =============================================================================

def key_export(baseurl, local_path, vault, keyjar, fqdn="", **kwargs):
    """
    :param baseurl: The base URL to which the key file names are added
    :param local_path: Where on the machine the export files are kept
    :param vault: Where the keys are kept
    :param keyjar: Where to store the exported keys
    :param fqdn: Fully qualified domain name
    :return: 2-tuple: result of urlsplit and a dictionary with
        parameter name as key and url and value
    """
    part = urlparse.urlsplit(baseurl)

    # deal with the export directory
    if part.path.endswith("/"):
        _path = part.path[:-1]
    else:
        _path = part.path[:]

    local_path = proper_path("%s/%s" % (_path,local_path))
    vault_path = proper_path(vault)

    if not os.path.exists(vault_path):
        os.makedirs(vault_path)

    if not os.path.exists(local_path):
        os.makedirs(local_path)

    res = {}
    # For each usage type
    # type, usage, format (rsa, sign, jwt)
    issuer_keys = {"sig":[], "ver": [], "enc": [], "dec":[]}
    for usage in ["sig", "enc"]:
        if usage in kwargs:
            if kwargs[usage] is None:
                continue

            _args = kwargs[usage]
            if _args["alg"] == "rsa":
                try:
                    _key = rsa_load('%s%s' % (vault_path, "pyoidc"))
                except Exception:
                    devnull = open(os.devnull, 'w')
                    with RedirectStdStreams(stdout=devnull, stderr=devnull):
                        _key = create_and_store_rsa_key_pair(
                            path=vault_path)

                # order is not arbitrary, make_cert messes with key
                if "x509" in _args["format"]:
                    if usage == "sig":
                        _name = "x509_url"
                    else:
                        _name = "x509_encryption_url"

                    cert, _key = make_cert(2045, fqdn, _key)
                    # the local filename
                    _export_filename = "%s%s" % (local_path, "cert.pem")
                    cert.save(_export_filename)
                    _url = "%s://%s%s" % (part.scheme, part.netloc,
                                          _export_filename[1:])

                    res[_name] = _url


                rsa_key = rsa_load('%s%s' % (vault_path, "pyoidc"))
                kc = KeyChain({"rsa": rsa_key}, usage=[usage])
                if usage == "sig":
                    kc.usage.append("ver")
                elif usage == "enc":
                    kc.usage.append("dec")

                if "jwk" in _args["format"]:
                    if usage == "sig":
                        _name = ("jwk.json", "jwk_url")
                    else:
                        _name = ("jwk_enc.json", "jwk_encryption_url")

                    # the local filename
                    _export_filename = "%s%s" % (local_path, _name[0])

                    f = open(_export_filename, "w")
                    f.write(jwk.dumps([rsa_key], usage))
                    f.close()

                    _url = "%s://%s%s" % (part.scheme, part.netloc,
                                          _export_filename[1:])

                    res[_name[1]] = _url

                if usage == "sig" and "enc" not in kwargs:
                    kc.usage.extend(["enc", "dec"])

                try:
                    keyjar[""].append(kc)
                except KeyError:
                    keyjar[""] = kc

    return part, res

# ================= create RSA key ======================

def create_and_store_rsa_key_pair(name="pyoidc", path=".", size=1024):
    #Seed the random number generator with 1024 random bytes (8192 bits)
    M2Crypto.Rand.rand_seed(os.urandom(size))

    key = M2Crypto.RSA.gen_key(size, 65537, lambda : None)

    if not path.endswith("/"):
        path += "/"

    key.save_key('%s%s' % (path, name), None, callback=no_passphrase_callback)
    key.save_pub_key('%s%s.pub' % (path, name))

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

import time
from M2Crypto import EVP
from M2Crypto import X509
from M2Crypto import RSA
from M2Crypto import ASN1

def make_req(bits, fqdn="example.com", rsa=None):
    pk = EVP.PKey()
    x = X509.Request()
    if not rsa:
        rsa = RSA.gen_key(bits, 65537, lambda : None)
    pk.assign_rsa(rsa)
    # Because rsa is messed with
    rsa = pk.get_rsa()
    x.set_pubkey(pk)
    name = x.get_subject()
    name.C = "SE"
    name.CN = "OpenID Connect Test Server"
    if fqdn:
        ext1 = X509.new_extension('subjectAltName', fqdn)
        extstack = X509.X509_Extension_Stack()
        extstack.push(ext1)
        x.add_extensions(extstack)
    x.sign(pk,'sha1')
    return x, pk, rsa

def make_cert(bits, fqdn="example.com", rsa=None):
    req, pk, rsa = make_req(bits, fqdn=fqdn, rsa=rsa)
    pkey = req.get_pubkey()
    sub = req.get_subject()
    cert = X509.X509()
    cert.set_serial_number(1)
    cert.set_version(2)
    cert.set_subject(sub)
    t = long(time.time()) + time.timezone
    now = ASN1.ASN1_UTCTIME()
    now.set_time(t)
    nowPlusYear = ASN1.ASN1_UTCTIME()
    nowPlusYear.set_time(t + 60 * 60 * 24 * 365)
    cert.set_not_before(now)
    cert.set_not_after(nowPlusYear)
    issuer = X509.X509_Name()
    issuer.CN = 'The code tester'
    issuer.O = 'Umea University'
    cert.set_issuer(issuer)
    cert.set_pubkey(pkey)
    cert.sign(pk, 'sha1')
    return cert, rsa



