__author__ = 'rohe0002'

import M2Crypto
import logging
import os
import urlparse
import sys
import traceback

from jwkest import jwk
from jwkest.jwk import load_x509_cert, x509_rsa_loads, loads
from jwkest.jwk import load_jwk
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

TYPE2FUNC = {"x509": x509_rsa_loads, "jwk": load_jwk}

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

class Key(object):
    def __init__(self, key=None, source="", type="", remote=True, srctype=""):
        if key:
            self._key = key
        else:
            self.source = source
            self.remote = remote
            self.srctype = srctype
            if remote == False: # local file
                if type == "rsa":
                    self._key = rsa_load(source)
                elif type == "ec":
                    self._key = ec_load(source)
            else: # load when needed
                self._key = None
        self.etag = ""
        self.cache_control = []

    def update(self, http_request):
        """
        Reload the key if necessary

        :param http_request: A function that can do a HTTP request
        """
        args = {"allow_redirects": True}
        if self.etag:
            args["headers"] = {"If-None-Match": self.etag}

        r = http_request(self.source, **args)
        if r.status_code == 304: # file has not changed
            return
        elif r.status_code == 200: # New content
            pass

    def get(self):
        if self._key:
            if self.remote: # verify that it's not to old
                pass
            return self._key
        elif self.remote:
            pass

    def set(self, key, cache_info):
        self._key = key


class KeyJar(object):

    def __init__(self, http_request, ca_certs=None):
        self.http_request = http_request
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

    def load(self, url, type, key=None):

        r = self.http_request(url, allow_redirects=True)
        if r.status_code == 200:
            _key = TYPE2FUNC[type](r.text)

            if key is None:
                key = Key(_key, url, remote=True, srctype=type)
            else:
                key.set(_key)

            try:
                key.etag = r.headers["Etag"]
            except KeyError:
                pass
            try:
                key.cache_control = r.headers["Cache-Control"]
            except KeyError:
                pass
            return
        else:
            raise Exception("HTTP Get error: %s" % r.status_code)

    def load_keys(self, inst, issuer, replace=False):
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
        if issuer not in self.issuer_keys:
            self.issuer_keys[issuer] = {}

        _s2k = self.spec2key
        for typ in ["jwk", "x509"]:
            _keys = None
            for pat, use in URLPAT:
                spec = pat % typ
                logger.debug("spec: %s, key: %s" % (spec, _keys))
                if spec in inst and inst[spec]:
                    _func = TYPE2FUNC[typ]
                    try:
                        _keys = _func(self.http_request, inst[spec], _s2k)
                    except Exception, err:
                        #message = traceback.format_exception(*sys.exc_info())
                        raise Exception(KEYLOADERR % (inst[spec], issuer, err))

                    self.add_if_unique(issuer, use, _keys)
                elif use == "enc" and _keys:
                    self.add_if_unique(issuer, use, _keys)

        logger.debug("keys: %s" % self.issuer_keys[issuer])
        return self.issuer_keys[issuer]

    def key_export(self, baseurl, local_path, vault, **kwargs):
        """
        :param baseurl: The base URL to which the key file names are added
        :param local_path: Where on the machine the export files are kept
        :param vault: Where the keys are kept
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
        self.issuer_keys[""] = {"sig":[], "ver":[], "enc": [], "dec":[]}

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

                        cert, _key = make_cert(2045, "lingon.ladok.umu.se",
                                               _key)
                        # the local filename
                        _export_filename = "%s%s" % (local_path, "cert.pem")
                        cert.save(_export_filename)
                        _url = "%s://%s%s" % (part.scheme, part.netloc,
                                              _export_filename[1:])

                        res[_name] = _url


                    rsa_key = rsa_load('%s%s' % (vault_path, "pyoidc"))
                    keyspec = ("rsa", rsa_key)
                    self.issuer_keys[""][usage] = [keyspec]
                    if usage == "sig":
                        self.issuer_keys[""]["ver"] = [keyspec]
                    elif usage == "enc":
                        self.issuer_keys[""]["dec"] = [keyspec]

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
                        self.issuer_keys[""]["enc"] = [keyspec]
                        self.issuer_keys[""]["dec"] = [keyspec]

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

# ============================================================================

def get_signing_key(keystore, keytype="rsa", owner=None):
    """Find out which key and algorithm to use

    :param keystore: The key store
    :param keytype: which type of key to use
    :param owner: Whoes key to look for
    :return: key
    """

    if keytype == "hmac":
        ckey = {"hmac": keystore.get_sign_key("hmac",owner=owner)}
    elif keytype == "rsa": # own asymmetric key
        ckey = {"rsa": keystore.get_sign_key("rsa")}
    else:
        ckey = {"ec":keystore.get_sign_key("ec")}

    logger.debug("Sign with '%s'" % (ckey,))

    return ckey


