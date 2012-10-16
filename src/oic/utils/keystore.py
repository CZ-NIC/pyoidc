import copy
import sys
import M2Crypto
import logging
import string

from oic.utils.keyio import KeyJar

__author__ = 'rohe0002'

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
logger = logging.getLogger(__name__)

# ========== base64 encoding/decoding large numbers ====

ALPHABET = string.ascii_uppercase + string.ascii_lowercase +\
           string.digits + '-_'
ALPHABET_REVERSE = dict((c, i) for (i, c) in enumerate(ALPHABET))
BASE = len(ALPHABET)
TB = 2**24
foo = '0000 0001 0000 0000 0000 0001'
foo_b64 = "QAB="


# ======================================================================

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

def x509_rsa_loads(string):
    cert = M2Crypto.X509.load_cert_string(string)
    return cert.get_pubkey().get_rsa()

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

class KeyStore(object):

    def __init__(self, http_request, keyspecs=None):
        self._store = {}
        self.spec2key = {}
        self.crypt = KeyJar(http_request)
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
            self._store[owner] = {"sig": {}, "ver": {}, "enc": {},
                                  "dec": {}}
            self._store[owner][usage][type] = [key]
        else:
            _keys = self._store[owner][usage]
            try:
                for _key in _keys[type]:
                    if key_eq(_key, key):
                        return

                _keys[type].append(key)
            except KeyError:
                _keys[type] = [key]

    def get_keys(self, usage, type=None, owner="."):
        logger.debug("get_keys(%s, %s, %s)" % (usage, type, owner))
        if not owner:
            res = {}
            for owner, _spec in self._store.items():
                _r0 = {}
                for usage, _val in _spec.items():
                    _r1 = {}
                    for typ, val in _val.items():
                        _r1[typ] = val[:]
                    _r0[usage] = _r1
                res[owner] = _r0
            return res
        else:
            try:
                if type:
                    return self._store[owner][usage][type][:]
                else:
                    return copy.copy(self._store[owner][usage])
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
                        _coll[usage][typ] = keys[:]

        return _coll

    def keys_by_owner(self, owner):
        """
        Get all the keys that belongs to an owner

        :param owner: The name/URL of the owner
        """
        try:
            return copy.copy(self._store[owner])
        except KeyError:
            return {}

    def remove_key_collection(self, owner):
        """
        Remove all keys that belongs to an owner

        :param owner: The name/URL of the owner
        """
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
        return self.get_keys("ver", type, owner)

    def get_sign_key(self, type="", owner="."):
        return self.get_keys("sig", type, owner)

    def get_encrypt_key(self, type="", owner="."):
        return self.get_keys("enc", type, owner)

    def get_decrypt_key(self, type="", owner="."):
        return self.get_keys("dec", type, owner)

    def set_verify_key(self, val, type="hmac", owner="."):
        self.add_key(val, type, "ver", owner)

    def set_sign_key(self, val, type="hmac", owner="."):
        self.add_key(val, type, "sig", owner)

    def set_encrypt_key(self, val, type="hmac", owner="."):
        self.add_key(val, type, "enc", owner)

    def set_decrypt_key(self, val, type="hmac", owner="."):
        self.add_key(val, type, "dec", owner)

    def match_owner(self, url):
        for owner in self._store.keys():
            if url.startswith(owner):
                return owner

        raise Exception("No keys for '%s'" % url)

    def collect_keys(self, url, usage="ver"):
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

    def update(self, keystore):
        """
        Add keys from another keystore to this keystore

        :param keystore:
        """

        for owner, spec in keystore._store.items():
            if owner == ".":
                continue
            self._store[owner] = spec

    def load_keys(self, pcr, issuer, replace=False):
        for usage, keys in self.crypt.load_keys(pcr, issuer, replace).items():
            for typ, key in keys:
                self.add_key(key, typ, usage, issuer)

    def key_export(self, baseurl, local_path, vault, **kwargs):
        res = self.crypt.key_export(baseurl, local_path, vault, **kwargs)

        for usage, keyspec in self.crypt.issuer_keys[""].items():
            for typ, key in keyspec:
                self.add_key(key, typ, usage, ".")

        return res

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

def get_verify_key(keystore, keytype="rsa", owner=None):
    """Find out which key and algorithm to use

    :param keystore: The key store
    :param keytype: which type of key to use
    :param owner: Whoes key to look for
    :return: key
    """

    if keytype == "hmac":
        ckey = {"hmac": keystore.get_verify_key("hmac",owner=owner)}
    elif keytype == "rsa": # own asymmetric key
        ckey = {"rsa": keystore.get_verify_key("rsa", owner=owner)}
    else:
        ckey = {"ec":keystore.get_verify_key("ec", owner=owner)}

    logger.debug("Verify with '%s'" % (ckey,))

    return ckey
