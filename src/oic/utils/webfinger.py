# coding=utf-8
import json
import logging
import re
from oic.exception import PyoidcError
import requests

try:
    from past.builtins import basestring
except ImportError:
    pass

from six.moves.urllib.parse import urlencode, urlparse

from oic.utils.time_util import in_a_while


__author__ = 'rolandh'

logger = logging.getLogger(__name__)

WF_URL = "https://%s/.well-known/webfinger"
OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer"

class WebFingerError(PyoidcError):
    pass


class Base(object):
    c_param = {}

    def __init__(self, dic=None):
        self._ava = {}
        if dic is not None:
            self.load(dic)

    def __setitem__(self, item, val):
        spec = self.c_param[item]
        try:
            t1, t2 = spec["type"]
            if t1 == list:  # Should always be
                assert not isinstance(val, basestring)
                assert isinstance(val, list)
                res = []
                if t2 == LINK:
                    for v in val:
                        res.append(LINK(v))
                else:
                    for v in val:
                        try:
                            assert isinstance(v, t2)
                        except AssertionError:
                            pass
                        res.append(v)
                self._ava[item] = res
        except TypeError:
            t2_type = spec["type"]
            try:
                assert isinstance(val, t2_type)
                self._ava[item] = val
            except AssertionError:
                pass

    def load(self, dictionary):
        for key, spec in list(self.c_param.items()):
            if key not in dictionary and spec["required"] is True:
                raise AttributeError("Required attribute '%s' missing" % key)

        for key, val in list(dictionary.items()):
            if val == "" or val == [""]:
                continue

            skey = str(key)
            try:
                self[skey] = val
            except KeyError:
                # ignore what I don't know
                pass

        return self

    def dump(self):
        res = {}
        for key in list(self.c_param.keys()):
            try:
                val = self._ava[key]
            except KeyError:
                continue

            if self.c_param[key]["type"] == (list, LINK):
                sres = []
                for _val in val:
                    sres.append(_val.dump())
                val = sres
            res[key] = val
        return res

    def __repr__(self):
        return "%s" % self.dump()

    def verify(self):
        pass

    def __getitem__(self, item):
        return self._ava[item]

    def items(self):
        return list(self._ava.items())

    def keys(self):
        return list(self._ava.keys())

    def values(self):
        return list(self._ava.values())

    def __len__(self):
        return self._ava.__len__()

    def __contains__(self, item):
        return item in self._ava


class LINK(Base):
    c_param = {
        "rel": {"type": basestring, "required": True},
        "type": {"type": basestring, "required": False},
        "href": {"type": basestring, "required": False},
        "titles": {"type": dict, "required": False},
        "properties": {"type": dict, "required": False},
    }


class JRD(Base):
    c_param = {
        "expires": {"type": basestring, "required": False},  # Optional
        "subject": {"type": basestring, "required": False},  # Should
        "aliases": {"type": (list, basestring), "required": False},  # Optional
        "properties": {"type": dict, "required": False},  # Optional
        "links": {"type": (list, LINK), "required": False},  # Optional
    }

    def __init__(self, dic=None, days=0, seconds=0, minutes=0, hours=0,
                 weeks=0):
        Base.__init__(self, dic)
        self.expires_in(days, seconds, minutes, hours, weeks)

    def expires_in(self, days=0, seconds=0, minutes=0, hours=0, weeks=0):
        self._exp_days = days
        self._exp_secs = seconds
        self._exp_min = minutes
        self._exp_hour = hours
        self._exp_week = weeks

    def export(self):
        res = self.dump()
        res["expires"] = in_a_while(days=self._exp_days, seconds=self._exp_secs,
                                    minutes=self._exp_min, hours=self._exp_hour,
                                    weeks=self._exp_week)
        return res


# -- Normalization --
# A string of any other type is interpreted as a URI either the form of scheme
# "://" authority path-abempty [ "?" query ] [ "#" fragment ] or authority
# path-abempty [ "?" query ] [ "#" fragment ] per RFC 3986 [RFC3986] and is
# normalized according to the following rules:
#
# If the user input Identifier does not have an RFC 3986 [RFC3986] scheme
# portion, the string is interpreted as [userinfo "@"] host [":" port]
# path-abempty [ "?" query ] [ "#" fragment ] per RFC 3986 [RFC3986].
# If the userinfo component is present and all of the path component, query
# component, and port component are empty, the acct scheme is assumed. In this
# case, the normalized URI is formed by prefixing acct: to the string as the
# scheme. Per the 'acct' URI Scheme [I‑D.ietf‑appsawg‑acct‑uri], if there is an
# at-sign character ('@') in the userinfo component, it needs to be
# percent-encoded as described in RFC 3986 [RFC3986].
# For all other inputs without a scheme portion, the https scheme is assumed,
# and the normalized URI is formed by prefixing https:// to the string as the
# scheme.
# If the resulting URI contains a fragment portion, it MUST be stripped off
# together with the fragment delimiter character "#".
# The WebFinger [I‑D.ietf‑appsawg‑webfinger] Resource in this case is the
# resulting URI, and the WebFinger Host is the authority component.
#
# Note: Since the definition of authority in RFC 3986 [RFC3986] is
# [ userinfo "@" ] host [ ":" port ], it is legal to have a user input
# identifier like userinfo@host:port, e.g., alice@example.com:8080.

class URINormalizer(object):
    def has_scheme(self, inp):
        if "://" in inp:
            return True
        else:
            authority = inp.replace('/', '#').replace('?', '#').split("#")[0]

            if ':' in authority:
                scheme_or_host, host_or_port = authority.split(':', 1)
                try:
                    # Assert it's not a port number
                    assert not re.match('^\d+$', host_or_port)
                except AssertionError:
                    return False
            else:
                return False
        return True

    def acct_scheme_assumed(self, inp):
        if '@' in inp:
            host = inp.split('@')[-1]
            return not (':' in host or '/' in host or '?' in host)
        else:
            return False

    def normalize(self, inp):
        if self.has_scheme(inp):
            pass
        elif self.acct_scheme_assumed(inp):
            inp = "acct:%s" % inp
        else:
            inp = "https://%s" % inp
        return inp.split("#")[0]  # strip fragment


class WebFinger(object):
    def __init__(self, default_rel=None, httpd=None):
        self.default_rel = default_rel
        self.httpd = httpd
        self.jrd = None

    def query(self, resource, rel=None):
        resource = URINormalizer().normalize(resource)

        info = [("resource", resource)]

        if rel is None:
            if self.default_rel:
                info.append(("rel", self.default_rel))
        elif isinstance(rel, basestring):
            info.append(("rel", rel))
        else:
            for val in rel:
                info.append(("rel", val))

        if resource.startswith("http"):
            #part = urlparse.urlparse(resource)
            part = urlparse(resource)
            host = part.hostname
            if part.port is not None:
                host += ":" + str(part.port)
        elif resource.startswith("acct:"):
            host = resource.split('@')[-1]
            host = host.replace('/', '#').replace('?', '#').split("#")[0]
        elif resource.startswith("device:"):
            host = resource.split(':')[1]
        else:
            raise WebFingerError("Unknown schema")

        return "%s?%s" % (WF_URL % host, urlencode(info))

    @staticmethod
    def load(item):
        return JRD(json.loads(item))

    def http_args(self, jrd=None):
        if jrd is None:
            if self.jrd:
                jrd = self.jrd
            else:
                return None

        return {
            "headers": {"Access-Control-Allow-Origin": "*",
                        "Content-Type": "application/json; charset=UTF-8"},
            "body": json.dumps(jrd.export())
        }

    def discovery_query(self, resource):
        """
        Given a resource find a OpenID connect OP to use

        :param resource: An identifier of an entity
        :return: A URL if an OpenID Connect OP could be found
        """

        logger.debug("Looking for OIDC OP for '%s'" % resource)
        url = self.query(resource, OIC_ISSUER)
        try:
            rsp = self.httpd.http_request(url)
        except requests.ConnectionError:
            raise

        if rsp.status_code == 200:
            self.jrd = self.load(rsp.text)
            for link in self.jrd["links"]:
                if link["rel"] == OIC_ISSUER:
                    return link["href"]
            return None
        elif rsp.status_code in [302, 301, 307]:
            return self.discovery_query(rsp.headers["location"])
        else:
            raise WebFingerError(rsp.status_code)

    def response(self, subject, base):
        self.jrd = JRD()
        self.jrd["subject"] = subject
        link = LINK()
        link["rel"] = OIC_ISSUER
        link["href"] = base
        self.jrd["links"] = [link]
        return json.dumps(self.jrd.export())