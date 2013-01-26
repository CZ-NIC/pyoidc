import json
from urllib import urlencode
import requests
from oic.utils.time_util import in_a_while

__author__ = 'rolandh'

WF_URL = "https://%s/.well-known/webfinger"
OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer"

class Base(object):
    c_param = {}

    def __init__(self, dic=None):
        self._ava = {}
        if dic is not None:
            self.load(dic)

    def __setitem__(self, item, val):
        spec = self.c_param[item]
        try:
            t1,t2 = spec["type"]
            if t1 == list: # Should always be
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
        for key,spec in self.c_param.items():
            if key not in dictionary and spec["required"] == True:
                raise AttributeError("Required attribute '%s' missing" % key)

        for key, val in dictionary.items():
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
        for key in self.c_param.keys():
            try:
                val = self._ava[key]
            except KeyError:
                continue

            if self.c_param[key] == (list, LINK):
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
        return self._ava.items()

    def keys(self):
        return self._ava.keys()

    def values(self):
        return self._ava.values()

    def __len__(self):
        return self._ava.__len__()

class LINK(Base):
    c_param = {
        "rel": {"type":basestring, "required":True},
        "type": {"type":basestring, "required":False},
        "href": {"type":basestring, "required":False},
        "titles": {"type":dict, "required":False},
        "properties": {"type":dict, "required":False},
        }

class JRD(Base):
    c_param = {
        "expires": {"type":basestring, "required":False},
        "subject": {"type":basestring, "required":True},
        "aliases": {"type":(list,basestring), "required":False},
        "properties": {"type":dict, "required":False},
        "links": {"type":(list, LINK), "required":False},
    }

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


class WebFinger(object):
    def __init__(self, default_rel=None, httpd=None):
        self.default_rel = default_rel
        self.httpd = httpd
        self.jrd = None

    def query(self, base, resource, rel=None):
        info = [("resource", resource)]

        if rel is None:
            if self.default_rel:
                info.append(("rel", self.default_rel))
        elif isinstance(rel, basestring):
            info.append(("rel", rel))
        else:
            for val in rel:
                info.append(("rel", val))

        return "%s?%s" % (WF_URL % base, urlencode(info))

    def load(self, item):
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

    def discovery_query(self, base, resource):
        """
        Given a resource find a OpenID connect OP to use

        :param base: The base URL for the query
        :param resource: An identifier of an entity
        :return: A URL if a there is an OpenID Connect OP that
        """

        url = self.query(base, resource)
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
        elif rsp.status_code in [302,301,307]:
            return self.discovery_query(rsp.headers["location"], resource)
        else:
            raise Exception(rsp.status_code)
