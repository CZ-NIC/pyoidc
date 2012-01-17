# ========================================================================
# Copyright (c) 2007, Metaweb Technologies, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY METAWEB TECHNOLOGIES AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL METAWEB
# TECHNOLOGIES OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ========================================================================

#
#
#  httplib2cookie.py allows you to use python's standard
#   CookieJar class with httplib2.
#
#

import re
import cookielib
from httplib2 import Http, RedirectLimit

import urllib
import urllib2

class DummyRequest(object):
    """Simulated urllib2.Request object for httplib2

       implements only what's necessary for cookielib.CookieJar to work
    """
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers
        self.origin_req_host = urllib2.request_host(self)
        self.type, r = urllib.splittype(url)
        self.host, r = urllib.splithost(r)
        if self.host:
            self.host = urllib.unquote(self.host)

    def get_full_url(self):
        return self.url

    def get_origin_req_host(self):
        # TODO to match urllib2 this should be different for redirects
        return self.origin_req_host

    def get_type(self):
        return self.type

    def get_host(self):
        return self.host

    def get_header(self, key, default=None):
        return self.headers.get(key.lower(), default)

    def has_header(self, key):
        return key in self.headers

    def add_unredirected_header(self, key, val):
        # TODO this header should not be sent on redirect
        self.headers[key.lower()] = val

    def is_unverifiable(self):
        # TODO to match urllib2, this should be set to True when the
        #  request is the result of a redirect
        return False


class DummyResponse(object):
    """Simulated urllib2.Request object for httplib2

       implements only what's necessary for cookielib.CookieJar to work
    """
    def __init__(self, response):
        self.response = response

    def info(self):
        return DummyMessage(self.response)


class DummyMessage(object):
    """Simulated mimetools.Message object for httplib2

       implements only what's necessary for cookielib.CookieJar to work
    """
    def __init__(self, response):
        self.response = response

    #noinspection PyUnusedLocal
    def getheaders(self, k):
        k = k.lower()
        v = self.response.get(k.lower(), None)
        if k not in self.response:
            return []
            #return self.response[k].split(re.compile(',\\s*'))

        # httplib2 joins multiple values for the same header
        #  using ','.  but the netscape cookie format uses ','
        #  as part of the expires= date format.  so we have
        #  to split carefully here - header.split(',') won't do it.
        HEADERVAL= re.compile(r'\s*(([^,]|(,\s*\d))+)')
        return [h[0] for h in HEADERVAL.findall(self.response[k])]

class CookiefulHttp(Http):
    """Subclass of httplib2.Http that keeps cookie state

       constructor takes an optional cookiejar=cookielib.CookieJar

       currently this does not handle redirects completely correctly:
       if the server redirects to a different host the original
       cookies will still be sent to that host.
    """
    def __init__(self, cookiejar=None, **kws):
        # note that httplib2.Http is not a new-style-class
        Http.__init__(self, **kws)
        if cookiejar is None:
            cookiejar = cookielib.CookieJar()
        self.cookiejar = cookiejar

    def crequest(self, uri, trace=None, **kws):
        """
        """
        headers = kws.pop('headers', {})
        req = DummyRequest(uri, headers)
        self.cookiejar.add_cookie_header(req)
        headers = req.headers

        if trace:
            trace.request("HEADERS: %s" % headers)

        try:
            (r, body) = Http.request(self, uri, headers=headers,
                                     redirections=0, **kws)
        except RedirectLimit, err:
            r = err.response
            body = err.content

        resp = DummyResponse(r)
        self.cookiejar.extract_cookies(resp, req)

        return r, body