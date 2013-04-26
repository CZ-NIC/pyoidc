from oic.oauth2.exception import ParameterError
from oic.utils.authn.user import UserAuthnMethod

import json
import urllib
import uuid
import logging
import requests
import base64
import xml.etree.ElementTree as ET
from urlparse import parse_qs
from oic.utils.http_util import Redirect
from oic.utils.http_util import Unauthorized

logger = logging.getLogger(__name__)

class CasAuthnMethod(UserAuthnMethod):
    #Standard login url for a CAS server.
    CONST_CASLOGIN = "/cas/login?"
    #Standard URL for validation of a ticket for a CAS server.
    CONST_CAS_VERIFY_TICKET = "/serviceValidate"
    #Standard name for the parameter containing a CAS ticket.
    CONST_TICKET = "ticket"
    #Standard name for the parameter containing the service url (callback url).
    CONST_SERVICE = "service"
    #A successful verification of a ticket against a CAS service will contain this XML element.
    CONST_AUTHSUCCESS = "authenticationSuccess"
    #If a success full verification of a CAS ticket has been perform, the uid will be containd in a XML element
    #with this name.
    CONST_USER = "user"
    #Used for preventing replay attacks.
    CONST_NONCE = "nonce"
    CONST_QUERY = "query"
    CONST_CAS_COOKIE = "cascookie"

    def __init__(self, srv, cas_server, service_url, return_to):
        UserAuthnMethod.__init__(self, srv)
        self.cas_server = cas_server
        self.service_url = service_url
        self.return_to = return_to


    def createRedirect(self, query):
        nonce = uuid.uuid4().get_urn()
        service_url = urllib.urlencode({self.CONST_SERVICE: self.getServiceUrl(nonce)})
        cas_url = self.cas_server + self.CONST_CASLOGIN + service_url
        cookie = self.create_cookie('{"' + self.CONST_NONCE + '": "' + base64.b64encode(nonce) + '", "' +
                                    self.CONST_QUERY + '": "' + base64.b64encode(query) + '"}', self.CONST_CAS_COOKIE)
        return Redirect(cas_url, headers=[cookie])

    def handleCallback(self, ticket, service_url):
        data = {self.CONST_TICKET: ticket, self.CONST_SERVICE: service_url}
        resp = requests.get(self.cas_server + self.CONST_CAS_VERIFY_TICKET,
                            params=data)
        root = ET.fromstring(resp.content)
        for l1 in root:
            if self.CONST_AUTHSUCCESS in l1.tag:
                for l2 in l1:
                    if self.CONST_USER in l2.tag:
                        return l2.text
        return None

    def __call__(self, query, *args, **kwargs):
        return self.createRedirect(query)


    def getServiceUrl(self, nonce):
        return self.service_url + "?" + self.CONST_NONCE + "=" + nonce

    def verify(self, request, cookie, **kwargs):
        logger.debug("verify(%s)" % request)
        if isinstance(request, basestring):
            _dict = parse_qs(request)
        elif isinstance(request, dict):
            _dict = request
        else:
            raise ValueError("Wrong type of input")
        try:
            cas_cookie = self.getCookieValue(cookie, self.CONST_CAS_COOKIE)
            data = json.loads(cas_cookie)
            nonce = base64.b64decode(data[self.CONST_NONCE])
            if nonce != _dict[self.CONST_NONCE][0]:
                return Unauthorized("You are not authorized!")
            uid = self.handleCallback(_dict[self.CONST_TICKET], self.getServiceUrl(nonce))
            if uid is None or len(uid) == 0:
                return Unauthorized("You are not authorized!")
            cookie = self.create_cookie(uid)
            return_to = self.generateReturnUrl(self.return_to, uid)
            if '?' in return_to:
                return_to += "&"
            else:
                return_to += "?"
            return_to += base64.b64decode(data[self.CONST_QUERY])
            return Redirect(return_to, headers=[cookie])
        except:
            return Unauthorized("You are not authorized!")

