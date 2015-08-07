import sys
from oic.oauth2 import PBase
from oic.utils.webfinger import WebFinger, OIC_ISSUER

__author__ = 'roland'

wf = WebFinger(OIC_ISSUER)
wf.httpd = PBase()
print (wf.discovery_query(sys.argv[1]))