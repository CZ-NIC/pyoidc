import importlib
from tempfile import NamedTemporaryFile
from saml2.client import Saml2Client
import six

from oic.utils.userinfo import UserInfo


__author__ = 'danielevertsson'


class AaUserInfo(UserInfo):
    def __init__(self, spconf, url, db=None):
        UserInfo.__init__(self, db)

        # Configurations for the SP handler. (pyOpSamlProxy.client.sp.conf)
        self.sp_conf = importlib.import_module(spconf)
        ntf = NamedTemporaryFile(suffix="pyoidc.py", delete=True)
        ntf.write("CONFIG = " + str(self.sp_conf.CONFIG).replace("%s", url))
        ntf.seek(0)
        self.sp = Saml2Client(config_file="%s" % ntf.name)
        self.samlcache = self.sp_conf.SAML_CACHE

    def __call__(self, userid, client_id, user_info_claims=None, **kwargs):
        try:
            ava = self.db[userid]
            entity_id = self.sp_conf.AA_ENTITY_ID
            if entity_id is None:
                entity_id = self.samlcache["AA_ENTITYID"]
            response = self.sp.do_attribute_query(
                entity_id,
                ava[self.sp_conf.AA_NAMEID_ATTRIBUTE][0],
                nameid_format=self.sp_conf.AA_NAMEID_FORMAT,
                attribute=self.sp_conf.AA_REQUEST_ATTRIBUTES)

            response_dict = response.ava.copy()
            if self.sp_conf.AA_ATTRIBUTE_SAML_IDP is True:
                for key, value in six.iteritems(ava):
                    if (self.sp_conf.AA_ATTRIBUTE_SAML_IDP_WHITELIST is None or
                            key in self.sp_conf.AA_ATTRIBUTE_SAML_IDP_WHITELIST) and \
                            key not in response_dict:
                        response_dict[key] = value

            return response_dict
        except Exception:
            return {}

    def filter(self, userinfo, user_info_claims=None):
        return userinfo