import importlib
from tempfile import NamedTemporaryFile
from oic.utils.userinfo import UserInfo
from saml2 import saml, samlp
from saml2.client import Saml2Client
from saml2 import config

__author__ = 'danielevertsson'

class AaUserInfo(UserInfo):

    def __init__(self, spconf, url, db=None):
        UserInfo.__init__(self, db)
        #Configurations for the SP handler. (pyOpSamlProxy.client.sp.conf)
        self.sp_conf = importlib.import_module(spconf)
        ntf = NamedTemporaryFile(suffix="pyoidc.py", delete=True)
        ntf.write("CONFIG = " + str(self.sp_conf.CONFIG).replace("%s", url))
        ntf.seek(0)
        self.sp = Saml2Client(config_file="%s" % ntf.name)


    def __call__(self, userid, user_info_claims=None, **kwargs):
        try:
            ava = self.db[userid]
            entity_id = self.sp_conf.AA_ENTITY_ID
            if entity_id is None:
                entity_id = ava["AA_ENTITYID"]
            response = self.sp.do_attribute_query(entity_id ,
                                                  ava[self.sp_conf.AA_NAMEID_ATTRIBUTE][0],
                                                  nameid_format=self.sp_conf.AA_NAMEID_FORMAT)

            return response.ava
        except Exception as ex:
            return {}

    def filter(self, userinfo, user_info_claims=None):
        return userinfo