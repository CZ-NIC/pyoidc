import json
import logging

from yubico_client import yubico_exceptions
from yubico_client.yubico import Yubico
from oic.utils.http_util import Response
from provider.authn import AuthnModule, make_cls_from_name

logger = logging.getLogger(__name__)


class YubicoOTP(AuthnModule):
    url_endpoint = "/yubi_otp/verify"

    def __init__(self, yubikey_db, validation_server, client_id, template_env,
                 secret_key=None, verify_ssl=True, template="yubico_otp.jinja2",
                 **kwargs):
        super(YubicoOTP, self).__init__(None)
        self.template_env = template_env
        self.template = template

        cls = make_cls_from_name(yubikey_db["class"])
        self.yubikey_db = cls(**yubikey_db["kwargs"])

        self.client = Yubico(client_id, secret_key,
                             api_urls=[validation_server],
                             verify_cert=verify_ssl)
        if not verify_ssl:
            # patch yubico-client to not find any ca bundle
            self.client._get_ca_bundle_path = lambda: None

    def __call__(self, *args, **kwargs):
        template = self.template_env.get_template(self.template)
        return Response(template.render(action=self.url_endpoint,
                                        state=json.dumps(kwargs)))

    def verify(self, *args, **kwargs):
        otp = kwargs["otp"]
        try:
            status = self.client.verify(otp, return_response=True)
        except yubico_exceptions.InvalidClientIdError as e:
            logger.error(
                "Client with id {} does not exist".format(e.client_id))
            return self.FAILED_AUTHN
        except yubico_exceptions.SignatureVerificationError:
            logger.error("Signature verification failed")
            return self.FAILED_AUTHN
        except yubico_exceptions.StatusCodeError as e:
            logger.error(
                "Negative status code was returned: {}".format(
                    e.status_code))
            return self.FAILED_AUTHN

        if status:
            logger.debug("Success, the provided OTP is valid")
            yubikey_public_id = otp[:12]

            return self.yubikey_db[yubikey_public_id], True
        else:
            logger.error(
                "No response from the servers or received other negative status code")
