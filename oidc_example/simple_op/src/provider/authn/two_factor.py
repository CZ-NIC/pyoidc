from email.mime.text import MIMEText
import hashlib
import json
import smtplib
import time

from oic.utils.http_util import Response

from provider.authn import AuthnModule, make_cls_from_name
from provider.authn.user_pass import UserPass


class MailTwoFactor(AuthnModule):
    url_endpoint = "/two_factor/verify"

    def __init__(self, user_db, passwd_db, smtp_server, outgoing_sender,
                 template_env, code_ttl=2, template="mail_two_factor.jinja2",
                 **kwargs):
        """

        :param user_db:
        :param smtp_server:
        :param outgoing_sender:
        :param code_ttl: how long the code is valid (in minutes)
        :param kwargs:
        :return:
        """
        super(MailTwoFactor, self).__init__(None)
        self.template_env = template_env
        self.template = template

        self.first_factor = UserPass(passwd_db, template_env)
        self.first_factor.url_endpoint = self.url_endpoint

        cls = make_cls_from_name(user_db["class"])
        self.user_db = cls(**user_db["kwargs"])
        self.smtp_server = smtp_server
        self.outgoing_sender = outgoing_sender
        self.code_ttl = code_ttl * 60 * 1000  # ttl in ms

        self.codes = {}

    def __call__(self, *args, **kwargs):
        # delegate to first factor module
        return self.first_factor(*args, **kwargs)

    def verify(self, *args, **kwargs):
        # second auth with code
        if "code" in kwargs:
            code = kwargs["code"]

            try:
                entry = self.codes[code]
            except KeyError:
                return self.FAILED_AUTHN

            username = entry["username"]
            # Verify code is not too old
            now = time.time()
            if now - entry["time"] > self.code_ttl:
                return self.FAILED_AUTHN

            del self.codes[code]  # Removed used code
            return username, True

        else:
            result = self.first_factor.verify(*args, **kwargs)
            if result == self.FAILED_AUTHN:
                return self.FAILED_AUTHN

            username, _ = result
            try:
                receiver = self.user_db[username]["email"]
            except KeyError:
                # Missing user or no mail address
                self.FAILED_AUTHN

            # Generate code and send it
            code = hashlib.md5(str(time.time())).hexdigest()
            self.codes[code] = {"username": username, "time": time.time()}
            self._send_mail(code, receiver)

            template = self.template_env.get_template(self.template)
            response = Response(template.render(mail=receiver,
                                                action=self.url_endpoint,
                                                state=json.dumps(
                                                    kwargs["state"])))
            return response, False

    def _send_mail(self, code, receiver):
        msg = MIMEText("Code: {}".format(code))
        msg["Subject"] = "Authentication code"
        msg["From"] = self.outgoing_sender
        msg["To"] = receiver

        s = smtplib.SMTP(self.smtp_server)
        s.sendmail(self.outgoing_sender, [receiver], msg.as_string())
        s.quit()