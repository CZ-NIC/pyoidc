import json

from oic.utils.http_util import Response

from provider.authn import make_cls_from_name, AuthnModule


class UserPass(AuthnModule):
    url_endpoint = "/user_pass/verify"

    def __init__(self, db, template_env, template="user_pass.jinja2", **kwargs):
        super(UserPass, self).__init__(None)
        self.template_env = template_env
        self.template = template

        cls = make_cls_from_name(db["class"])
        self.user_db = cls(**db["kwargs"])

        self.kwargs = kwargs
        self.kwargs.setdefault("page_header", "Log in")
        self.kwargs.setdefault("user_label", "Username")
        self.kwargs.setdefault("passwd_label", "Password")
        self.kwargs.setdefault("submit_btn", "Log in")

    def __call__(self, *args, **kwargs):
        template = self.template_env.get_template(self.template)
        return Response(template.render(action=self.url_endpoint,
                                        state=json.dumps(kwargs),
                                        **self.kwargs))

    def verify(self, *args, **kwargs):
        username = kwargs["username"]
        if username in self.user_db and self.user_db[username] == kwargs[
            "password"]:
            return username, True
        else:
            return self.FAILED_AUTHN
