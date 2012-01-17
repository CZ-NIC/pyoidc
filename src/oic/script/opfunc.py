__author__ = 'rohe0002'

import json

from urlparse import urlparse

from mechanize import ParseResponse
from mechanize._form import ControlNotFoundError
#from httplib2 import Response

class FlowException(Exception):
    def __init__(self, function="", content="", url=""):
        Exception.__init__(self)
        self.function = function
        self.content = content
        self.url = url

    def __str__(self):
        return json.dumps(self.__dict__)


class DResponse():
    def __init__(self, **kwargs):
        self.status = 200
        self.index = 0
        self._message = ""
        self.url = ""
        if kwargs:
            for key, val in kwargs.items():
                self.__setitem__(key, val)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        if item == "content-location":
            return self.url
        elif item == "content-length":
            return len(self._message)
        else:
            return getattr(self, item)

    def geturl(self):
        return self.url

    def read(self, size=0):
        if size:
            if self._len < size:
                return self._message
            else:
                if self._len == self.index:
                    part = None
                elif self._len - self.index < size:
                    part = self._message[self.index:]
                    self.index = self._len
                else:
                    part = self._message[self.index:self.index+size]
                    self.index += size
                return part
        else:
            return self._message

    def write(self, message):
        self._message = message
        self._len = len(message)


def do_request(client, url, method, body="", headers=None, trace=False):
    if headers is None:
        headers = {}

    if trace:
        trace.request("URL: %s" % url)
        trace.request("BODY: %s" % body)

    response, content = client.http_request(url, method=method,
                                            body=body, headers=headers,
                                            trace=trace)

    if trace:
        trace.reply("RESPONSE: %s" % response)
        trace.reply("CONTENT: %s" % unicode(content, encoding="utf-8"))

    return response, content

def pick_form(response, content, url=None, **kwargs):
    forms = ParseResponse(response)
    if not forms:
        raise FlowException(content=content, url=url)

    form = None
    if len(forms) == 1:
        form = forms[0]
    else:
        for form in forms:
            if kwargs["_action_url"] in form.action:
                break

    return form

#noinspection PyUnusedLocal
def login_form(client, orig_response, content, **kwargs):
    _url = orig_response["content-location"]
    # content is a form to be filled in and returned
    response = DResponse(status=orig_response["status"], url=_url)
    response.write(content)

    form = pick_form(response, content, _url, **kwargs)

    try:
        form[kwargs["user_label"]] = kwargs["user"]
    except KeyError:
        pass

    try:
        form[kwargs["password_label"]] = kwargs["password"]
    except KeyError:
        pass

    request = form.click()

    headers = {}
    for key, val in request.unredirected_hdrs.items():
        headers[key] = val

    url = request._Request__original
    try:
        _trace = kwargs["_trace_"]
    except KeyError:
        _trace = False

    return do_request(client, url, "POST", request.data, headers, _trace)

#noinspection PyUnusedLocal
def approve_form(client, orig_response, content, **kwargs):
    # content is a form to be filled in and returned
    response = DResponse(status=orig_response["status"],
    )
    if orig_response["status"] == 302:
        response.url = orig_response["content-location"]
    else:
        response.url = client.authorization_endpoint
    response.write(content)

    form = pick_form(response, content, **kwargs)

    # do something with args

    request = form.click()

    headers = {}
    for key, val in request.unredirected_hdrs.items():
        headers[key] = val

    try:
        _trace = kwargs["_trace_"]
    except KeyError:
        _trace = False

    url = request._Request__original
    return do_request(client, url, "POST", request.data, headers, _trace)
#    resp.url = request._Request__original
#    return resp, request.data

def select_form(client, orig_response, content, **kwargs):
    _url = orig_response["content-location"]
    # content is a form to be filled in and returned
    response = DResponse(status=orig_response["status"], url=_url)
    response.write(content)

    form = pick_form(response, content, _url, **kwargs)

    for key, val in kwargs.items():
        if key.startswith("_"):
            continue

        try:
            form[key] = val
        except ControlNotFoundError:
            pass

    request = form.click()

    headers = {}
    for key, val in request.unredirected_hdrs.items():
        headers[key] = val

    url = request._Request__original
    try:
        _trace = kwargs["_trace_"]
    except KeyError:
        _trace = False

    if form.method == "POST":
        return do_request(client, url, "POST", request.data, headers, _trace)
    else:
        return do_request(client, url, "GET", headers=headers, trace=_trace)

#noinspection PyUnusedLocal
def chose(client, orig_response, content, **kwargs):
    _loc = orig_response["content-location"]
    part = urlparse(_loc)
    #resp = Response({"status":"302"})

    try:
        _trace = kwargs["trace"]
    except KeyError:
        _trace = False

    url = "%s://%s%s" %  (part[0], part[1], kwargs["path"])
    return do_request(client, url, "GET", trace=_trace)
    #return resp, ""

def post_form(client, orig_response, content, **kwargs):
    _url = orig_response["content-location"]
    # content is a form to be filled in and returned
    response = DResponse(status=orig_response["status"], url=_url)
    response.write(content)

    form = pick_form(response, content, _url, **kwargs)

    request = form.click()

    headers = {}
    for key, val in request.unredirected_hdrs.items():
        headers[key] = val

    url = request._Request__original
    try:
        _trace = kwargs["_trace_"]
    except KeyError:
        _trace = False

    if form.method == "POST":
        return do_request(client, url, "POST", request.data, headers, _trace)
    else:
        return do_request(client, url, "GET", headers=headers, trace=_trace)

# ========================================================================

#LOGIN_FORM = {
#    "function": login_form,
#    "args": {
#        "user_label": "login",
#        "password_label": "password",
#        "user": "username",
#        "password": "hemligt"
#        }
#}

LOGIN_FORM = {
    "id": "login_form",
    "function": login_form,
    }

APPROVE_FORM = {
    "id": "approve_form",
    "function": approve_form,
    }


CHOSE = {
    "id": "chose",
    "function": chose,
    "args": { "path": "/account/fake"}
}

SELECT_FORM = {
    "id": "select_form",
    "function": select_form,
    "args": { "path": "/account/fake"}
}

POST_FORM = {
    "id": "post_form",
    "function": post_form,
    }

# ========================================================================