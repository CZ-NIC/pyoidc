#!/usr/bin/env python

__author__ = 'rohe0002'


#from importlib import import_module
#from httplib2 import Http

from oic.oic import Client
from oic.oic import message
from oic.oic.consumer import Consumer
from oic.oauth2.message import ErrorResponse

import operations

QUERY2RESPONSE = {
    "AuthorizationRequest": "AuthorizationResponse",
    "AccessTokenRequest": "AccessTokenResponse",
    "UserInfoRequest": "OpenIDSchema",
    "RegistrationRequest": "RegistrationResponse"
}

def make_sequence(info):
    sequences = []
    for flows in info["flows"]:
        sequence = []
        for flow in flows:
            (items, resp) = info["phases"][flow]
            if isinstance(items, basestring):
                seq = [getattr(operations, items.strip())]
            else:
                seq = [getattr(operations, item.strip()) for item in items]
            resp = getattr(operations, resp.strip())
            for _se in seq:
                try:
                    _se["function"] = _se["function"].__name__
                except KeyError:
                    pass
            sequence.append((seq, resp))
        sequences.append(sequence)

    info["sequences"] = sequences
    del info["flows"]
    del info["phases"]
    return info

class Trace(object):
    def __init__(self):
        self.trace = []

    def request(self, msg):
        self.trace.append("--> %s" % msg)

    def reply(self, msg):
        self.trace.append("<-- %s" % msg)

    def info(self, msg):
        self.trace.append("%s" % msg)

    def error(self, msg):
        self.trace.append("[ERROR] %s" % msg)

    def warning(self, msg):
        self.trace.append("[WARNING] %s" % msg)

    def __str__(self):
        return "\n". join([t.encode("utf-8") for t in self.trace])

    def clear(self):
        self.trace = []

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

#noinspection PyUnusedLocal
def do_operation(client, opdef, response=None, content=None, trace=None):
    op = opdef
    qresp = None

    if "request" in op:
        cls = getattr(message, op["request"])

        try:
            kwargs = op["args"]["kw"].copy()
        except KeyError:
            kwargs = {}

        try:
            kwargs["request_args"] = op["args"]["request"].copy()
            _req = kwargs["request_args"]
        except KeyError:
            _req = {}

        try:
            kwargs["extra_args"] = op["args"]["extra"].copy()
        except KeyError:
            pass

        cis = getattr(client, "construct_%s" % cls.__name__)(cls, **kwargs)

        ht_add = None

        if "token_placement" in kwargs:
            if kwargs["token_placement"] == "header":
                ht_add = {"Authorization": "Bearer %s" % cis.access_token}
                cis.access_token = None

        url, body, ht_args, cis = client.uri_and_body(cls, cis,
                                                      method=op["method"],
                                                      request_args=_req)

        if ht_add:
            ht_args.update({"headers": ht_add})

        if trace:
            trace.request("URL: %s" % url)
            trace.request("BODY: %s" % body)

        response, content = client.http_request(url, method=op["method"],
                                                body=body, trace=trace,
                                                **ht_args)

        if trace:
            trace.reply("RESPONSE: %s" % response)
            trace.reply("CONTENT: %s" % unicode(content, encoding="utf-8"))

    elif "function" in op:
        func = op["function"]
        try:
            _args = op["args"].copy()
        except KeyError:
            _args = {}

        _args["trace"] = trace

        if trace:
            trace.request("FUNCTION: %s" % func.__name__)
            trace.request("ARGS: %s" % _args)

        response, content = func(client, response, content, **_args)

        if trace:
            trace.reply("RESPONSE: %s" % response)
            trace.reply("CONTENT: %s" % unicode(content, encoding="utf-8"))
    else:
        try:
            url = response.url
        except AttributeError:
            url = response["location"]

        if op["method"] == "POST":
            body = content
        else:
            body=None

        if "Content-type" in response:
            headers = {"Content-type": response["Content-type"]}
        else:
            headers = {}

        if trace:
            trace.request("URL: %s" % url)
            trace.request("BODY: %s" % body)

        response, content = client.http_request(url, method=op["method"],
                                                body=body, headers=headers,
                                                trace=trace)

        if trace:
            trace.reply("RESPONSE: %s" % response)
            trace.reply("CONTENT: %s" % unicode(content, encoding="utf-8"))

    return response, content

def discover(principal):
    c = Consumer(None, None)
    return c.discover(principal)

def provider_config(issuer):
    c = Consumer(None, None)
    return c.provider_config(issuer)

def register(endpoint, info):
    c = Consumer(None, None)
    return c.register(endpoint, **info)

if __name__ == "__main__":
    import argparse
    import json
    import httplib2cookie

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-c', dest='client_config')
    parser.add_argument('-s', dest='server_conf')
    parser.add_argument('-p', dest="principal")
    parser.add_argument('-C', dest="ca_certs")
    parser.add_argument('-R', dest="register", action="store_true")
    parser.add_argument('-P', dest="provider_conf_url")
    parser.add_argument('-J', dest="json_config_file")
    parser.add_argument('-A', dest="function_args")
    parser.add_argument("-f", dest="flows", nargs="*")
    parser.add_argument("-l", dest="list", action="store_true")

    args = parser.parse_args()

    if args.list:
        lista = []
        for key,val in operations.FLOWS.items():
            item = {"id": key,
                    "name": val["name"],
                    "descr": "".join(val["descr"])}
            lista.append(item)
        print json.dumps(lista)
        exit()

    trace = Trace()

    if args.json_config_file:
        json_config = json.loads(open(args.json_config_file).read())
    else:
        json_config = None

    sconf = {}
    if args.server_conf:
        sconf = json.loads(args.server_conf)
    elif args.provider_conf_url:
        sconf = provider_config(args.provider_conf_url)
    elif json_config:
        if "provider_conf_url" in json_config:
            sconf = provider_config(json_config["provider_conf_url"]).dictionary()

    trace.info("SERVER CONFIGURATION: %s" % sconf)

    _htclass = httplib2cookie.CookiefulHttp
    if args.ca_certs:
        client = Client(ca_certs=args.ca_certs, httpclass=_htclass)
    else:
        try:
            client = Client(ca_certs=json_config["ca_certs"],
                            httpclass=_htclass)
        except (KeyError, TypeError):
            client = Client(disable_ssl_certificate_validation=True,
                            httpclass=_htclass)

    client.http_request = client.http.crequest

    # set the endpoints in the Client
    for key, val in sconf.items():
        if key.endswith("_endpoint"):
            setattr(client, key, val)

    # Client configuration
    if args.client_config:
        cconf = json.loads(args.client_config)
    elif "config" in json_config:
        cconf = json_config["config"]
    else:
        raise Exception("Missing client configuration")

    # set necessary information in the Client
    for prop in ["client_id", "redirect_uri", "password"]:
        try:
            setattr(client, prop, cconf[prop])
        except KeyError:
            pass

    # should I register the client ?
    if args.register or "register" in json_config:
        info = {}
        for prop in ["contact", "redirect_uri", "application_name",
                     "application_type"]:
            info[prop] = cconf[prop]
        resp = register(sconf["registration_endpoint"], info)
        for prop in ["client_id", "client_secret"]:
            try:
                setattr(client, prop, resp[prop])
            except KeyError:
                pass

        trace.info("REGISTRATION INFORMATION: %s" % resp.dictionary())

    #client.http = MyFakeOICServer()
    client.state = "STATE0"

    if args.flows:
        flows = [operations.FLOWS[flow] for flow in args.flows]
        sequences = []
        for flow in flows:
            _flow = [operations.PHASES[phase] for phase in flow["sequence"]]
            sequences.append((_flow, flow["endpoints"]))
    elif json_config and "flows" in json_config:
        flows = [operations.FLOWS[flow] for flow in json_config["flows"]]
        sequences = []
        for flow in flows:
            _flow = [operations.PHASES[phase] for phase in flow["sequence"]]
            sequences.append((_flow, flow["endpoints"]))
    else:
        sequences = []


    if args.function_args:
        function_args = args.function_args
    else:
        function_args = {}

    response = None
    content = None

    for sequence, endpoints in sequences:
        # clear cookie cache
        client.grant.clear()
        try:
            client.http.cookiejar.clear()
        except AttributeError:
            pass
        for opers, resp in sequence:
            err = None
            for oper in opers:
                if trace:
                    trace.info(70*"=")

                if "function" in oper:
                    try:
                        oper["args"] = function_args[oper["id"]]
                    except KeyError:
                        pass

                try:
                    response, content = do_operation(client, oper, response,
                                                     content, trace)
                #print content
                except Exception, err:
                    trace.error("%s: %s" % (err.__class__.__name__, err))
                    break

                while response.status == 302:
                    try:
                        url = response.url
                    except AttributeError:
                        url = response["location"]

                    # If back to me
                    for_me = False
                    for redirect_uri in client.redirect_uri:
                        if url.startswith(redirect_uri):
                            for_me=True

                    if for_me:
                        break
                    else:
                        if trace:
                            trace.info(70*"-")
                        response,content = do_request(client, url, "GET",
                                                      trace=trace)

                if response.status >= 400:
                    if response["content-type"] == "application/json":
                        err = ErrorResponse.set_json(content)
                        if trace:
                            trace.error("%s: %s" % (response.status,
                                                    err.get_json()))
                    else:
                        err = content
                    break

            if err is None:
                if resp["where"] == "url":
                    info = response["location"]
                else:
                    info = content

                respcls = getattr(message, resp["response"])
                qresp = client.parse_response(respcls, info,
                                              resp["type"],
                                              client.state, True)
                if trace and qresp:
                    trace.info("[%s]: %s" % (qresp.__class__.__name__,
                                             qresp.dictionary()))

            print trace
            trace.clear()
