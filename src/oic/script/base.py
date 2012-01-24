#!/usr/bin/env python

__author__ = 'rohe0002'

from importlib import import_module
from oic.oauth2.message import ErrorResponse

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

def flow2sequence(operations, item):
    flow = operations.FLOWS[item]
    return [operations.PHASES[phase] for phase in flow["sequence"]]

def endpoint(client, base):
    for _endp in client._endpoints:
        if getattr(client, _endp) == base:
            return True

    return False

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
def do_operation(client, opdef, message_mod, response=None, content=None,
                 trace=None, location=""):
    op = opdef
    qresp = None

    if "request" in op:
        if isinstance(op["request"], tuple):
            (mod, klass) = op["request"]
            imod = import_module(mod)
            cls = getattr(imod, klass)
        else:
            cls = getattr(message_mod, op["request"])

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

        if "authn_method" in kwargs:
            (r_arg, h_arg) = client.init_authentication_method(**kwargs)
            if r_arg:
                for key,val in r_arg.items():
                    setattr(cis, key, val)
        else:
            h_arg = None

        url, body, ht_args, cis = client.uri_and_body(cls, cis,
                                                      method=op["method"],
                                                      request_args=_req)

        if h_arg:
            ht_args.update(h_arg)
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
        except (KeyError, AttributeError):
            _args = {}

        _args["_trace_"] = trace
        _args["location"] = location

        if trace:
            trace.request("FUNCTION: %s" % func.__name__)
            trace.request("ARGS: %s" % _args)

        url, response, content = func(client, response, content, **_args)
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

    return url, response, content

def rec_update(dic0, dic1):
    res = {}
    for key, val in dic0.items():
        if key not in dic1:
            res[key] = val
        else:
            if isinstance(val, dict):
                res[key] = rec_update(val, dic1[key])
            else:
                res[key] = dic1[key]

    for key, val in dic1.items():
        if key in dic0:
            continue
        else:
            res[key] = val

    return res

def run_sequence(client, sequence, trace, interaction, message_mod, verbose,
                 tests=None):
    item = []
    response = None
    content = None
    err = None

    for req, resp in sequence:
        err = None
        if trace:
            trace.info(70*"=")
        try:
            extra_args = interaction[req["request"]]
            try:
                req["args"] = rec_update(req["args"], extra_args)
            except KeyError:
                req["args"] = extra_args
        except KeyError:
            pass

        try:
            url, response, content = do_operation(client, req,
                                                  message_mod,
                                                  response, content,
                                                  trace)
        except Exception, err:
            trace.error("%s: %s" % (err.__class__.__name__, err))
            break

        done = False
        while not done:
            while response.status in [302, 301, 303]:
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
                    done = True
                    break
                else:
                    if trace:
                        trace.info(70*".")
                    response, content = do_request(client, url, "GET",
                                                  trace=trace)
            if done or err:
                break

            if response.status >= 400:
                if response["content-type"] == "application/json":
                    err = ErrorResponse.set_json(content)
                    if trace:
                        trace.error("%s: %s" % (response.status,
                                                err.get_json()))
                else:
                    err = content
                break

            if trace:
                trace.info(70*"=")

            _base = url.split("?")[0]
            try:
                _spec = interaction[_base]
            except KeyError:
                if endpoint(client, _base):
                    break
                trace.error("No interaction bound to '%s'" % _base)
                raise

            _op = {"function": _spec[0], "args": _spec[1]}

            try:
                url, response, content = do_operation(client, _op,
                                                      message_mod,
                                                      response, content,
                                                      trace, location=url)
                #print content
            except Exception, err:
                trace.error("%s: %s" % (err.__class__.__name__, err))
                raise


        if err is None:
            if resp["where"] == "url":
                try:
                    info = response["location"]
                except KeyError:
                    trace.error("Not a final redirect")
                    raise Exception
            else:
                info = content

            if info:
                if isinstance(resp["response"], tuple):
                    (mod, klass) = resp["response"]
                    imod = import_module(mod)
                    respcls = getattr(imod, klass)
                else:
                    respcls = getattr(message_mod, resp["response"])

                try:
                    qresp = client.parse_response(respcls, info,
                                                  resp["type"],
                                                  client.state, True,
                                                  key=client.client_secret,
                                                  client_id=client.client_id)
                    if trace and qresp:
                        trace.info("[%s]: %s" % (qresp.__class__.__name__,
                                                 qresp.dictionary()))
                    item.append(qresp)
                except Exception, err:
                    trace.error("info: %s" % info)
                    trace.error("%s" % err)
                    raise

        if err:
            break

    if err or verbose:
        print trace

    if not err and tests:
        for test in tests:
            assert test(client, item)

    return err


def run_sequences(client, sequences, trace, interaction, message_mod,
                  verbose=False):
    for sequence, endpoints, fid in sequences:
        # clear cookie cache
        client.grant.clear()
        try:
            client.http.cookiejar.clear()
        except AttributeError:
            pass

        err = run_sequence(client, sequence, trace, interaction, message_mod,
                           verbose)

        if err:
            print "%s - FAIL" % fid
            print
            if not verbose:
                print trace
        else:
            print "%s - OK" % fid

        trace.clear()
