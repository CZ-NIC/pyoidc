#!/usr/bin/env python
__author__ = 'rohe0002'

from oic.script import oic_operations as operations

from oic.oic import Client
from oic.oic import message
from oic.oic.consumer import Consumer

from oic.script import httplib2cookie
from oic.script.base import *

QUERY2RESPONSE = {
    "AuthorizationRequest": "AuthorizationResponse",
    "AccessTokenRequest": "AccessTokenResponse",
    "UserInfoRequest": "OpenIDSchema",
    "RegistrationRequest": "RegistrationResponse"
}

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

    run_sequences(client, sequences, trace, function_args, message)
