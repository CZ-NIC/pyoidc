#!/usr/bin/env python

__author__ = 'rohe0002'

from oic.script import oauth2_operations as operations

from oic.oauth2 import Client
from oic.oauth2 import message

from oic.script import httplib2cookie
from oic.script.base import *

import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='verbose', action='store_true')
parser.add_argument('-d', dest='debug', action='store_true')
parser.add_argument('-c', dest='client_config')
parser.add_argument('-s', dest='server_conf')
parser.add_argument('-p', dest="principal")
parser.add_argument('-C', dest="ca_certs")
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
elif json_config:
    if "server_conf" in json_config:
        sconf = json_config["server_conf"]

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
for prop in ["client_id", "redirect_uri", "password", "client_secret"]:
    try:
        setattr(client, prop, cconf[prop])
    except KeyError:
        pass

#client.http = MyFakeOICServer()
client.state = "STATE0"

if json_config and "flows" in json_config:
    flows = [operations.FLOWS[flow] for flow in json_config["flows"]]
    sequences = []
    for flow in flows:
        _flow = [operations.PHASES[phase] for phase in flow["sequence"]]
        sequences.append((_flow, flow["endpoints"]))
elif args.flows:
    flows = [operations.FLOWS[flow] for flow in args.flows]
    sequences = []
    for flow in flows:
        _flow = [operations.PHASES[phase] for phase in flow["sequence"]]
        sequences.append((_flow, flow["endpoints"]))
else:
    sequences = []


if args.function_args:
    function_args = args.function_args
elif json_config:
    try:
        function_args = json_config["function_args"]
    except KeyError:
        function_args = {}
else:
    function_args = {}

run_sequences(client, sequences, trace, function_args, message)
