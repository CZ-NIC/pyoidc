#!/usr/bin/env python
__author__ = 'rohe0002'

import sys
import argparse
import json

from oic.script import httplib2cookie
from oic.script.base import *

QUERY2RESPONSE = {
    "AuthorizationRequest": "AuthorizationResponse",
    "AccessTokenRequest": "AccessTokenResponse",
    "UserInfoRequest": "OpenIDSchema",
    "RegistrationRequest": "RegistrationResponse"
}

class OAuth2(object):
    client_args = ["client_id", "redirect_uri", "password"]
    def __init__(self, operations_mod, message_mod, client_class):
        self.operations_mod = operations_mod
        self.message_mod = message_mod
        self.client_class = client_class
        self.client = None
        self.trace = Trace()

        self._parser = argparse.ArgumentParser()
        self._parser.add_argument('-v', dest='verbose', action='store_true')
        self._parser.add_argument('-d', dest='debug', action='store_true')
        self._parser.add_argument('-C', dest="ca_certs")
        self._parser.add_argument('-J', dest="json_config_file")
        self._parser.add_argument('-I', dest="interactions")
        self._parser.add_argument("-l", dest="list", action="store_true")
        self._parser.add_argument("flow")

        self.args = None
        self.pinfo = None
        self.sequences = []
        self.function_args = {}

    def parse_args(self):
        self.json_config= self.json_config_file()

        self.pinfo = self.provider_info()
        self.client_conf(self.client_args)

    def json_config_file(self):
        if self.args.json_config_file == "-":
            return json.loads(sys.stdin.read())
        else:
            return json.loads(open(self.args.json_config_file).read())

    def run(self):
        self.args = self._parser.parse_args()

        self.args.flow = self.args.flow.strip("'")
        self.args.flow = self.args.flow.strip('"')
        if self.args.list:
            return self.operations()
        else:
            self.parse_args()
            if self.args.verbose:
                print "SERVER CONFIGURATION: %s" % self.pinfo
            #client.http = MyFakeOICServer()
            _seq = self.make_sequence()
            interact = self.get_interactions()

            self.client.state = "STATE0"

            try:
                run_sequence(self.client, _seq, self.trace, interact,
                             self.message_mod, self.args.verbose)
            except Exception:
                print self.trace

    def operations(self):
        lista = []
        for key,val in self.operations_mod.FLOWS.items():
            item = {"id": key,
                    "name": val["name"],
                    "descr": "".join(val["descr"])}
            lista.append(item)

        return json.dumps(lista)

    def provider_info(self):
        # Should provide a Metadata class
        res = {}
        _jc = self.json_config["provider"]
        for key in ["version", "issuer", "endpoints", "scopes_supported",
                    "schema", "user_id_types_supported",
                    "userinfo_algs_supported",
                    "id_token_algs_supported",
                    "request_object_algs_supported",
                    "provider_trust"]:
            if key == "endpoints":
                try:
                    for endp, url in _jc[key].items():
                        res[endp] = url
                except KeyError:
                    pass
            else:
                try:
                    res[key] = _jc[key]
                except KeyError:
                    pass

        return res

    def client_conf(self, cprop):
        _htclass = httplib2cookie.CookiefulHttp
        if self.args.ca_certs:
            self.client = self.client_class(ca_certs=self.args.ca_certs,
                                       httpclass=_htclass)
        else:
            try:
                self.client = self.client_class(
                                        ca_certs=self.json_config["ca_certs"],
                                        httpclass=_htclass)
            except (KeyError, TypeError):
                self.client = self.client_class(
                                        disable_ssl_certificate_validation=True,
                                        httpclass=_htclass)

        self.client.http_request = self.client.http.crequest

        # set the endpoints in the Client from the provider information
        for key, val in self.pinfo.items():
            if key.endswith("_endpoint"):
                setattr(self.client, key, val)

        # Client configuration
        self.cconf = self.json_config["client"]

        # set necessary information in the Client
        for prop in cprop:
            try:
                setattr(self.client, prop, self.cconf[prop])
            except KeyError:
                pass

    def make_sequence(self):
        if self.json_config and "flow" in self.json_config:
            sequence = flow2sequence(self.operations_mod,
                                            self.json_config["flow"])
        elif self.args.flow:
            sequence = flow2sequence(self.operations_mod, self.args.flow)
        else:
            sequence = None

        return sequence

    def get_interactions(self):
        interactions = {}

        if self.args.interactions:
            interactions = json.loads(self.args.interactions)
        elif self.json_config:
            try:
                interactions = self.json_config["interaction"]
            except KeyError:
                pass

        for url, spec in interactions.items():
            try:
                func_name, args = spec
                func = getattr(self.operations_mod, func_name)
                interactions[url] = (func, args)
            except ValueError:
                interactions[url] = spec

        return interactions

class OIC(OAuth2):
    client_args = ["client_id", "redirect_uri", "password", "client_secret"]

    def __init__(self, operations_mod, message_mod, client_class,
                 consumer_class):
        OAuth2.__init__(self, operations_mod, message_mod, client_class)

        self._parser.add_argument('-P', dest="provider_conf_url")
        self._parser.add_argument('-p', dest="principal")
        self._parser.add_argument('-R', dest="register", action="store_true")

        self.consumer_class = consumer_class

    def parse_args(self):
        OAuth2.parse_args(self)
        self.register()

    def discover(self, principal):
        c = self.consumer_class(None, None)
        return c.discover(principal)

    def provider_config(self, issuer):
        c = self.consumer_class(None, None)
        return c.provider_config(issuer)

    def _register(self, endpoint, info):
        c = self.consumer_class(None, None)
        return c.register(endpoint, **info)

    def provider_info(self):
        if "conf_url" in self.json_config["provider"]:
            _url = self.json_config["provider"]["conf_url"]
            return self.provider_config(_url).dictionary()
        else:
            return OAuth2.provider_info(self)

    def register(self):
        # should I register the client ?
        if self.args.register or "register" in self.json_config["client"]:
            info = {}
            for prop in self.message_mod.RegistrationRequest.c_attributes.keys():
                try:
                    info[prop] = self.cconf[prop]
                except KeyError:
                    pass

            self.reg_resp = self._register(self.pinfo["registration_endpoint"],
                                      info)

            for prop in ["client_id", "client_secret"]:
                try:
                    setattr(self.client, prop, self.reg_resp[prop])
                except KeyError:
                    pass

            if self.args.verbose:
                print "REGISTRATION INFORMATION: %s" % self.reg_resp


if __name__ == "__main__":
    from oic.script import OAuth2
    from oic.script import oauth2_operations
    from oic.oauth2 import Client
    from oic.oauth2 import message

    cli = OAuth2(oauth2_operations, message, Client)

    cli.run()