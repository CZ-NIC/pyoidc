#!/usr/bin/env python3

import cherrypy
import importlib
import logging
import os
import sys

import cherrypy_cors

from oic.oic.provider import Provider
from oic.utils import webfinger

logger = logging.getLogger("")
LOGFILE_NAME = 'op.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(
        '-c', dest='capabilities',
        help="A file containing a JSON representation of the capabilities")
    parser.add_argument('-i', dest='issuer', help="issuer id of the OP",
                        nargs=1)
    parser.add_argument(dest="config")
    args = parser.parse_args()

    folder = os.path.abspath(os.curdir)

    cherrypy.config.update(
        {'environment': 'production',
         'log.error_file': 'site.log',
         'log.screen': True,
         'server.socket_host': '0.0.0.0',
         'server.socket_port': args.port,
         'tools.encode.on': True,
         'tools.encode.encoding': 'utf-8',
         'tools.sessions.on': True,
         'tools.trailing_slash.on': False
         })

    provider_config = {
        '/': {
            'root_path': 'localhost',
            'log.screen': True,
            'log.error_file': 'site.log',
            'tools.staticdir.root': folder
        },
        '/static': {
            'tools.staticdir.dir': 'static',
            'tools.staticdir.debug': True,
            'tools.staticdir.on': True,
            'log.screen': True,
            'cors.expose_public.on': True
        }}

    cherrypy_cors.install()

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    cpop = importlib.import_module('cpop')
    setup = importlib.import_module('setup')

    # OIDC Provider
    _op = setup.op_setup(args, config, Provider)

    # WebFinger
    webfinger_config = {
        '/': {'base_url': _op.baseurl}}
    cherrypy.tree.mount(cpop.WebFinger(webfinger.WebFinger()),
                        '/.well-known/webfinger', webfinger_config)

    cherrypy.tree.mount(cpop.Provider(_op, ['static']), '/', provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = config.SERVER_CERT
        cherrypy.server.ssl_private_key = config.SERVER_KEY
        if config.CA_BUNDLE:
            cherrypy.server.ssl_certificate_chain = config.CA_BUNDLE

    cherrypy.engine.start()
    cherrypy.engine.block()
