#!/usr/bin/env python3
import os

from oidctest.site_setup import oidc_op_setup

_distroot = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))

_root = 'test_site'

if os.path.isdir(_root) is False:
    os.makedirs(_root)

os.chdir(_root)

oidc_op_setup(_distroot)
