#!/usr/bin/env python
#
# Copyright (C) 2013 Umea Universitet, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

__author__ = 'rohe0002'


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest

        errno = pytest.main(self.test_args)
        sys.exit(errno)

tests_requires = ['responses', 'testfixtures', 'pytest', 'mock', 'freezegun']

# Python 2.7 and later ship with importlib and argparse
if sys.version_info[0] == 2 and sys.version_info[1] == 6:
    extra_install_requires = ["importlib", "argparse"]
else:
    extra_install_requires = []

version = ''
with open('src/oic/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name="oic",
    version=version,
    description="Python implementation of OAuth2 and OpenID Connect",
    author="Roland Hedberg",
    author_email="roland@catalogix.se",
    license="Apache 2.0",
    url='https://github.com/OpenIDC/pyoidc/',
    packages=[
        "oic", "oic/oauth2", "oic/oic", "oic/utils", "oic/utils/authn",
        "oic/utils/userinfo", 'oic/utils/rp', 'oic/extension'
    ],
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    extras_require={
        'develop': ["cherrypy==3.2.4"],
        'testing': tests_requires,
        'docs': ['Sphinx', 'sphinx-autobuild'],
        'quality': ['pylama', 'isort'],
        'ldap_authn': ['pyldap'],
    },
    install_requires=[
        "requests",
        "pycryptodomex",
        "pyjwkest>=1.3.6",
        "mako",
        "beaker",
        "alabaster",
        "pyOpenSSL",
        "future",
        "six",
    ] + extra_install_requires,
    tests_require=tests_requires,
    zip_safe=False,
    cmdclass={'test': PyTest},
)
