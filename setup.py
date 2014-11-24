#!/usr/bin/python
#
# Copyright (C) 2013 Umea Universitet, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from setuptools import setup
from setuptools.command.test import test as TestCommand
import sys

__author__ = 'rohe0002'


class PyTest(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

setup(
    name="oic",
    version="0.6.gamma",
    description="Python implementation of OAuth2 and OpenID Connect",
    author = "Roland Hedberg",
    author_email = "roland.hedberg@adm.umu.se",
    license="Apache 2.0",
    url='https://github.com/rohe/pyoidc',
    packages=["oic", "oic/oauth2", "oic/oic", "oic/utils", "oic/utils/authn",
              "oic/utils/userinfo"],
    package_dir = {"": "src"},
    classifiers = ["Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires = ['requests', "pycrypto>=2.6.1", "cherrypy==3.2.4",
                        "mako", "pyjwkest>=5.1.0", "beaker", "alabaster",
                        "importlib", "argparse", "pyOpenSSL"],
    tests_require=['pytest'],
    zip_safe=False,
    cmdclass={'test': PyTest},
)