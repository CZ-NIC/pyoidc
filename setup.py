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
from io import open

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


tests_requires = ['responses', 'testfixtures', 'pytest', 'freezegun']

with open('src/oic/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name="oic",
    version=version,
    description="Python implementation of OAuth2 and OpenID Connect",
    long_description=open('README.rst', encoding='utf-8').read(),
    author="Roland Hedberg",
    author_email="roland@catalogix.se",
    license="Apache 2.0",
    url='https://github.com/OpenIDC/pyoidc/',
    packages=[
        "oic", "oic/oauth2", "oic/oic", "oic/utils", "oic/utils/authn",
        "oic/utils/userinfo", 'oic/utils/rp', 'oic/extension'
    ],
    entry_points={
        'console_scripts': [
            'oic-client-management = oic.utils.client_management:run'
        ]
    },
    package_dir={"": "src"},
    package_data={"oic": ["py.typed"]},
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    python_requires='~=3.5',
    extras_require={
        'develop': ["cherrypy==3.2.4", "pyOpenSSL"],
        'testing': tests_requires,
        'docs': ['Sphinx', 'sphinx-autobuild', 'alabaster'],
        'quality': ['pylama', 'isort', 'eradicate', 'mypy', 'black', 'bandit', 'readme_renderer[md]'],
        'types': ['types-requests'],
        'ldap_authn': ['python-ldap'],
    },
    install_requires=[
        "requests",
        "pycryptodomex",
        "pyjwkest>=1.3.6",
        "mako",
        "beaker",
        "cryptography",
        "defusedxml",
        "typing_extensions",
    ],
    tests_require=tests_requires,
    long_description_content_type="text/x-rst",
    zip_safe=False,
    cmdclass={'test': PyTest},
)
