.. image:: https://api.travis-ci.org/OpenIDC/pyoidc.png?branch=master
    :target: https://travis-ci.org/OpenIDC/pyoidc

.. image:: https://ci.appveyor.com/api/projects/status/5g3ucux767mef3f4/branch/master?svg=true
    :target: https://ci.appveyor.com/project/tpazderka/pyoidc/branch/master

.. image:: https://img.shields.io/pypi/pyversions/oic.svg
    :target: https://pypi.python.org/pypi/oic

.. image:: https://img.shields.io/pypi/v/oic.svg
    :target: https://pypi.python.org/pypi/oic

.. image:: https://readthedocs.org/projects/pyoidc/badge/?version=latest
    :target: http://pyoidc.readthedocs.io/en/latest/?badge=latest

.. image:: https://codecov.io/gh/OpenIDC/pyoidc/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/OpenIDC/pyoidc

.. image:: https://api.codacy.com/project/badge/Grade/2038cfa7c56b480db6ae18b8320d7157
    :target: https://www.codacy.com/app/tpazderka/pyoidc?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=OpenIDC/pyoidc&amp;utm_campaign=Badge_Grade

A Python OpenID Connect implementation
======================================

This is a complete implementation of OpenID Connect as specified in the `OpenID
Connect Core specification`_. And as a side effect, a complete implementation
of OAuth2.0 too.

Please see the `CHANGELOG.md`_ to review the latest changes.

.. _OpenID Connect Core specification: http://openid.net/specs/openid-connect-core-1_0.html
.. _CHANGELOG.md: https://github.com/OpenIDC/pyoidc/blob/master/CHANGELOG.md

Documentation
==============

The `documentation`_ is graciously hosted by `Read the Docs`_. Unfortunately,
the documentation has been largely left unmaintained and `there are various
issues`_. However, the maintainers are trying to remedy this lately with some
new momentum. Please help us by submitting pull requests if you can help
improve the documentation.

.. _documentation: http://pyoidc.rtfd.io
.. _Read the Docs: https://readthedocs.org/
.. _there are various issues: https://github.com/OpenIDC/pyoidc/issues?q=is%3Aopen+is%3Aissue+label%3Adocumentation

Examples
========

Unfortunately, the current examples included in this repository are
unmaintained and `there are many issues`_. We're currently in the process of
creating a working canonical example implementation, however, until that time,
the current examples largely do not work. Please help us by submitting pull
requests that may bring these examples back into a working condition if you
get something working locally.

.. _there are many issues: https://github.com/OpenIDC/pyoidc/issues?q=is%3Aopen+is%3Aissue+label%3Aexamples

Acknowledgements
================

Cudos to Vladislav Mladenov and Christian Mainka both at
Horst Görtz Institute for IT-Security, Ruhr-University Bochum, Germany
for helping me making the implementation more secure.

Maintainers Needed
==================

If you're interested in helping maintain and improve this package, we're
looking for you! We're working on the project on a best effort basis but we
still maintain a good flow of reviewing each others pull requests and driving
discussions on what should be done. We also use a `mailing list`_ to have long
form discussions.

Please contact one of the current maintainers `@rohe`_, `@tpazderka`_ or `@schlenk`_.

.. _@rohe: https://github.com/rohe/
.. _@tpazderka: https://github.com/tpazderka/
.. _@schlenk: https://github.com/schlenk
.. _mailing list: https://lists.sunet.se/listinfo/pyoidc-dev

Contribute
==========

`Fork the repository`_, clone your copy and `install pipenv`_.

.. _Fork the repository: https://github.com/OpenIDC/pyoidc#fork-destination-box
.. _install pipenv: https://pipenv.readthedocs.io/en/latest/

Then just run:

.. code:: bash

    $ make install

Next, running the tests:

.. code:: bash

    $ make test

This will not affect your system level Python installation. Please review `our
issues`_ to see what needs working on. Do not hesitate to ask questions if
something is unclear. We mark easy issues as `newcomer-friendly`_, so they are
a good place to start if you want to contribute.

.. _our issues: https://github.com/OpenIDC/pyoidc/issues
.. _newcomer-friendly: https://github.com/OpenIDC/pyoidc/issues?q=is%3Aopen+is%3Aissue+label%3Anewcomer-friendly
