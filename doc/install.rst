.. _install:

Quick install guide
===================

Before you can use PyOIDC, you'll need to get it installed. This guide
will guide you to a simple, minimal installation.

Install PyOIDC
--------------

For all this to work you need to have Python installed.
The development has been done using 2.7.
There will shortly be a 3.4 version.

Prerequisites
^^^^^^^^^^^^^

For installing pyOIDC you will need

* requests
* pycrypto
* pyjwkest

To build the documentation you will need

* alabaster

and for running the examples:

* mako
* cherrypy
* beaker

Quick build instructions
^^^^^^^^^^^^^^^^^^^^^^^^

Once you have installed all the necessary prerequisites a simple::

    python setup.py install

will install the basic code.

Note for rhel/centos 6: cffi depends on libffi-devel, and cryptography on
openssl-devel to compile. So you might want first to do:
yum install libffi-devel openssl-devel

After this you ought to be able to run the tests without an hitch.
The tests are based on the pypy test environment, so::

    cd tests
    py.test

is what you should use. If you don't have py.test, get it it's part of pypy!
It's really good!

