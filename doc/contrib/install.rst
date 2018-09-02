.. _install:

Development Install
###################

Firstly, fork_ the project and get a local copy with:

::

  $ git clone git@github.com:<your-username>/pyoidc.git

.. _fork: https://github.com/OpenIDC/pyoidc/issues#fork-destination-box

PyOIDC supports Python 2 and 3.

Installation via a `virtual environment`_ is **highly** recommended.

.. _virtual environment: http://docs.python-guide.org/en/latest/dev/virtualenvs/

Install dependencies (using Pip_) via:

.. _Pip: pip.pypa.io/en/stable/installing/

::

  $ make install

.. Note:: The dependencies will require that you compile your Python source code
          with byte-compiling. This means avoiding the ``-B`` option and
          not setting ``PYTHONDONTWRITEBYTECODE``.
