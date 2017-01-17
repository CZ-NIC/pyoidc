.. _install:

Development Install
###################

Firstly, fork_ the project and get a local copy with:

::

  $ git clone git@github.com:<your-username>/pyoidc.git

.. _fork: https://github.com/rohe/pyoidc/issues#fork-destination-box

PyOIDC supports Python 2 and 3.

Installation via a `virtual environment`_ is **highly** recommended.

.. _virtual environment: http://docs.python-guide.org/en/latest/dev/virtualenvs/

Install dependencies via:

::

  $ python setup.py install

Installation via Pip_ is also possible:

.. _Pip: pip.pypa.io/en/stable/installing/

::

  $ pip install -U -e . -r requirements.txt

.. Note:: The depdencies will require you compile your Python source code
          with byte-compiling. This means avoiding the ``-B`` option or
          not setting ``PYTHONDONTWRITEBYTECODE``.
