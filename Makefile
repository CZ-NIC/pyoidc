PROJECT_ROOT:=.

SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXABUILD  = sphinx-autobuild
BUILDDIR      = doc/_build
DOCDIR        = doc/
OICDIR        = src/oic
TESTDIR       = tests

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html       to make HTML documentation files"
	@echo "  livehtml   to make HTML documentation files (live reload!)"
	@echo "  install    to install the python dependencies for development"
	@echo "  test       to run the tests"
	@echo "  isort      to sort imports"
.PHONY: help

clean:
	rm -rf $(BUILDDIR)/*
.PHONY: clean

ALLSPHINXOPTS=-W
html:
	@pipenv run $(SPHINXBUILD) -b html $(DOCDIR) $(BUILDDIR)/html $(ALLSPHINXOPTS)
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."
.PHONY: html

livehtml:
	@pipenv run $(SPHINXABUILD) -b html $(DOCDIR) $(BUILDDIR)/html $(ALLSPHINXOPTS)
	@echo "Build finished. Watching for change ..."
.PHONY: livehtml

install:
	@pipenv install --dev -e .[develop,testing,docs,quality,ldap_authn]
.PHONY: install

test:
	@pipenv run pytest $(TESTDIR)
.PHONY: test

isort:
	@pipenv run isort --recursive $(OICDIR) $(TESTDIR)

check-isort:
	@pipenv run isort --recursive --diff --check-only $(OICDIR) $(TESTDIR)
.PHONY: isort check-isort

check-pylama:
	@pipenv run pylama $(OICDIR) $(TESTDIR)
.PHONY: check-pylama

release:
	@pipenv run python setup.py sdist upload -r pypi
.PHONY: release
