PROJECT_ROOT:=.

SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXABUILD  = sphinx-autobuild
BUILDDIR      = doc/_build
DOCDIR        = doc/
OICDIR        = src/oic

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html       to make HTML documentation files"
	@echo "  livehtml   to make HTML documentation files (live reload!)"
	@echo "  install    to install the python dependencies for development"
	@echo "  isort      to sort imports"
.PHONY: help

clean:
	rm -rf $(INDEXDIR)
	rm -rf $(BUILDDIR)/*
.PHONY: clean

ALLSPHINXOPTS=-W
html:
	$(SPHINXBUILD) -b html $(DOCDIR) $(BUILDDIR)/html $(ALLSPHINXOPTS)
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."
.PHONY: html

livehtml:
	$(SPHINXABUILD) -b html $(DOCDIR) $(BUILDDIR)/html $(ALLSPHINXOPTS)
	@echo "Build finished. Watching for change ..."
.PHONY: livehtml

install:
	pip install -r requirements/test.txt -e .
.PHONY: install

isort:
	isort --recursive src/ tests/

check-isort:
	isort --recursive --diff --check-only src/ tests/
.PHONY: isort check-isort

check-pylama:
	pylama src/ tests/
.PHONY: check-pylama
