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
	@echo "  upgrade    to upgrade the python dependencies"
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

REQS_DIR=$(PROJECT_ROOT)/requirements
BASE_DEPS:=$(REQS_DIR)/base.txt
TEST_DEPS:=$(REQS_DIR)/test.txt
ADMIN_DEPS:=$(REQS_DIR)/admin.txt
DOC_DEPS:=$(REQS_DIR)/docs.txt
QUAL_DEPS:=$(REQS_DIR)/quality.txt
ALL_REQS:=$(BASE_DEPS) $(TEST_DEPS) $(ADMIN_DEPS) $(DOC_DEPS) $(QUAL_DEPS)
reqs: $(ALL_REQS)
upgrade:
	$(RM) $(ALL_REQS)
	$(MAKE) reqs PIP_COMPILE_ARGS=--rebuild
.PHONY: upgrade

$(REQS_DIR)/%.txt: PIP_COMPILE_ARGS?=
$(REQS_DIR)/%.txt: $(REQS_DIR)/%.in
	pip-compile --no-header $(PIP_COMPILE_ARGS) --output-file "$@.tmp" "$<" >/tmp/pip-compile.out.tmp || { \
	  ret=$$?; echo "pip-compile failed:" >&2; cat /tmp/pip-compile.out.tmp >&2; \
	  $(RM) "$@.tmp" /tmp/pip-compile.out.tmp; \
	  exit $$ret; }
	@sed -n '1,10 s/# Depends on/-r/; s/\.in/.txt/p' "$<" > "$@"
	@cat "$@.tmp" >> "$@"
	@$(RM) "$@.tmp" /tmp/pip-compile.out.tmp

isort:
	isort --recursive src/ tests/

check-isort:
	isort --recursive --diff --check-only src/ tests/
.PHONY: isort, check-isort
