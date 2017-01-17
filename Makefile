SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXABUILD  = sphinx-autobuild
SPHINXAPIDOC  = sphinx-apidoc
BUILDDIR      = doc/_build
DOCDIR        = doc/
INDEXDIR      = doc/index
OICDIR        = src/oic

ifeq ($(shell which $(SPHINXBUILD) >/dev/null 2>&1; echo $$?), 1)
$(error The '$(SPHINXBUILD)' command was not found. Make sure you have Sphinx installed!)
endif

.PHONY: help clean html livehtml index

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  index      to make HTML code index files"
	@echo "  html       to make HTML documentation files"
	@echo "  livehtml   to make HTML documentation files (live reload!)"

clean:
	rm -rf $(INDEXDIR)
	rm -rf $(BUILDDIR)/*

index:
	$(SPHINXAPIDOC) -F -o $(INDEXDIR) $(OICDIR)
	@echo "Build finished. The Index pages are in $(INDEXDIR)."

ALLSPHINXOPTS=-W
html:
	$(SPHINXBUILD) -b html $(DOCDIR) $(BUILDDIR)/html $(ALLSPHINXOPTS)
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

livehtml:
	$(SPHINXABUILD) -b html $(DOCDIR) $(BUILDDIR)/html $(ALLSPHINXOPTS)
	@echo "Build finished. Watching for change ..."
