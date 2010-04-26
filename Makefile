#!/usr/bin/make -f

DESTDIR=/
PROJECT=certain

all:
	@echo "make source - Create source package"
	@echo "make install - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean - Get rid of scratch and byte files"

source:
	$(CURDIR)/setup.py sdist

install:
	$(CURDIR)/setup.py install --prefix=/usr --root $(DESTDIR)

release:
ifndef REL
	@echo "Need to specify a release tag: 'make release REL=x.y.z'"
	@exit 2
endif
	git-dch  --debian-tag='%(version)s' --new-version=$(REL) --release
	git commit debian/changelog -m "Release: $(REL)"
	git tag -a $(REL) -m "Tagged for release: $(REL)"

builddeb:
	mkdir -p setup/deb/
	git-buildpackage --git-postbuild='make clean'

buildrpm:
	$(CURDIR)/setup.py bdist_rpm --post-install=rpm/postinstall --re-uninstall=rpm/preuninstall



clean:
	$(CURDIR)/setup.py clean
	rm -rf build/
	rm -rf debian/certain*
	rm -rf debian/files
	rm -rf debian/python-module-stampdir/
	$(MAKE) -f $(CURDIR)/debian/rules clean
	find . -name '*.py[oc]' -delete
