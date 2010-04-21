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

buildrpm:
	$(CURDIR)/setup.py bdist_rpm --post-install=rpm/postinstall --re-uninstall=rpm/preuninstall

builddeb:
	mkdir -p setup/deb/
	git-dch -a --new-version=`git describe` --release
	git-buildpackage --git-ignore-new
	#$(CURDIR)/setup.py sdist $(COMPILE) --dist-dir=setup/deb/
	#rename -f 's/$(PROJECT)-(.*)\.tar\.gz/$(PROJECT)_$$1\.orig\.tar\.gz/' ../*
	#dpkg-buildpackage -tc -i -I -rfakeroot

clean:
	$(CURDIR)/setup.py clean
	rm -rf build/
	rm -rf debian/certain*
	rm -rf debian/files
	rm -rf debian/python-module-stampdir/
	$(MAKE) -f $(CURDIR)/debian/rules clean
	find . -name '*.py[oc]' -delete
