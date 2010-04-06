#!/usr/bin/make -f

PYTHON=`which python`
DESTDIR=/
PROJECT=certain
BUILDDIR=$(CURDIR)/build/$(PROJECT)

all:
	@echo "make source - Create source package"
	@echo "make install - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean - Get rid of scratch and byte files"

source:
	$(PYTHON) setup.py sdist $(COMPILE)


install:
	$(PYTHON) setup.py install --root $(DESTDIR) $(COMPILE) 

buildrpm:
	$(PYTHON) setup.py bdist_rpm --post-install=rpm/postinstall --re-uninstall=rpm/preuninstall

builddeb:
	$(PYTHON) setup.py sdist $(COMPILE) --dist-dir=../
	rename -f 's/$(PROJECT)-(.*)\.tar\.gz/$(PROJECT)_$$1\.orig\.tar\.gz/' ../*
	dpkg-buildpackage -i -I -rfakeroot

clean:
	$(PYTHON) setup.py clean
	$(MAKE) -f $(CURDIR)/debian/rules clean
	rm -rf build/ MANIFEST
	find . -name '*.pyc' -delete

