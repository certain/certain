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
<<<<<<< HEAD
	mkdir -p setup/deb/
	$(CURDIR)/setup.py sdist $(COMPILE) --dist-dir=setup/deb/
=======
	$(CURDIR)/setup.py sdist $(COMPILE) --dist-dir=../
>>>>>>> 5a332f55cf495bd3d303082aed6726ed074d9595
	rename -f 's/$(PROJECT)-(.*)\.tar\.gz/$(PROJECT)_$$1\.orig\.tar\.gz/' ../*
	dpkg-buildpackage -tc -i -I -rfakeroot

clean:
<<<<<<< HEAD
	$(CURDIR)/setup.py clean
	$(MAKE) -f $(CURDIR)/debian/rules clean
	rm -rf setup/
=======
	$(CURDIR)/setup.py clean --root $(DESTDIR)
	$(MAKE) -f $(CURDIR)/debian/rules clean
>>>>>>> 5a332f55cf495bd3d303082aed6726ed074d9595
	find . -name '*.py[oc]' -delete
