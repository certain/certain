#!/usr/bin/make -f

install:
	mkdir -p $(CURDIR)/debian/certmgr
	#mkdir -p $(CURDIR)/debian/certmgr/etc/certmgr
	#mkdir -p $(CURDIR)/debian/certmgr/usr/share/pyshared
	#mkdir -p $(CURDIR)/debian/certmgr/usr/bin
	dh_installdirs

	cp $(CURDIR)/cert.py $(CURDIR)/debian/tmp/usr/share/pyshared
	cp $(CURDIR)/certmgr.py $(CURDIR)/debian/tmp/usr/bin/certmgr
	cp $(CURDIR)/certmgr.cfg $(CURDIR)/debian/tmp/etc/certmgr

