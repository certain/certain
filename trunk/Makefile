#!/usr/bin/make -f

prefix=/

install:
	mkdir -p $(prefix)/usr/share/pyshared
	mkdir -p $(prefix)/usr/bin
	mkdir -p $(prefix)/etc/certmgr
	cp cert.py $(prefix)/usr/share/pyshared
	cp certmgr.py $(prefix)/usr/bin/certmgr
	cp certmgr.cfg $(prefix)/etc/certmgr

