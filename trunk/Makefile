#!/usr/bin/make -f

prefix=src

install:
	install -d $(prefix)/usr/share/pyshared/certmgr/StoreHandler
	install -d $(prefix)/usr/bin
	install -d $(prefix)/etc/certmgr

	install -m 0644 certmgr/__init__.py $(prefix)/usr/share/pyshared/certmgr
	install -m 0644 certmgr/StoreHandler/*.py $(prefix)/usr/share/pyshared/certmgr/StoreHandler
	install bin/certmgr $(prefix)/usr/bin/
	install -m 0644 certmgr.cfg.example $(prefix)/etc/certmgr/
