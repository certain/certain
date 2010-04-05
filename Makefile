#!/usr/bin/make -f

prefix=src

install:
	install -d $(prefix)/usr/share/pyshared/certmgr/StoreHandler
	install -d $(prefix)/usr/share/pyshared/certmgr/ExpiryHandler
	install -d $(prefix)/usr/share/pyshared/certmgr/StoreServer
	install -d $(prefix)/usr/bin
	install -d $(prefix)/etc/certmgr

	install -m 0644 certmgr/*.py $(prefix)/usr/share/pyshared/certmgr
	install -m 0644 certmgr/StoreHandler/*.py $(prefix)/usr/share/pyshared/certmgr/StoreHandler
	install -m 0644 certmgr/ExpiryHandler/*.py $(prefix)/usr/share/pyshared/certmgr/ExpiryHandler
	install -m 0644 certmgr/StoreServer/*.py $(prefix)/usr/share/pyshared/certmgr/StoreServer
	install bin/certmgr $(prefix)/usr/bin/
	install bin/storeserver $(prefix)/usr/bin/
	install -m 0644 certmgr.cfg.example $(prefix)/etc/certmgr/
