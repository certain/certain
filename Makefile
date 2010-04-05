#!/usr/bin/make -f

prefix=src

install:
	install -d $(prefix)/usr/share/pyshared/certain/StoreHandler
	install -d $(prefix)/usr/share/pyshared/certain/ExpiryHandler
	install -d $(prefix)/usr/share/pyshared/certain/StoreServer
	install -d $(prefix)/usr/bin
	install -d $(prefix)/etc/certain

	install -m 0644 certain/*.py $(prefix)/usr/share/pyshared/certain
	install -m 0644 certain/StoreHandler/*.py $(prefix)/usr/share/pyshared/certain/StoreHandler
	install -m 0644 certain/ExpiryHandler/*.py $(prefix)/usr/share/pyshared/certain/ExpiryHandler
	install -m 0644 certain/StoreServer/*.py $(prefix)/usr/share/pyshared/certain/StoreServer
	install bin/certain $(prefix)/usr/bin/
	install bin/storeserver $(prefix)/usr/bin/
	install -m 0644 certain.cfg.example $(prefix)/etc/certain/
