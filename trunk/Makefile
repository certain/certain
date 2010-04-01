#!/usr/bin/make -f

prefix=src

install:
	install -d $(prefix)/usr/share/pyshared/
	install -d $(prefix)/usr/bin
	install -d $(prefix)/etc/certmgr
	install -d -m 0700 $(prefix)/etc/certmgr/CA
	install -d -m 0700 $(prefix)/etc/certmgr/CA/private
	install -d -m 0700 $(prefix)/etc/certmgr/private
	install -d $(prefix)/etc/certmgr/CSRCache
	install -d $(prefix)/etc/certmgr/certs

	install certmgr.py $(prefix)/usr/share/pyshared/
	install certmgr $(prefix)/usr/bin/
	install certmgr.cfg.example $(prefix)/etc/certmgr/


