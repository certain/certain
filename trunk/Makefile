#!/usr/bin/make -f

prefix=src

install:
	groupadd --system --force certmgr
	getent passwd certmgr || useradd --system -c "Certmgr daemon" --gid certmgr --shell /bin/false certmgr

	install -d $(prefix)/usr/share/pyshared
	install -d $(prefix)/usr/bin
	install -d $(prefix)/etc/certmgr
	install -d -o certmgr -g certmgr -m 0700 $(prefix)/etc/certmgr/CA
	install -d -o certmgr -g certmgr -m 0700 $(prefix)/etc/certmgr/CA/private
	install -d -o certmgr -g certmgr -m 0700 $(prefix)/etc/certmgr/private
	install -d -o certmgr -g certmgr $(prefix)/etc/certmgr/CSRCache
	install -d -o certmgr -o certmgr $(prefix)/etc/certmgr/certs

	install cert.py $(prefix)/usr/share/pyshared
	install certmgr.py $(prefix)/usr/bin/certmgr
	install certmgr.cfg $(prefix)/etc/certmgr


