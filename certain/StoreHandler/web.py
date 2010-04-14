"""Web StoreHandler plugin."""

# .. should refer to 'certain'
from ..StoreHandler import StoreBase
from .. import config
from .. import log
from M2Crypto import httpslib
from HTMLParser import HTMLParser
from urlparse import urlparse
import os
import urllib2
import tempfile
import errno
import time


class store(StoreBase):

    class _AnchorParser(HTMLParser):

        def __init__(self):
            HTMLParser.__init__(self)
            self.items = []

        def handle_starttag(self, tag, attrs):
            if tag == 'a':
                for key, value in attrs:
                    if key == 'href' and value.endswith('.crt'):
                        self.items.append(value)

        def get_items(self):
            return self.items

    def __init__(self):
        super(store, self).__init__()
        self.storedir = config.get('global', 'StoreDir')
        self.webdir = config.get('webserver', 'WebDir')
        self.lastcheckfile = os.path.join(self.storedir, "lastcheck.txt")
        self.lastcheck = 0
        self.url = urlparse(config.get('store', 'StoreUrl'))
        if self.url.scheme == "https":
            self.web = httpslib.HTTPSConnection(self.url.netloc)
        else:
            self.web = httpslib.HTTPConnection(self.url.netloc)

    def setup(self):
        try:
            with open(self.lastcheckfile) as f:
                #Readline should ensure no accidental trailing newlines
                self.lastcheck = f.readline()
            self.lastcheck = float(self.lastcheck)
        except (IOError, ValueError, TypeError):
            #If we got an exception, lastcheck may be unset or not a float
            #Set it to 0 (epoch) to force a cert update
            self.lastcheck = 0
        try:
            os.mkdir(self.storedir)
            os.mkdir(self.webdir)
        except OSError, e:
            if e.errno != errno.EEXIST:
                raise
        super(store, self).setup()

    def checkpoint(self):
        super(store, self).checkpoint()

    def fetch(self):
        """Fetch certificates from a webserver."""
        parser = self._AnchorParser()
        self.web.request('GET', self.url.path)
        reply = self.web.getresponse()
        now = time.mktime(time.strptime(
            reply.getheader("Date"),
            "%a, %d %b %Y %H:%M:%S %Z"))
        parser.feed(reply.read())
        files = parser.get_items()

        for certfile in files:
            self.web.request('GET', self.url.path + certfile)
            resp = self.web.getresponse()
            lastmod = time.mktime(time.strptime(
                resp.getheader("Last-Modified"),
                "%a, %d %b %Y %H:%M:%S %Z"))

            if lastmod > self.lastcheck:
                log.debug("Fetching cert %s to %s",
                          certfile, self.storedir)
                with tempfile.NamedTemporaryFile(
                    dir=self.storedir,
                    delete=False) as f_crt:
                    f_crt.write(resp.read())
                    os.rename(f_crt.name,
                              os.path.join(self.storedir,
                                           urllib2.unquote(certfile)))

        try:
            with tempfile.NamedTemporaryFile(
                dir=self.storedir,
                delete=False) as f:
                f.write(str(now))

            os.rename(f.name, self.lastcheckfile)
            self.lastcheck = now
        except Exception:
            #Don't care if the lastcheck write fails
            pass
        super(store, self).fetch()

    def write(self, certobj):
        """Write certificate to a web-served path."""

        with tempfile.NamedTemporaryFile(
            dir=self.webdir,
            delete=False) as f_crt:
            log.debug("Writing cert: %s to %s",
                     certobj.get_subject().CN, self.webdir)
            f_crt.write(certobj.as_pem())

        certfile = os.path.join(
            self.webdir, certobj.get_subject().CN) + ".crt"
        os.rename(f_crt.name, certfile)

        super(store, self).write(certobj)

    def remove(self, CN):
        os.unlink(os.path.join(self.webdir, CN + ".crt"))
        super(store, self).remove(certobj)

    def __str__(self):
        return "StoreHandler." + __name__ + "()"
