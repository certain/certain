"""Webdav StoreHandler plugin."""

# .. should refer to 'certmgr'
from ..StoreHandler import StoreBase
from .. import config
import os
from urlparse import urlparse
from M2Crypto import httpslib


class store(StoreBase):

    def __init__(self):
        super(store, self).__init__()
        self.url = urlparse(config.get('store', 'StoreUrl'))

        if self.url.scheme == "https":
            self.web = httpslib.HTTPSConnection(self.url.netloc)
        else:
            self.web = httpslib.HTTPConnection(self.url.netloc)

    def setup(self):
        super(store, self).setup()

    def checkpoint(self):
        super(store, self).checkpoint()

    def fetch(self):
        super(store, self).fetch()

    def write(self, certobj):
        """Puts certificate on a webdav server."""

        certfile = os.path.join(
            self.url.path, certobj.get_subject().CN) + ".crt"
        log.debug("Writing cert: %s to server: %s", certfile, self.web)
        self.web.request('PUT', certfile, certobj.as_pem())
        resp = self.web.getresponse()
        if not 200 <= resp.status < 300:
            raise Exception(
                "Error writing to webdav server: %d" % resp.status)
        super(store, self).write()

    def __str__(self):
        return "StoreHandler." + __name__ + "()"
