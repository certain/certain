"""Subversion StoreHandler plugin."""

# .. should refer to 'certmgr'
from ..StoreHandler import StoreBase
from .. import config
from .. import log
import pysvn
import threading
import os
import tempfile
from contextlib import nested


class store(StoreBase):

    def __init__(self):
        super(store, self).__init__()
        self.client = pysvn.Client()
        self.client.callback_ssl_server_trust_prompt = lambda trust_data: (
            True, 8, False) #8 = Cert not yet trusted - i.e auto-trust
        self.lock = threading.Lock()
        self.storedir = config.get('global', 'StoreDir')

    def setup(self):
        """Perform an svn checkout."""

        log.debug("Setting up svn repository (co)")
        with self.lock:
            self.client.checkout(config.get('store', 'StoreUrl'),
                                 self.storedir)
        super(store, self).setup()

    def checkpoint(self):
        """Perform an svn checkin."""

        log.debug("Doing checkin of store")
        with self.lock:
            self.client.checkin(self.storedir, "Adding certificates")
        super(store, self).checkpoint()

    def fetch(self):
        """Perform an svn update."""

        with self.lock:
            self.client.update(self.storedir)
        super(store, self).fetch()

    def write(self, certobj):
        """Write the certificate to the local svn working copy."""

        certfile = os.path.join(
            self.storedir, certobj.get_subject().CN) + ".crt"
        log.debug("Storing cert: %s", certfile)

        with nested(self.lock, tempfile.NamedTemporaryFile(
                dir=os.path.dirname(certfile),
                delete=False)) as (locked, f_crt):
            self.client.update(self.storedir)
            f_crt.write(certobj.as_pem())

        os.rename(f_crt.name, certfile)

        try:
            with self.lock:
                self.client.add(certfile)
        except pysvn.ClientError:
            log.exception("Failed to add %s to repository", certfile)
        super(store, self).write()

    def __str__(self):
        return "StoreHandler." + __name__ + "()"
