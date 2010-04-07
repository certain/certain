"""Empty plugin."""

# .. should refer to 'certain'
from ..StoreHandler import StoreBase
from .. import config


class store(StoreBase):

    def setup(self):
        super(store, self).setup()

    def checkpoint(self):
        super(store, self).checkpoint()

    def fetch(self):
        super(store, self).fetch()

    def write(self, certobj):
        super(store, self).write(certobj)

    def __str__(self):
        return "StoreHandler." + __name__ + "()"
