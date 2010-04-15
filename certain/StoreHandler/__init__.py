"""Module to handle different store types."""

__all__ = ['git', 'svn', 'web']

import abc


class StoreBase(object):
    """Abstract base class for StoreHandler 'plugins'."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def setup(self):
        """Setup this specific store object."""
        return

    @abc.abstractmethod
    def fetch(self):
        """Retrieve certificates from the store."""
        return

    @abc.abstractmethod
    def write(self, certobj):
        """Write certificate to the central store."""
        return

    @abc.abstractmethod
    def checkpoint(self):
        """Checkpoint any pending actions on the store."""
        return

    @abc.abstractmethod
    def remove(self, CN):
        """Remove a certificate from the store by Common Name."""
        return

    def __enter__(self):
        self.setup()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.checkpoint()


def storeerror(name):
    """Error method. Default for getattr to deal with unknown StoreType."""

    # This cannot be imported at initialisation, as this module is loaded
    # before the log object has been created.
    from .. import log
    log.error('Unknown StoreType: "%s"' % (name, ))


def dispatch(name):
    """Dispatch a store object to handle this type of Store.

    Returns an object of the appropriate type, or None. Also logs a message
    if the store type could not be found.

    """

    try:
        store = __import__(__name__ + '.' + name,
            fromlist=name).store
    except (ImportError, AttributeError):
        return storeerror(name)
    return store()
