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

    def __enter__(self):
        self.setup()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.checkpoint()


def storeerror(name):
    """Error method. Default for getattr to deal with unknown StoreType."""

    print "Unknown StoreType: " + name


def dispatch(name, errorfunc=storeerror):
    """Dispatch a store object to handle this type of Store.

    Returns an object of the appropriate type, or None. Also logs a message
    if the store type could not be found.

    """

    try:
        return __import__('certmgr.StoreHandler.' + name,
            fromlist=name).store()
    except (ImportError, AttributeError), e:
        raise
        return storeerror(name)
