"""Git StoreHandler plugin."""

# .. should refer to 'certain'
from ..StoreHandler import StoreBase
from .. import config
import dulwich
import threading
import os
import stat
import errno
from functools import wraps


def synchronised(lock):
    """Synchronisation decorator."""

    def wrap(func):
        @wraps(func)
        def newFunction(*args, **kw):
            with lock:
                return func(*args, **kw)
        return newFunction
    return wrap


class store(StoreBase):

    lock = threading.RLock()

    def __init__(self):
        super(store, self).__init__()
        # Dulwich stores the path literally, so if it is relative, the
        # code is no longer thread safe. abspath works around this.
        path = os.path.abspath(config.get('global', 'StoreDir'))
        try:
            self.repo = dulwich.repo.Repo(path)
        except dulwich.errors.NotGitRepository:
            try:
                os.makedirs(path)
            except OSError, e:
                if e.errno != errno.EEXIST:
                    raise
            self.repo = dulwich.repo.Repo.init(path)
            self.repo.refs['HEAD'] = 'ref: refs/heads/master'
        # Work around dulwich 0.50 bug.
        def try_again(func):
            @wraps(func)
            def new_add_object(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except OSError, e:
                    if e.errno != errno.EEXIST:
                        raise
                    return func(*args, **kwargs)
            return new_add_object
        self.repo.object_store.add_object = try_again(
            self.repo.object_store.add_object)

    @synchronised(lock)
    def setup(self):
        client, path = self._get_transport_and_path(
                        config.get('store', 'StoreUrl'))
        f, commit = self.repo.object_store.add_pack()
        remote_refs = client.fetch_pack(path,
            self.repo.object_store.determine_wants_all,
            self.repo.get_graph_walker(),
            f.write, open(os.devnull, 'w').write)
        commit()
        self.repo.refs['refs/remotes/origin/HEAD'] = (
            'ref: refs/remotes/origin/master')
        self.repo.refs['refs/remotes/origin/master'] = remote_refs['HEAD']
        # We need to decide if the HEAD is a descendant of the branch we
        # are about to merge. If it is, merging again will destroy any
        # commits
        try:
            branch = self.repo.object_store[
                self.repo.refs['refs/heads/master']]
        except KeyError:
            branch = None
        if not self._branch_has_object(branch, remote_refs['HEAD']):
            self.repo.refs['refs/heads/master'] = remote_refs['HEAD']
            tree = self.repo.tree(
                self.repo.get_object(self.repo.head()).tree)
            self._unpack(tree, self.repo.path)
        super(store, self).setup()

    @synchronised(lock)
    def checkpoint(self):
        client, path = self._get_transport_and_path(
                        config.get('store', 'StoreUrl'))
        # Will raise ChecksumMismatch if the server refuses to update
        # because this is not a fast forward FIXME
        def get_changed_refs(old_refs):
            return {"refs/heads/master":
                    self.repo.refs['refs/heads/master']}
        assert get_changed_refs(None)['refs/heads/master']
        client.send_pack(path, get_changed_refs,
            self.repo.object_store.generate_pack_contents)
        super(store, self).checkpoint()

    @synchronised(lock)
    def fetch(self):
        self.setup()
        super(store, self).fetch()

    @synchronised(lock)
    def write(self, certobj):
        tree = self.repo.tree(self.repo.get_object(self.repo.head()).tree)
        blob = dulwich.objects.Blob.from_string(certobj.as_pem())
        tree.add(0100644, certobj.get_subject().CN + ".crt", blob.id)

        self.repo.object_store.add_object(blob)
        self._do_commit(tree, u'Add certificate for "%s"\n' % (
            certobj.get_subject().CN, ))
        super(store, self).write(certobj)

    @synchronised(lock)
    def remove(self, CN):
        tree = self.repo.tree(self.repo.get_object(self.repo.head()).tree)
        # The certificate is in the root tree, and is called "<CN>.crt"
        del tree[CN + ".crt"]
        self._do_commit(tree, u'Delete certificate for "%s"\n' % (
            certobj.get_subject().CN, ))
        super(store, self).remove(certobj)

    def _do_commit(self, tree, message):
        commit = dulwich.objects.Commit()
        commit.tree = tree.id
        commit.author = '<' + config.get('ca', 'Email') + '>'
        commit.committer = commit.author
        commit.commit_time = commit.author_time = int(time.time())
        commit.author_timezone = dulwich.objects.parse_timezone("0000")
        commit.commit_timezone = commit.author_timezone
        commit.encoding = "UTF-8"
        commit.message = message
        commit.parents = [self.repo.refs['refs/heads/master']]

        self.repo.object_store.add_object(tree)
        self.repo.object_store.add_object(commit)
        self.repo.refs['refs/heads/master'] = commit.id
        self._unpack(tree, self.repo.path)

    def _unpack(self, tree, path='.'):
        for name, mode, sha1 in tree.iteritems():
            if stat.S_ISREG(mode):
                with open(os.path.join(path, name), 'w') as f:
                    f.write(self.repo.object_store.get_raw(sha1)[1])
                    os.fchmod(f.fileno(), mode)
            elif stat.S_ISDIR(mode):
                try:
                    # Don't bother with chmod. git doesn't store the mode.
                    os.mkdir(os.path.join(path, name))
                except OSError, e:
                    if e.errno != errno.EEXIST:
                        raise
                _unpack(self.repo.object_store[sha1],
                        os.path.join(path, name))

    @staticmethod
    def _get_transport_and_path(uri):
        """Parse a URI pointing to a git repository.

        Returns a dulwich.client object.

        """
        # Stolen from /usr/bin/dulwich
        for handler, transport in (
                ("git://", dulwich.client.TCPGitClient),
                ("git+ssh://", dulwich.client.SSHGitClient)):
            if uri.startswith(handler):
                host, path = uri[len(handler):].split("/", 1)
                return transport(host), "/" + path
        # if its not git or git+ssh, try a local url..
        return dulwich.client.SubprocessGitClient(), uri

    def _branch_has_object(self, commit, sha):
        """Traverse the list of commits on this branch and return True if
        we find sha."""

        if not commit:
            return False
        if commit.id == sha:
            return True
        for parent in commit.parents:
            if self._branch_has_object(
                    self.repo.object_store[parent], sha):
                return True
        return False

    def __str__(self):
        return "StoreHandler." + __name__ + "()"
